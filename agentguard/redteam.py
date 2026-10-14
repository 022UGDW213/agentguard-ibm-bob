"""Defensive adversarial replay harness (red team) for AgentGuard.

The trap skill fingerprints denied attacks by technique. This module closes the
loop: it takes techniques/samples the trap already learned, applies algorithmic
string transforms to generate variants, and replays each variant against the
trap's policy-DECISION API, asserting DENY every time.

Safety contract (enforced in code, not just documented):
  1. Payloads are inert strings POSTed to a policy-decision endpoint that never
     executes anything (the worker's check_call computes decisions only).
     This harness never executes a payload, on any machine, ever.
  2. It talks ONLY to the user's own demo (or localhost). Any other host is
     refused outright.
  3. A variant that returns ALLOW is a CRITICAL finding (loud, exit code 2).
     That is the whole point: find holes before real attackers do.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError

# The user's own demo. The harness refuses every other host (except
# localhost loopbacks) — see check_target_url().
DEMO_BASE_URL = "https://agentguard-demo.o22ugdw213.network"
ALLOWED_HOSTS = frozenset({
    "agentguard-demo.o22ugdw213.network",
    "localhost",
    "127.0.0.1",
    "::1",
})

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CRITICAL = 2  # a variant was ALLOWED — a real hole


# ---------------------------------------------------------------------------
# Host guard
# ---------------------------------------------------------------------------

def check_target_url(url: str) -> str:
    """Return a normalized base URL, or raise ValueError for a foreign host.

    Only the user's own demo and localhost loopbacks are permitted.
    """
    parsed = urllib.parse.urlparse(url or "")
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or host not in ALLOWED_HOSTS:
        raise ValueError(
            "refusing to target %r: only %s (or localhost) are allowed"
            % (url, sorted(ALLOWED_HOSTS))
        )
    return "%s://%s" % (parsed.scheme, parsed.netloc)


# ---------------------------------------------------------------------------
# Transforms — pure, deterministic string -> list[str]. No network, no I/O.
# ---------------------------------------------------------------------------

def url_encode(s: str) -> list:
    return [urllib.parse.quote(s, safe="")]


def double_url_encode(s: str) -> list:
    return [urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")]


def mixed_case(s: str) -> list:
    return ["".join(c.upper() if i % 2 else c.lower()
                    for i, c in enumerate(s))]


def separator_swap(s: str) -> list:
    out = []
    if "/" in s:
        out.append(s.replace("/", "\\"))
    if "\\" in s:
        out.append(s.replace("\\", "/"))
    return out


def dotdot_variants(s: str) -> list:
    if ".." not in s:
        return []
    return [s.replace("..", rep) for rep in
            ("....//", "..\\", "..%2f", "..././")]


def prefix_variants(s: str) -> list:
    cands = [s, "/" + s.lstrip("/"), "~/" + s.lstrip("/"),
             "./" + s.lstrip("./")]
    return [c for c in cands if c != s]


def whitespace_pad(s: str) -> list:
    return [" " + s + " ", "\t" + s, "\n" + s, s + "\n"]


def null_inject(s: str) -> list:
    if not s:
        return []
    mid = len(s) // 2
    return ["\x00" + s, s[:mid] + "\x00" + s[mid:], s + "\x00"]


def comment_inject(s: str) -> list:
    return [s + " #", s + " ; true", "# " + s]


def quote_wrap(s: str) -> list:
    return ["'" + s + "'", '"' + s + '"']


# Which transforms apply to which fingerprinted technique.
PATH_TRANSFORMS = [url_encode, double_url_encode, mixed_case, separator_swap,
                   dotdot_variants, prefix_variants, whitespace_pad,
                   null_inject]
CMD_TRANSFORMS = [comment_inject, quote_wrap, whitespace_pad, mixed_case,
                  separator_swap]
TEXT_TRANSFORMS = [mixed_case, whitespace_pad, url_encode]
SECRET_TRANSFORMS = [mixed_case, whitespace_pad, separator_swap]

TECHNIQUE_TRANSFORMS = {
    "sandbox_escape": PATH_TRANSFORMS,
    "path_traversal": PATH_TRANSFORMS,
    "sandbox_probe": PATH_TRANSFORMS,
    "destructive_command": CMD_TRANSFORMS,
    "prompt_injection_pattern": TEXT_TRANSFORMS,
    "secret_exfiltration_attempt": SECRET_TRANSFORMS,
    "scope_escalation": [],
    "token_tampering": [],
    "token_expired": [],
    "unknown": PATH_TRANSFORMS + CMD_TRANSFORMS,
}


def mutate(technique: str, tool: str, args: dict,
           max_variants: int = 12) -> list:
    """Generate variant arg-dicts from one learned sample, algorithmically.

    Applies the technique's transforms to every string argument value,
    deduplicates, and caps the count. Returns [] for techniques with no
    applicable transforms.
    """
    transforms = TECHNIQUE_TRANSFORMS.get(
        technique, TECHNIQUE_TRANSFORMS["unknown"])
    if not transforms:
        return []
    variants: list = []
    seen = set()
    for key, value in args.items():
        if not isinstance(value, str) or not value:
            continue
        for fn in transforms:
            try:
                outs = fn(value)
            except Exception:
                continue
            for out in outs:
                if out == value or out in seen:
                    continue
                seen.add(out)
                new_args = dict(args)
                new_args[key] = out
                variants.append({"tool": tool, "args": new_args,
                                 "via": fn.__name__, "from": value})
                if len(variants) >= max_variants:
                    return variants
    return variants


# ---------------------------------------------------------------------------
# Ledger seeds — replay what the trap itself learned, nothing else.
# ---------------------------------------------------------------------------

def _http(method: str, url: str, token: str | None = None,
          data: dict | None = None, timeout: int = 20):
    req = urllib.request.Request(url, method=method)
    # Identify as the user's own defensive tooling; the demo's front door
    # 403s Python's default urllib User-Agent.
    req.add_header("User-Agent",
                   "AgentGuard-RedTeam/1.0 (defensive security testing)")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=body,
                                    timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, {}
    except Exception as exc:  # URLError, RemoteDisconnected, timeouts, ...
        raise RuntimeError("network error: %s" % exc)


def mint_guest_token(base_url: str) -> str:
    status, data = _http("POST", base_url + "/api/guest")
    if status != 200 or not data.get("token"):
        raise RuntimeError("guest mint failed (http %s)" % status)
    return data["token"]


def fetch_learned_seeds(base_url: str, token: str,
                        limit: int = 200) -> list:
    """Pull trap intel records from the demo's audit ledger.

    Returns [(technique, tool, args)] for samples whose args survived
    redaction. Redacted samples are skipped (never reconstructed).
    """
    status, data = _http(
        "GET", base_url + "/api/skills/audit-query?limit=%d" % limit, token)
    if status != 200:
        raise RuntimeError("audit-query failed (http %s)" % status)
    return seeds_from_ledger(data)


def seeds_from_ledger(data: dict) -> list:
    """Extract learned seeds from an audit-query response dict.

    Pure function — lets callers load a ledger snapshot saved by another
    client (e.g. curl, which tolerates the sandbox egress proxy better than
    Python's urllib on large responses) via --ledger-file.
    """
    seeds = []
    for entry in data.get("entries", []):
        if entry.get("tool") != "skill.trap.intel":
            continue
        rec = entry.get("args", {})
        technique = rec.get("technique", "unknown")
        tool = rec.get("tool", "")
        args = rec.get("args", {})
        if not tool or not isinstance(args, dict):
            continue
        if any("[redacted" in str(v) for v in args.values()):
            continue  # never reconstruct redacted values
        seeds.append((technique, tool, dict(args)))
    # Deduplicate identical (technique, tool, args).
    uniq, seen = [], set()
    for technique, tool, args in seeds:
        key = (technique, tool, json.dumps(args, sort_keys=True,
                                          default=str))
        if key not in seen:
            seen.add(key)
            uniq.append((technique, tool, args))
    return uniq


# ---------------------------------------------------------------------------
# Replay — decisions only. Nothing here executes anything, anywhere.
# ---------------------------------------------------------------------------

def replay_variant(base_url: str, token: str, tool: str,
                   args: dict) -> dict:
    """Submit one variant to the trap DECISION endpoint.

    The endpoint computes allow/deny only; it never executes the tool call.
    Returns the parsed decision dict.
    """
    status, data = _http("POST", base_url + "/api/skills/trap", token,
                         {"tool": tool, "args": args})
    if status == 401:
        raise RuntimeError("unauthorized (bad/expired token)")
    if status != 200:
        raise RuntimeError("trap endpoint http %s" % status)
    return data


def run_campaign(base_url: str, token: str, seeds: list,
                 techniques: set | None = None,
                 max_variants: int = 12) -> dict:
    """Replay mutated variants of learned seeds; assert DENY on all.

    Returns a report dict. Any allow is recorded under
    report["critical"] — the caller decides how loud to be.
    """
    report = {"variants": 0, "denied": 0, "allowed": 0, "errors": 0,
              "critical": [], "by_technique": {}}
    for technique, tool, args in seeds:
        if techniques and technique not in techniques:
            continue
        variants = mutate(technique, tool, args, max_variants)
        bucket = report["by_technique"].setdefault(
            technique, {"variants": 0, "denied": 0, "allowed": 0,
                        "errors": 0})
        for var in variants:
            decision = None
            for attempt in range(2):  # one retry on transient network faults
                try:
                    decision = replay_variant(base_url, token, var["tool"],
                                              var["args"])
                    break
                except RuntimeError as exc:
                    if attempt == 1:
                        decision = {"_error": str(exc)}
                    else:
                        time.sleep(1.0)
            time.sleep(0.3)  # be gentle with the demo
            report["variants"] += 1
            bucket["variants"] += 1
            if decision is None or "_error" in decision:
                report["errors"] += 1
                bucket["errors"] += 1
                continue
            if decision.get("allow"):
                report["allowed"] += 1
                bucket["allowed"] += 1
                report["critical"].append({
                    "technique": technique,
                    "tool": var["tool"],
                    "args": var["args"],
                    "via": var["via"],
                    "reason": decision.get("reason"),
                })
            else:
                report["denied"] += 1
                bucket["denied"] += 1
    return report


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Defensive adversarial replay: mutate the trap's learned "
                    "attacks and verify the guard still denies them all.")
    parser.add_argument("--url", default=DEMO_BASE_URL,
                        help="demo base URL (own demo or localhost only)")
    parser.add_argument("--technique", action="append", default=[],
                        help="only replay this technique (repeatable)")
    parser.add_argument("--max-variants", type=int, default=12,
                        help="variant cap per learned sample")
    parser.add_argument("--limit", type=int, default=200,
                        help="audit ledger entries to scan for seeds")
    parser.add_argument("--ledger-file", default=None,
                        help="JSON file with a saved audit-query response; "
                             "seeds are read from it instead of the live "
                             "ledger (handy when the sandbox egress proxy "
                             "truncates large urllib reads)")
    args = parser.parse_args(argv)

    try:
        base_url = check_target_url(args.url)
    except ValueError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    try:
        token = None
        seeds = None
        limit = args.limit
        for attempt in range(4):
            try:
                token = mint_guest_token(base_url)
                if args.ledger_file:
                    with open(args.ledger_file, encoding="utf-8") as fh:
                        seeds = seeds_from_ledger(json.load(fh))
                else:
                    seeds = fetch_learned_seeds(base_url, token, limit)
                break
            except RuntimeError as exc:
                # The sandbox egress proxy intermittently truncates larger
                # responses for Python clients; shrink the window and retry.
                limit = max(15, limit // 2)
                if attempt == 3:
                    raise
                time.sleep(2.0)
    except RuntimeError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    techniques = set(args.technique) or None
    print("learned seeds: %d%s" % (
        len(seeds), " (filter: %s)" % ",".join(sorted(techniques))
        if techniques else ""))
    report = run_campaign(base_url, token, seeds, techniques,
                          args.max_variants)

    print("variants replayed: %d | denied: %d | allowed: %d | errors: %d"
          % (report["variants"], report["denied"], report["allowed"],
             report["errors"]))
    for tech, bucket in sorted(report["by_technique"].items()):
        print("  %-26s variants=%d denied=%d allowed=%d errors=%d" % (
            tech, bucket["variants"], bucket["denied"], bucket["allowed"],
            bucket["errors"]))

    if report["critical"]:
        print("\n*** CRITICAL: %d variant(s) were ALLOWED ***"
              % len(report["critical"]))
        for finding in report["critical"]:
            print("  technique=%s via=%s tool=%s args=%s reason=%s" % (
                finding["technique"], finding["via"], finding["tool"],
                json.dumps(finding["args"], default=str)[:160],
                finding["reason"]))
        return EXIT_CRITICAL
    if report["errors"]:
        print("WARNING: %d variant(s) could not be replayed (network); "
              "not counted as denied." % report["errors"])
        return EXIT_ERROR
    print("OK: every variant denied.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

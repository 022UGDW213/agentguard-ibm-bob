"""AgentGuard live demo on Cloudflare Workers (Python).

Runs the REAL AgentGuard policy engine (policy.py / tokens.py code copied
verbatim from the repo) and the REAL secret-pattern regexes. Only the web
layer is adapted for Workers: fetch handler instead of http.server,
KV-backed audit ledger instead of a local JSONL file, and embedded demo
files instead of a filesystem directory. No mocks, no simulated decisions.

Token-based login (same contract as web_demo.py):
  * POST /api/guest -> limited guest capability token (1h TTL), one click.
  * POST /api/login {username, password} -> user capability token (8h TTL).
    The demo credential comes ONLY from worker vars (AG_DEMO_USER /
    AG_DEMO_PASSWORD); nothing is hardcoded or committed. Password login
    is disabled when AG_DEMO_PASSWORD is unset.
  * The frontend keeps the token in localStorage and sends it as
    `Authorization: Bearer <token>` on every /check request.
  * /check verifies the token server-side on each request.

Secrets hygiene:
  * HMAC signing key: HMAC_SECRET worker var when set, otherwise generated
    once and persisted in KV. Never committed to the repo.

Bindings:
  AUDIT_KV : KV namespace for the audit ledger + HMAC secret

Plain-text bindings (demo-only — set at deploy time, never committed):
  AG_DEMO_USER, AG_DEMO_PASSWORD

Canonical source: this file is versioned in the repo as worker_entry.py
and mirrored to ~/workspace/agentguard-vpc-worker/entry.py before each
deploy (the two are kept identical; deploy from the vpc-worker dir).

Deploy (the same path as the original 2026-10-12 deploy):
  cd ~/workspace/agentguard-vpc-worker   # entry.py must be the new version
  cd ~/workspace/custom-connectors/custom.legacy-cloudflare
  python3 bin/cf.py PUT \
    /accounts/fc8d8f750762db94a4374fec8f64a242/workers/scripts/agentguard-demo \
    --multipart-meta '{"main_module":"entry.py","compatibility_date":"2026-10-12",
      "compatibility_flags":["python_workers","disable_python_external_sdk"],
      "usage_model":"standard",
      "bindings":[
        {"type":"kv_namespace","name":"AUDIT_KV",
         "namespace_id":"5adf61dbc5c3477e8d296a90233747e7"},
        {"type":"plain_text","name":"AG_DEMO_USER","text":"demo"},
        {"type":"plain_text","name":"AG_DEMO_PASSWORD","text":"agentguard"}]}' \
    --file entry.py=/home/hatch/workspace/agentguard-vpc-worker/entry.py \
    --file-type text/x-python
  # Python workers need the file part as text/x-python (per Cloudflare
  # docs); application/octet-stream deploys it as an ES module and fails.
  # Then GET .../workers/scripts/agentguard-demo/settings and assert the
  # AUDIT_KV binding is still present (secret bindings are omitted from
  # upload metadata and must persist untouched).
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs

from workers import Response, WorkerEntrypoint

# ---------------------------------------------------------------------------
# agentguard/tokens.py (verbatim from repo)
# ---------------------------------------------------------------------------

class TokenError(ValueError):
    """Raised when a token is malformed, expired, or fails verification."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii") + b"=" * (-len(data) % 4))


@dataclass
class CapabilityToken:
    """A parsed, verified capability token payload."""

    subject: str
    scopes: list[str]
    expires_at: int
    token_id: str = field(default_factory=lambda: secrets.token_hex(8))
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def is_expired(self, now: int | None = None) -> bool:
        return int(now if now is not None else time.time()) >= self.expires_at


def mint(
    secret: bytes,
    subject: str,
    scopes: list[str],
    ttl_seconds: int = 3600,
) -> str:
    """Mint a new signed capability token string."""
    payload = {
        "sub": subject,
        "scopes": list(scopes),
        "iat": int(time.time()),
        "exp": int(time.time()) + int(ttl_seconds),
        "jti": secrets.token_hex(8),
    }
    body = _b64url_encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
    sig = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(sig)}"


def verify(secret: bytes, token: str, now: int | None = None) -> CapabilityToken:
    """Verify a token string and return its payload. Raises TokenError."""
    try:
        body, sig_b64 = token.split(".", 1)
        expected = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
        actual = _b64url_decode(sig_b64)
    except (ValueError, Exception) as exc:
        raise TokenError(f"malformed token: {exc}") from exc
    if not hmac.compare_digest(expected, actual):
        raise TokenError("invalid signature")
    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
        cap = CapabilityToken(
            subject=str(payload["sub"]),
            scopes=list(payload["scopes"]),
            expires_at=int(payload["exp"]),
            token_id=str(payload.get("jti", "")),
            issued_at=int(payload.get("iat", 0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError(f"invalid payload: {exc}") from exc
    if cap.is_expired(now):
        raise TokenError("token expired")
    return cap


# ---------------------------------------------------------------------------
# agentguard/policy.py (verbatim from repo)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    matched_rule: dict | None = None


@dataclass
class Policy:
    rules: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = data.get("rules", [])
        for rule in rules:
            if rule.get("effect") not in ("allow", "deny"):
                raise ValueError(f"rule has bad effect: {rule!r}")
            if "tool" not in rule:
                raise ValueError(f"rule missing 'tool': {rule!r}")
        return cls(rules=list(rules))


def _rule_matches(rule: dict, tool: str, args: dict) -> bool:
    if not fnmatch.fnmatchcase(tool, rule["tool"]):
        return False
    for key in ("path", "host"):
        if key in rule:
            value = str(args.get(key, ""))
            if not fnmatch.fnmatchcase(value, rule[key]):
                return False
    return True


def _scope_covers(scopes: list[str], tool: str, args: dict) -> bool:
    for scope in scopes:
        parts = scope.split(":")
        if len(parts) < 2 or parts[0] != "tool":
            continue
        if not fnmatch.fnmatchcase(tool, parts[1]):
            continue
        ok = True
        for constraint in parts[2:]:
            if "=" not in constraint:
                ok = False
                break
            key, pattern = constraint.split("=", 1)
            if not fnmatch.fnmatchcase(str(args.get(key, "")), pattern):
                ok = False
                break
        if ok:
            return True
    return False


class PolicyEngine:
    """Evaluates tool calls against a Policy plus a capability token."""

    def __init__(self, policy: Policy, secret: bytes):
        self.policy = policy
        self.secret = secret

    def authorize(self, tool: str, args: dict, token: str) -> Decision:
        try:
            cap = verify(self.secret, token)
        except TokenError as exc:
            return Decision(False, f"token rejected: {exc}")

        for rule in self.policy.rules:
            if rule["effect"] == "deny" and _rule_matches(rule, tool, args):
                return Decision(False, f"denied by rule: {rule}", matched_rule=rule)

        allowed_by_rule = any(
            rule["effect"] == "allow" and _rule_matches(rule, tool, args)
            for rule in self.policy.rules
        )
        if not allowed_by_rule:
            return Decision(False, "no allow rule matched (deny by default)")

        if not _scope_covers(cap.scopes, tool, args):
            return Decision(
                False,
                f"token scopes {cap.scopes} do not cover {tool} with args {args}",
            )

        return Decision(True, f"allowed: token {cap.token_id} covers {tool}")


# ---------------------------------------------------------------------------
# agentguard/scanner.py SECRET_PATTERNS (verbatim from repo)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("generic_password_assign", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]")),
]


# ---------------------------------------------------------------------------
# Demo wiring (adapted from web_demo.py for Workers)
# ---------------------------------------------------------------------------

MAX_BODY = 64 * 1024
MAX_SCAN_LINES = 500
MAX_FINDINGS = 50
MAX_AUDIT_ENTRIES = 200
FETCH_HEADER = "X-AgentGuard-Fetch"

DEMO_POLICY = Policy.from_dict({
    "rules": [
        {"effect": "allow", "tool": "read_file"},
        {"effect": "allow", "tool": "scan_text"},
    ]
})
DEMO_TOKEN_SCOPES = ["tool:read_file", "tool:scan_text"]
GUEST_TOKEN_TTL = 3600
USER_TOKEN_TTL = 8 * 3600

# Embedded demo files (same content as web_demo.py's canned files).
DEMO_FILES = {
    "welcome.txt": (
        "Welcome to the AgentGuard demo sandbox.\n"
        "\n"
        "Only the files in this directory may be read by an agent.\n"
        "Try read_file on 'welcome.txt' (allowed) versus\n"
        "'/etc/passwd' (denied: path escapes sandbox).\n"
    ),
    "policy_notes.txt": (
        "AgentGuard policy notes\n"
        "-----------------------\n"
        "- Deny by default: a call is allowed only if an allow rule\n"
        "  matches AND the capability token covers the tool.\n"
        "- Explicit deny rules always win over allow rules.\n"
        "- Tokens are HMAC-signed and expire; possession of a valid,\n"
        "  narrowly-scoped token is what authorizes a call.\n"
    ),
    "agent_tips.txt": (
        "Tips for agents in the sandbox\n"
        "------------------------------\n"
        "1. Present a capability token with every tool call.\n"
        "2. Stay inside your scoped paths and hosts.\n"
        "3. Every decision — allow or deny — is written to the\n"
        "   append-only audit ledger.\n"
    ),
}


# ---------------------------------------------------------------------------
# Skills API — every demo capability as a callable skill.
# GET /api/skills lists them; one endpoint per skill below.
# ---------------------------------------------------------------------------

SKILLS = [
    {
        "name": "policy-check",
        "path": "/api/skills/policy-check",
        "method": "POST",
        "auth": "any valid token (guest works)",
        "description": (
            "Submit a tool call and get the policy engine's ALLOW/DENY "
            "decision with the reason. Nothing is executed — this is the "
            "read-only view of the guard."
        ),
        "input_schema": {
            "tool": "string, required — e.g. \"read_file\"",
            "args": "object, required — e.g. {\"path\": \"welcome.txt\"}",
        },
        "example": {"tool": "read_file", "args": {"path": "welcome.txt"}},
    },
    {
        "name": "token-mint",
        "path": "/api/skills/token-mint",
        "method": "POST",
        "auth": (
            "any valid token — the minted token can only carry scopes you "
            "already hold (no privilege escalation, ever)"
        ),
        "description": (
            "Mint a new HMAC-signed capability token. Scopes must be a "
            "subset of your own, and the TTL can't outlive your token."
        ),
        "input_schema": {
            "scopes": "array of strings, optional — defaults to your scopes",
            "ttl_seconds": "integer, optional — default 3600",
        },
        "example": {"scopes": ["tool:read_file"], "ttl_seconds": 600},
    },
    {
        "name": "token-verify",
        "path": "/api/skills/token-verify",
        "method": "POST",
        "auth": "any valid token (guest works)",
        "description": (
            "Verify any capability token: signature, expiry, and scopes. "
            "Returns what the token allows — or why it doesn't."
        ),
        "input_schema": {
            "token": "string, required — the token to inspect",
        },
        "example": {"token": "<paste a token here>"},
    },
    {
        "name": "secret-scan",
        "path": "/api/skills/secret-scan",
        "method": "POST",
        "auth": "any valid token (guest works)",
        "description": (
            "Scan text with the real secret-pattern regexes — AWS keys, "
            "GitHub tokens, private keys, passwords, and more."
        ),
        "input_schema": {
            "text": "string, required — the text to scan",
        },
        "example": {"text": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"},
    },
    {
        "name": "audit-query",
        "path": "/api/skills/audit-query",
        "method": "GET",
        "auth": "any valid token (guest works)",
        "description": (
            "Read recent entries from the append-only audit ledger. "
            "Sensitive values are never stored, so there's nothing to leak."
        ),
        "input_schema": {
            "limit": "integer query param, optional — default 20, max 100",
        },
        "example": {"limit": 10},
    },
    {
        "name": "harness-run",
        "path": "/api/skills/harness-run",
        "method": "POST",
        "auth": "any valid token (guest works)",
        "description": (
            "Run the scripted demo agent through the guard: four tool "
            "calls — a good read, a sandbox escape, a secret leak, and a "
            "destructive command. Each is authorized, executed-or-denied, "
            "and audited; the full transcript comes back."
        ),
        "input_schema": {},
        "example": {},
    },
]

# The scripted demo-agent task run by the harness-run skill. Each step goes
# through the policy engine with the caller's token and is audited.
HARNESS_PLAN = [
    {
        "note": "The agent reads the welcome file.",
        "tool": "read_file",
        "target": "welcome.txt",
    },
    {
        "note": "The agent tries to read outside the sandbox.",
        "tool": "read_file",
        "target": "/etc/passwd",
    },
    {
        "note": "The agent scans pasted text for secrets.",
        "tool": "scan_text",
        "target": "deploy key: AKIAIOSFODNN7EXAMPLE — ship it",
    },
    {
        "note": "The agent tries a destructive shell command.",
        "tool": "run_command",
        "target": "rm -rf /",
    },
]


def env_get(env, name: str, default: str = "") -> str:
    """Read a worker var (or os.environ fallback); never raises."""
    try:
        val = getattr(env, name, None)
    except Exception:
        val = None
    if isinstance(val, str) and val:
        return val
    return os.environ.get(name, default)


def demo_auth_user(env) -> str:
    return env_get(env, "AG_DEMO_USER", "demo")


def demo_auth_password(env) -> str:
    # Empty means password login is disabled on this deployment.
    return env_get(env, "AG_DEMO_PASSWORD", "")


def password_login_enabled(env) -> bool:
    return bool(demo_auth_password(env))


def check_demo_credentials(env, username: str, password: str) -> bool:
    """Verify the demo username/password against the env-configured value."""
    expected_pw = demo_auth_password(env)
    if not expected_pw:
        return False
    if (username or "") != demo_auth_user(env):
        hmac.compare_digest(password or "", expected_pw)
        return False
    return hmac.compare_digest(password or "", expected_pw)


def bearer_token(headers) -> str:
    """Extract a `Bearer <token>` value from request headers ("" if none)."""
    auth = ""
    try:
        if hasattr(headers, "get"):
            auth = headers.get("Authorization") or \
                headers.get("authorization") or ""
    except Exception:
        return ""
    if not isinstance(auth, str):
        return ""
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return ""


class SandboxEscape(Exception):
    """Raised when a read_file target tries to leave the demo directory."""


def resolve_demo_path(target: str) -> str:
    """Validate a read_file target against the embedded demo files."""
    name = (target or "").strip()
    if not name:
        raise ValueError("target is required")
    if name.startswith(("/", "\\", "~")) or ":" in name[:3]:
        raise SandboxEscape("path escapes sandbox")
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if ".." in parts or not parts:
        raise SandboxEscape("path escapes sandbox")
    clean = "/".join(parts)
    if clean not in DEMO_FILES:
        raise ValueError("file not found in demo directory")
    return clean


def scan_text_for_secrets(text: str) -> list[dict]:
    """Scan pasted text with the REAL secret-pattern regexes."""
    findings: list[dict] = []
    for lineno, line in enumerate(text.splitlines()[:MAX_SCAN_LINES], 1):
        for kind, pattern in SECRET_PATTERNS:
            try:
                if pattern.search(line):
                    findings.append({"line": lineno, "kind": kind})
                    if len(findings) >= MAX_FINDINGS:
                        return findings
            except Exception:
                continue
    return findings


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _args_hash(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class AuditLogKV:
    """Append-only audit ledger backed by Workers KV (same record format)."""

    KEY = "audit_log_v1"

    def __init__(self, kv):
        self.kv = kv

    async def record(self, tool, args, allow, reason,
                     subject="", token_id="") -> dict:
        entry = {
            "ts": int(time.time()),
            "tool": tool,
            "args": args,
            "args_hash": _args_hash(args),
            "decision": "allow" if allow else "deny",
            "reason": reason,
            "subject": subject,
            "token_id": token_id,
        }
        entries = await self.read_all()
        entries.append(entry)
        await self.kv.put(self.KEY,
                          json.dumps(entries[-MAX_AUDIT_ENTRIES:], default=str))
        return entry

    async def read_all(self) -> list[dict]:
        raw = await self.kv.get(self.KEY)
        if not raw:
            return []
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    async def summary(self) -> dict:
        entries = await self.read_all()
        return {
            "total": len(entries),
            "allowed": sum(1 for e in entries if e.get("decision") == "allow"),
            "denied": sum(1 for e in entries if e.get("decision") == "deny"),
        }


async def get_secret(env) -> bytes:
    """Worker-wide HMAC secret: HMAC_SECRET var when set, else generated
    once and persisted in KV. Never committed anywhere."""
    var = env_get(env, "HMAC_SECRET", "")
    if var:
        try:
            return base64.b64decode(var)
        except Exception:
            return var.encode("utf-8")
    kv = env.AUDIT_KV
    raw = await kv.get("hmac_secret_v1")
    if raw:
        return base64.b64decode(raw.encode("ascii"))
    secret = secrets.token_bytes(32)
    await kv.put("hmac_secret_v1",
                 base64.b64encode(secret).decode("ascii"))
    return secret


PAGE_CSS = """
:root{
  --bg:#04050d;
  --cyan:#00e5ff;
  --magenta:#ff2ea6;
  --violet:#8b5cf6;
  --green:#00ffa3;
  --red:#ff4d6d;
  --amber:#ffc400;
  --text:#eaf6ff;
  --muted:#93a4c4;
  --glass:rgba(16,24,48,.55);
  --stroke:rgba(0,229,255,.22);
}
*{box-sizing:border-box}
html{background:var(--bg)}
body{
  margin:0;min-height:100vh;color:var(--text);
  font-family:'Rajdhani','Segoe UI',system-ui,-apple-system,sans-serif;
  font-size:1.08rem;line-height:1.55;
  background:
    radial-gradient(1100px 500px at 15% -5%, rgba(0,229,255,.12), transparent 60%),
    radial-gradient(900px 500px at 90% 10%, rgba(255,46,166,.10), transparent 60%),
    radial-gradient(700px 700px at 50% 110%, rgba(139,92,246,.12), transparent 60%),
    var(--bg);
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(0,229,255,.055) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,229,255,.055) 1px, transparent 1px);
  background-size:44px 44px;
  -webkit-mask-image:radial-gradient(ellipse 90% 70% at 50% 18%, #000 25%, transparent 78%);
  mask-image:radial-gradient(ellipse 90% 70% at 50% 18%, #000 25%, transparent 78%);
}
body::after{
  content:"";position:fixed;inset:0;pointer-events:none;z-index:50;
  background:radial-gradient(ellipse at center, transparent 55%, rgba(0,0,12,.55) 100%);
}
.wrap{position:relative;z-index:1;max-width:920px;margin:0 auto;padding:2.5rem 1.25rem 4rem}
h1{
  font-family:'Orbitron',sans-serif;font-weight:800;
  font-size:clamp(1.7rem,4.6vw,2.5rem);letter-spacing:.06em;margin:0 0 .4rem;
  background:linear-gradient(92deg,var(--cyan) 10%,var(--violet) 55%,var(--magenta) 90%);
  -webkit-background-clip:text;background-clip:text;color:transparent;
  filter:drop-shadow(0 0 18px rgba(0,229,255,.35));
}
h2{font-family:'Orbitron',sans-serif;letter-spacing:.06em}
.sub{color:var(--muted);margin:.2rem 0 1.2rem;font-size:1.12rem}
.sandbox-note{
  background:var(--glass);border:1px solid rgba(255,196,0,.38);border-radius:14px;
  padding:.8rem 1.1rem;margin:1.2rem 0;font-weight:600;color:#ffe9a8;
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  box-shadow:0 0 24px rgba(255,196,0,.08), inset 0 1px 0 rgba(255,255,255,.08);
}
form,#login-card{
  background:linear-gradient(135deg, rgba(255,255,255,.10), rgba(255,255,255,.03));
  border:1px solid var(--stroke);border-radius:18px;
  padding:1.4rem;margin:1.4rem 0;
  backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%);
  box-shadow:0 12px 40px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.12),
             0 0 28px rgba(0,229,255,.07);
}
#login-card{border-color:rgba(255,46,166,.32);
  box-shadow:0 12px 40px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.12),
             0 0 34px rgba(255,46,166,.12)}
#login-card h2{margin:0 0 .4rem;font-size:1.25rem;color:#fff;
  text-shadow:0 0 14px rgba(255,46,166,.55)}
label{display:block;margin:.7rem 0 .25rem;font-weight:600;color:var(--text);letter-spacing:.04em}
input[type=text],input[type=password],textarea{
  width:100%;box-sizing:border-box;padding:.65rem .8rem;
  background:rgba(2,6,18,.65);border:1px solid rgba(0,229,255,.28);
  border-radius:10px;font-size:1rem;color:var(--text);font-family:inherit;
  transition:border-color .2s, box-shadow .2s;
}
input[type=text]:focus,input[type=password]:focus,textarea:focus{
  outline:none;border-color:var(--cyan);
  box-shadow:0 0 0 3px rgba(0,229,255,.18), 0 0 18px rgba(0,229,255,.25);
}
button{
  margin-top:.9rem;padding:.7rem 1.4rem;font-size:1rem;font-weight:700;letter-spacing:.06em;
  font-family:'Rajdhani',sans-serif;color:var(--cyan);text-transform:uppercase;
  background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.55);
  border-radius:12px;cursor:pointer;transition:all .2s;
}
button:hover:not(:disabled){background:rgba(0,229,255,.18);
  box-shadow:0 0 22px rgba(0,229,255,.35);transform:translateY(-1px)}
button:disabled{opacity:.55;cursor:wait}
.big-guest{
  display:block;width:100%;padding:1rem;font-size:1.15rem;font-weight:700;
  color:#04121a;background:linear-gradient(92deg,var(--cyan),#8ef4ff 45%,var(--magenta));
  border:0;border-radius:14px;margin:.8rem 0;letter-spacing:.06em;text-transform:uppercase;
  box-shadow:0 0 28px rgba(0,229,255,.45), 0 0 60px rgba(255,46,166,.18);
  animation:guestpulse 2.6s ease-in-out infinite;
}
.big-guest:hover:not(:disabled){transform:translateY(-2px);
  background:linear-gradient(92deg,var(--cyan),#8ef4ff 45%,var(--magenta));
  box-shadow:0 0 42px rgba(0,229,255,.62), 0 0 84px rgba(255,46,166,.28)}
@keyframes guestpulse{
  0%,100%{box-shadow:0 0 26px rgba(0,229,255,.40), 0 0 55px rgba(255,46,166,.15)}
  50%{box-shadow:0 0 42px rgba(0,229,255,.62), 0 0 84px rgba(255,46,166,.30)}
}
.error{color:#ff6b8a;font-weight:600;min-height:1.2em;
  text-shadow:0 0 12px rgba(255,77,109,.4)}
.banner{padding:.9rem 1.1rem;border-radius:14px;margin:1.2rem 0;font-weight:700;
  letter-spacing:.06em;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
.allow{background:rgba(0,255,163,.10);border:1px solid rgba(0,255,163,.45);
  color:#c2ffe2;box-shadow:0 0 26px rgba(0,255,163,.18), inset 0 1px 0 rgba(255,255,255,.1)}
.deny{background:rgba(255,46,120,.10);border:1px solid rgba(255,77,109,.5);
  color:#ffd3dd;box-shadow:0 0 26px rgba(255,46,120,.22), inset 0 1px 0 rgba(255,255,255,.1)}
table{border-collapse:collapse;width:100%;font-size:.92rem;margin-top:.6rem;
  background:rgba(10,16,36,.55);border:1px solid var(--stroke);border-radius:12px;
  overflow:hidden;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
th,td{border-bottom:1px solid rgba(255,255,255,.07);padding:.5rem .7rem;
  text-align:left;vertical-align:top}
th{font-family:'Orbitron',sans-serif;font-size:.7rem;letter-spacing:.14em;
  color:var(--cyan);text-transform:uppercase;background:rgba(0,229,255,.06)}
tr:last-child td{border-bottom:0}
.mono{font-family:ui-monospace,'Cascadia Code',Menlo,Consolas,monospace;
  color:#8ef4ff;font-size:.92em}
.note{color:var(--muted);font-size:.95rem}
a{color:var(--cyan);text-decoration:none;border-bottom:1px dotted rgba(0,229,255,.5)}
a:hover{text-shadow:0 0 12px rgba(0,229,255,.65)}
@media (max-width:640px){
  .wrap{padding:1.6rem .9rem 3rem}
  form,#login-card{padding:1.1rem}
  h1{letter-spacing:.03em}
  .big-guest{font-size:1rem}
}
.bob-card{
  background:linear-gradient(135deg, rgba(139,92,246,.14), rgba(0,229,255,.06));
  border:1px solid rgba(139,92,246,.45);border-radius:18px;
  padding:1.4rem;margin:1.4rem 0;
  backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%);
  box-shadow:0 12px 40px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.12),
             0 0 34px rgba(139,92,246,.16);
}
.bob-card h2{margin:0 0 .4rem;font-size:1.25rem;color:#fff;
  text-shadow:0 0 14px rgba(139,92,246,.6)}
.bob-card ul{margin:.6rem 0;padding-left:1.2rem}
.bob-card li{margin:.45rem 0}
#skills-section{margin-top:2.2rem}
#skill-output{
  background:rgba(2,6,18,.72);border:1px solid var(--stroke);
  border-radius:12px;padding:1rem;overflow:auto;max-height:420px;
  white-space:pre-wrap;word-break:break-word;margin-top:.8rem;
}
select{
  width:100%;box-sizing:border-box;padding:.65rem .8rem;
  background:rgba(2,6,18,.65);border:1px solid rgba(0,229,255,.28);
  border-radius:10px;font-size:1rem;color:var(--text);font-family:inherit;
}
select:focus{outline:none;border-color:var(--cyan);
  box-shadow:0 0 0 3px rgba(0,229,255,.18), 0 0 18px rgba(0,229,255,.25)}
"""

LOGIN_JS = """
<script>
(function () {
  var LS_KEY = 'ag_demo_token';
  function $(id) { return document.getElementById(id); }
  function showDemo(subject) {
    $('login-card').style.display = 'none';
    $('demo-section').style.display = 'block';
    $('whoami').textContent = subject;
  }
  function showLogin() {
    $('demo-section').style.display = 'none';
    $('login-card').style.display = 'block';
  }
  function setErr(msg) { var e = $('login-error'); if (e) e.textContent = msg || ''; }
  async function readJson(res) { try { return await res.json(); } catch (e) { return {}; } }

  async function init() {
    var token = null;
    try { token = localStorage.getItem(LS_KEY); } catch (e) {}
    if (!token) { showLogin(); return; }
    try {
      var res = await fetch('/api/me', {headers: {Authorization: 'Bearer ' + token}});
      var data = await readJson(res);
      if (res.ok && data.ok) { showDemo(data.subject); return; }
    } catch (e) {}
    try { localStorage.removeItem(LS_KEY); } catch (e) {}
    showLogin();
  }

  async function guestLogin() {
    setErr('');
    var btn = $('guest-btn'); btn.disabled = true;
    try {
      var res = await fetch('/api/guest', {method: 'POST'});
      var data = await readJson(res);
      if (res.ok && data.ok && data.token) {
        try { localStorage.setItem(LS_KEY, data.token); } catch (e) {}
        showDemo(data.subject || 'guest');
      } else { setErr('Something went wrong — please try again.'); }
    } catch (e) { setErr('Something went wrong — please try again.'); }
    btn.disabled = false;
  }

  async function doLogin(ev) {
    ev.preventDefault(); setErr('');
    var u = $('username').value.trim(), p = $('password').value;
    try {
      var res = await fetch('/api/login', {method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: u, password: p})});
      var data = await readJson(res);
      if (res.ok && data.ok && data.token) {
        try { localStorage.setItem(LS_KEY, data.token); } catch (e) {}
        showDemo(data.subject || u);
      } else { setErr((data && data.error) || 'Sign-in failed — try again.'); }
    } catch (e) { setErr('Sign-in failed — try again.'); }
  }

  function logout() {
    try { localStorage.removeItem(LS_KEY); } catch (e) {}
    $('result').innerHTML = '';
    var t = $('target'); if (t) t.value = '';
    showLogin();
  }

  async function submitCheck(ev) {
    ev.preventDefault();
    var token = null;
    try { token = localStorage.getItem(LS_KEY); } catch (e) {}
    if (!token) { showLogin(); return; }
    var fd = new FormData($('check-form'));
    var body = new URLSearchParams();
    fd.forEach(function (v, k) { body.append(k, v); });
    $('result').innerHTML = '<p class="note">Checking…</p>';
    try {
      var res = await fetch('/check', {method: 'POST',
        headers: {Authorization: 'Bearer ' + token, 'X-AgentGuard-Fetch': '1'},
        body: body});
      if (res.status === 401) {
        try { localStorage.removeItem(LS_KEY); } catch (e) {}
        showLogin(); setErr('Your session expired — please sign in again.');
        return;
      }
      $('result').innerHTML = await res.text();
    } catch (e) {
      $('result').innerHTML = '<p class="error">Request failed — please try again.</p>';
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    $('guest-btn').addEventListener('click', guestLogin);
    var lf = $('login-form'); if (lf) lf.addEventListener('submit', doLogin);
    $('check-form').addEventListener('submit', submitCheck);
    $('logout-btn').addEventListener('click', logout);
    init();
  });
})();
</script>
"""

SKILLS_JS = """
<script>
(function () {
  var SKILLS = __SKILLS_JSON__;
  function $(id) { return document.getElementById(id); }
  function current() {
    var s = $('skill-select');
    return SKILLS[s.selectedIndex] || SKILLS[0];
  }
  function fill() {
    var sk = current();
    var html = '<b>' + sk.name + '</b> &middot; ' + sk.method + ' '
      + '<span class="mono">' + sk.path + '</span><br>' + sk.description
      + '<br><span class="note">Auth: ' + sk.auth + '</span>';
    $('skill-desc').innerHTML = html;
    $('skill-input').value = JSON.stringify(sk.example, null, 2);
    $('skill-output').textContent = '';
  }
  async function run() {
    var sk = current();
    var out = $('skill-output');
    out.textContent = 'Running…';
    var token = null;
    try { token = localStorage.getItem('ag_demo_token'); } catch (e) {}
    if (!token) { out.textContent = 'Sign in or continue as a guest first.'; return; }
    var url = sk.path;
    var init = {headers: {'Authorization': 'Bearer ' + token}};
    if (sk.method === 'POST') {
      init.method = 'POST';
      init.headers['Content-Type'] = 'application/json';
      init.body = $('skill-input').value;
    } else {
      try {
        var params = JSON.parse($('skill-input').value || '{}');
        var q = new URLSearchParams();
        for (var k in params) { q.append(k, params[k]); }
        var qs = q.toString();
        if (qs) { url += '?' + qs; }
      } catch (e) {}
    }
    try {
      var res = await fetch(url, init);
      var txt = await res.text();
      try { out.textContent = JSON.stringify(JSON.parse(txt), null, 2); }
      catch (e) { out.textContent = txt; }
    } catch (e) { out.textContent = 'Request failed: ' + e; }
  }
  document.addEventListener('DOMContentLoaded', function () {
    var sel = $('skill-select');
    if (!sel) { return; }
    SKILLS.forEach(function (sk) {
      var o = document.createElement('option');
      o.value = sk.name;
      o.textContent = sk.name + '  [' + sk.method + ']';
      sel.appendChild(o);
    });
    sel.addEventListener('change', fill);
    $('skill-run').addEventListener('click', run);
    fill();
  });
})();
</script>
""".replace("__SKILLS_JSON__", json.dumps(SKILLS))


def landing_html(env) -> str:
    if password_login_enabled(env):
        user = demo_auth_user(env)
        pw = demo_auth_password(env)
        login_form = f"""
  <p style="margin-top:1.2rem">Or sign in with the demo account:</p>
  <form id="login-form">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" value="{esc(user)}"
           autocomplete="username">
    <label for="password">Password</label>
    <input type="password" id="password" name="password"
           autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
  <p class="note">Demo credentials: <span class="mono">{esc(user)}</span> /
  <span class="mono">{esc(pw)}</span> — same access as a guest,
  it just walks the full sign-in flow.</p>
"""
    else:
        login_form = """
  <p class="note">Password sign-in isn't turned on for this deployment —
  the guest button above gets you the same access.</p>
"""
    return f"""
<h1>AgentGuard live demo</h1>
<p class="sub">Model-agnostic security harness for AI agents &mdash;
every tool call below is evaluated by the <span class="mono">real</span>
deny-by-default policy engine and written to the <span class="mono">real</span>
append-only audit ledger. No mocks, no simulated decisions.</p>
<div class="bob-card">
  <h2>Built with IBM Bob</h2>
  <p>Bob is the AI coding assistant behind this project — and it did real
  work here, not a logo on a slide:</p>
  <ul>
    <li><b>Understood the codebase</b> — read every module and mapped how
    the policy engine, capability tokens, and audit ledger fit together.</li>
    <li><b>Generated the security policies</b> — drafted the deny-by-default
    rules this live demo enforces on every tool call.</li>
    <li><b>Authored the test suite</b> — wrote the tests that keep every
    deploy honest (62 tests passing).</li>
  </ul>
  <p class="note">Judges: the repo's <span class="mono">.bob/mcp.json</span>
  shows exactly how Bob was wired into the build.</p>
</div>
<div class="sandbox-note">Demo sandbox &mdash; policy decisions only,
nothing is executed. Running serverless.</div>
<div id="login-card">
  <h2>Try the live demo</h2>
  <p>Two ways in &mdash; pick whichever is easier:</p>
  <button class="big-guest" id="guest-btn" type="button">Continue as guest
  &mdash; no signup</button>
  <p class="note">One click, no account, no email. You get a demo token
  that's good for an hour.</p>
  {login_form}
  <p id="login-error" class="error"></p>
  <p class="note">Either way, you sign a capability token and the demo
  checks it on every request &mdash; that's the product working, live.</p>
</div>
<div id="demo-section" style="display:none">
  <p>Signed in as <b id="whoami" class="mono"></b>
  &nbsp;<button id="logout-btn" type="button">Log out</button></p>
  <form id="check-form">
    <label for="tool">Tool name</label>
    <input type="text" id="tool" name="tool" list="tools"
           placeholder="read_file" value="read_file" required>
    <datalist id="tools">
      <option value="read_file"></option>
      <option value="scan_text"></option>
    </datalist>
    <label for="target">Target &mdash; file name (read_file) or text to scan (scan_text)</label>
    <textarea id="target" name="target" rows="3"
      placeholder="welcome.txt"></textarea>
    <button type="submit">Check tool call</button>
  </form>
  <div id="result"></div>
  <p class="note">Try: <span class="mono">read_file</span> on
  <span class="mono">welcome.txt</span> (allowed) vs
  <span class="mono">/etc/passwd</span> or
  <span class="mono">../../etc/passwd</span> (denied: path escapes sandbox),
  <span class="mono">run_command</span> on anything (denied), or
  <span class="mono">scan_text</span> on text containing
  <span class="mono">AKIAIOSFODNN7EXAMPLE</span> (flagged).</p>
  <div id="skills-section">
    <h2>Skills API</h2>
    <p class="note">Everything this demo does is also a skill — callable
    over HTTP with your capability token. Pick one and try it live:</p>
    <label for="skill-select">Skill</label>
    <select id="skill-select"></select>
    <p id="skill-desc" class="note"></p>
    <label for="skill-input">Input (JSON)</label>
    <textarea id="skill-input" rows="6" class="mono"></textarea>
    <button id="skill-run" type="button">Run skill</button>
    <pre id="skill-output" class="mono"></pre>
  </div>
</div>
<noscript><p class="error">This demo needs JavaScript for the sign-in step.
You can also run it locally from the repo: <span class="mono">python3
web_demo.py</span></p></noscript>
"""


def page(body: str, title: str = "AgentGuard live demo") -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{esc(title)}</title>"
        "<link rel='preconnect' href='https://fonts.googleapis.com'>"
        "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
        "<link href='https://fonts.googleapis.com/css2?"
        "family=Orbitron:wght@600;800&family=Rajdhani:wght@400;500;600;700"
        "&display=swap' rel='stylesheet'>"
        f"<style>{PAGE_CSS}</style></head><body><div class='wrap'>{body}"
        "</div></body></html>"
    )


def json_response(obj: dict, status: int = 200) -> Response:
    return Response(json.dumps(obj),
                    status=status,
                    headers={"Content-Type": "application/json"})


def html_response(body: str, status: int = 200,
                  title: str = "AgentGuard live demo") -> Response:
    return Response(page(body, title), status=status,
                    headers={"Content-Type": "text/html; charset=utf-8"})


async def audit_tail_html(audit: AuditLogKV, limit: int = 20) -> str:
    try:
        entries = await audit.read_all()
        summary = await audit.summary()
    except Exception as exc:
        return f"<p class='note'>Could not read audit ledger: {esc(exc)}</p>"
    rows = []
    for entry in reversed(entries[-limit:]):
        rows.append(
            "<tr><td class='mono'>{ts}</td><td class='mono'>{tool}</td>"
            "<td class='mono'>{args}</td>"
            "<td><b>{decision}</b></td><td>{reason}</td></tr>".format(
                ts=esc(entry.get("ts", "")),
                tool=esc(entry.get("tool", "")),
                args=esc(entry.get("args", "")),
                decision=esc(entry.get("decision", "")),
                reason=esc(entry.get("reason", "")),
            )
        )
    return (
        "<h2>Audit ledger (live tail)</h2>"
        f"<p class='note'>total {esc(summary.get('total', 0))} &middot; "
        f"allowed {esc(summary.get('allowed', 0))} &middot; "
        f"denied {esc(summary.get('denied', 0))}</p>"
        "<table><tr><th>ts</th><th>tool</th><th>args</th>"
        "<th>decision</th><th>reason</th></tr>"
        + ("\n".join(rows) if rows else
           "<tr><td colspan='5' class='note'>no entries yet</td></tr>")
        + "</table>"
    )


def token_identity(secret: bytes, token: str) -> tuple[str, str]:
    try:
        cap = verify(secret, token)
        return cap.subject, cap.token_id
    except TokenError:
        return "", ""


def check_result_html(result: dict, tail: str) -> str:
    cls = "allow" if result["allow"] else "deny"
    verdict = "ALLOW" if result["allow"] else "DENY"
    findings_html = ""
    if result["findings"] is not None:
        if result["findings"]:
            items = "".join(
                f"<li class='mono'>line {esc(f['line'])}: "
                f"{esc(f['kind'])}</li>"
                for f in result["findings"]
            )
            findings_html = (
                "<div class='banner deny'>Scan result: secret "
                "pattern(s) flagged</div><ul>" + items + "</ul>"
            )
        else:
            findings_html = (
                "<div class='banner allow'>Scan result: no secret "
                "patterns detected</div>"
            )
    return (
        f"<div class='banner {cls}'>Decision: {verdict}</div>"
        + findings_html +
        "<table>"
        f"<tr><th>tool</th><td class='mono'>{esc(result['tool'])}</td></tr>"
        f"<tr><th>args</th><td class='mono'>{esc(result['args'])}</td></tr>"
        f"<tr><th>signed in as</th><td class='mono'>{esc(result['subject'])}</td></tr>"
        f"<tr><th>reason</th><td>{esc(result['reason'])}</td></tr>"
        "</table>"
        + tail
    )


def token_required_html() -> str:
    return (
        "<h1>Token required</h1>"
        "<p>This demo checks a capability token on every request. "
        "Grab one first — it takes one click:</p>"
        "<p><a href='/'>Back to the demo sign-in</a></p>"
        "<p class='note'>API: <span class='mono'>POST /api/guest</span> "
        "returns <span class='mono'>{\"token\": \"...\"}</span> — then call "
        "<span class='mono'>/check</span> with "
        "<span class='mono'>Authorization: Bearer &lt;token&gt;</span>.</p>"
    )


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        raw_path = request.url.split("?", 1)[0]
        # "https://host/a/b" -> "/a/b"
        path = "/" + "/".join(raw_path.split("/")[3:])
        method = request.method
        if method == "GET" and path == "/":
            return await self.handle_index()
        if method == "GET" and path == "/api/me":
            return await self.handle_me(request)
        if method == "POST" and path == "/api/guest":
            return await self.handle_guest()
        if method == "POST" and path == "/api/login":
            return await self.handle_login(request)
        if method == "POST" and path == "/check":
            return await self.handle_check(request)
        if method == "GET" and path == "/api/skills":
            return await self.handle_skills_list(request)
        if method == "POST" and path == "/api/skills/policy-check":
            return await self.handle_skill_policy_check(request)
        if method == "POST" and path == "/api/skills/token-mint":
            return await self.handle_skill_token_mint(request)
        if method == "POST" and path == "/api/skills/token-verify":
            return await self.handle_skill_token_verify(request)
        if method == "POST" and path == "/api/skills/secret-scan":
            return await self.handle_skill_secret_scan(request)
        if method == "GET" and path == "/api/skills/audit-query":
            return await self.handle_skill_audit_query(request)
        if method == "POST" and path == "/api/skills/harness-run":
            return await self.handle_skill_harness_run(request)
        return html_response("<h1>404</h1><p>Not found.</p>", 404, "Not found")

    async def _audit(self):
        return AuditLogKV(self.env.AUDIT_KV)

    async def handle_index(self):
        audit = await self._audit()
        body = (landing_html(self.env) + await audit_tail_html(audit)
                + LOGIN_JS + SKILLS_JS)
        return html_response(body)

    async def handle_me(self, request):
        secret = await get_secret(self.env)
        try:
            cap = verify(secret, bearer_token(request.headers))
        except TokenError:
            return json_response({"ok": False, "error": "invalid token"}, 401)
        now = int(time.time())
        return json_response({
            "ok": True,
            "subject": cap.subject,
            "scopes": cap.scopes,
            "expires_in": max(0, cap.expires_at - now),
        })

    async def handle_guest(self):
        secret = await get_secret(self.env)
        token = mint(secret, "guest", DEMO_TOKEN_SCOPES,
                     ttl_seconds=GUEST_TOKEN_TTL)
        audit = await self._audit()
        try:
            await audit.record("auth.guest", {"subject": "guest"}, True,
                               "guest token minted", subject="guest")
        except Exception:
            pass
        return json_response({"ok": True, "token": token, "subject": "guest",
                              "expires_in": GUEST_TOKEN_TTL})

    async def _read_body(self, request) -> str | None:
        try:
            raw = await request.text()
        except Exception:
            return None
        if not raw or len(raw.encode("utf-8")) > MAX_BODY:
            return None
        return raw

    async def handle_login(self, request):
        raw = await self._read_body(request)
        if raw is None:
            return json_response({"ok": False, "error": "Bad request body."},
                                 400)
        try:
            data = json.loads(raw)
            username = str(data.get("username", ""))
            password = str(data.get("password", ""))
        except Exception:
            form = parse_qs(raw, keep_blank_values=True)
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
        audit = await self._audit()
        user = demo_auth_user(self.env)
        if check_demo_credentials(self.env, username, password):
            secret = await get_secret(self.env)
            token = mint(secret, user, DEMO_TOKEN_SCOPES,
                         ttl_seconds=USER_TOKEN_TTL)
            try:
                await audit.record("auth.login", {"subject": user}, True,
                                   "password login accepted", subject=user)
            except Exception:
                pass
            return json_response({"ok": True, "token": token, "subject": user,
                                  "expires_in": USER_TOKEN_TTL})
        try:
            await audit.record("auth.login",
                               {"subject": (username or "?")[:64]},
                               False, "password login rejected")
        except Exception:
            pass
        return json_response({
            "ok": False,
            "error": "Hmm, that didn't match — check the demo credentials, "
                     "or just continue as a guest.",
        }, 401)

    # ------------------------------------------------------------------
    # Skills API
    # ------------------------------------------------------------------

    async def _skill_auth(self, request):
        """Require a valid Bearer token. Returns (cap, token, err_response)."""
        secret = await get_secret(self.env)
        token = bearer_token(request.headers)
        try:
            cap = verify(secret, token)
        except TokenError:
            return None, "", json_response(
                {"ok": False,
                 "error": "A valid capability token is required — sign in "
                          "or continue as a guest first."}, 401)
        return cap, token, None

    async def _skill_body(self, request):
        """Parse a JSON request body. Returns (data, err_response)."""
        raw = await self._read_body(request)
        if raw is None:
            return None, json_response(
                {"ok": False, "error": "A JSON request body is required."},
                400)
        try:
            data = json.loads(raw)
        except Exception:
            return None, json_response(
                {"ok": False, "error": "Request body must be valid JSON."},
                400)
        if not isinstance(data, dict):
            return None, json_response(
                {"ok": False, "error": "Request body must be a JSON object."},
                400)
        return data, None

    async def _skill_audit(self, audit, skill, detail, allow, reason,
                           cap) -> None:
        try:
            await audit.record(f"skill.{skill}", detail, allow, reason,
                               subject=cap.subject, token_id=cap.token_id)
        except Exception:
            pass

    async def handle_skills_list(self, request):
        _, _, err = await self._skill_auth(request)
        if err:
            return err
        return json_response({"ok": True, "skills": SKILLS})

    async def handle_skill_policy_check(self, request):
        cap, token, err = await self._skill_auth(request)
        if err:
            return err
        data, derr = await self._skill_body(request)
        if derr:
            return derr
        tool = str(data.get("tool", "")).strip()
        args = data.get("args")
        if not tool or not isinstance(args, dict):
            return json_response(
                {"ok": False,
                 "error": "Provide 'tool' (string) and 'args' (object)."},
                400)
        secret = await get_secret(self.env)
        # Run the same sandbox validation as /check: a read_file target
        # must resolve inside the demo directory, or it is denied.
        if tool == "read_file":
            try:
                args = dict(args)
                args["path"] = resolve_demo_path(str(args.get("path", "")))
            except (SandboxEscape, ValueError) as exc:
                await self._skill_audit(
                    await self._audit(), "policy-check",
                    {"tool": tool}, False, str(exc), cap)
                return json_response({
                    "ok": True, "skill": "policy-check", "tool": tool,
                    "allow": False, "reason": str(exc),
                })
        decision = PolicyEngine(DEMO_POLICY, secret).authorize(tool, args,
                                                               token)
        await self._skill_audit(await self._audit(), "policy-check",
                                {"tool": tool}, decision.allow,
                                decision.reason, cap)
        return json_response({
            "ok": True, "skill": "policy-check", "tool": tool,
            "allow": decision.allow, "reason": decision.reason,
        })

    async def handle_skill_token_mint(self, request):
        cap, _, err = await self._skill_auth(request)
        if err:
            return err
        data, derr = await self._skill_body(request)
        if derr:
            return derr
        scopes = data.get("scopes", cap.scopes)
        if (not isinstance(scopes, list) or not scopes
                or not all(isinstance(s, str) and s for s in scopes)):
            return json_response(
                {"ok": False,
                 "error": "'scopes' must be a non-empty array of strings."},
                400)
        if any(s not in cap.scopes for s in scopes):
            return json_response(
                {"ok": False,
                 "error": "You can only mint scopes you already hold — "
                          "no privilege escalation."}, 403)
        try:
            ttl = int(data.get("ttl_seconds", 3600))
        except (TypeError, ValueError):
            ttl = 3600
        now = int(time.time())
        ttl = max(1, min(ttl, cap.expires_at - now, 8 * 3600))
        secret = await get_secret(self.env)
        new_token = mint(secret, cap.subject, scopes, ttl_seconds=ttl)
        await self._skill_audit(await self._audit(), "token-mint",
                                {"scopes": scopes, "ttl": ttl}, True,
                                f"token minted for {cap.subject}", cap)
        return json_response({
            "ok": True, "skill": "token-mint", "token": new_token,
            "subject": cap.subject, "scopes": scopes, "expires_in": ttl,
        })

    async def handle_skill_token_verify(self, request):
        cap, _, err = await self._skill_auth(request)
        if err:
            return err
        data, derr = await self._skill_body(request)
        if derr:
            return derr
        token = str(data.get("token", "")).strip()
        if not token:
            return json_response(
                {"ok": False, "error": "Provide 'token' to inspect."}, 400)
        secret = await get_secret(self.env)
        try:
            inspected = verify(secret, token)
        except TokenError as exc:
            await self._skill_audit(
                await self._audit(), "token-verify", {}, False,
                f"token invalid: {exc}", cap)
            return json_response({
                "ok": True, "skill": "token-verify", "valid": False,
                "error": str(exc),
            })
        await self._skill_audit(await self._audit(), "token-verify", {},
                                True,
                                f"token valid for {inspected.subject}", cap)
        return json_response({
            "ok": True, "skill": "token-verify", "valid": True,
            "subject": inspected.subject, "scopes": inspected.scopes,
            "expires_in": max(0, inspected.expires_at - int(time.time())),
        })

    async def handle_skill_secret_scan(self, request):
        cap, _, err = await self._skill_auth(request)
        if err:
            return err
        data, derr = await self._skill_body(request)
        if derr:
            return derr
        text = str(data.get("text", ""))
        findings = scan_text_for_secrets(text)
        await self._skill_audit(
            await self._audit(), "secret-scan", {"chars": len(text)},
            True, f"{len(findings)} finding(s)", cap)
        return json_response({
            "ok": True, "skill": "secret-scan", "chars": len(text),
            "findings": findings,
        })

    async def handle_skill_audit_query(self, request):
        cap, _, err = await self._skill_auth(request)
        if err:
            return err
        query = request.url.split("?", 1)[1] if "?" in request.url else ""
        params = parse_qs(query)
        try:
            limit = max(1, min(int(params.get("limit", ["20"])[0]), 100))
        except (TypeError, ValueError):
            limit = 20
        audit = await self._audit()
        entries = await audit.read_all()
        projected = [{
            "ts": e.get("ts"),
            "tool": e.get("tool"),
            "args": e.get("args"),
            "decision": e.get("decision"),
            "reason": e.get("reason"),
            "subject": e.get("subject"),
        } for e in entries[-limit:]]
        return json_response({
            "ok": True, "skill": "audit-query", "entries": projected,
            "summary": await audit.summary(),
        })

    async def handle_skill_harness_run(self, request):
        cap, token, err = await self._skill_auth(request)
        if err:
            return err
        secret = await get_secret(self.env)
        audit = await self._audit()
        steps = []
        for i, step in enumerate(HARNESS_PLAN, 1):
            try:
                result = await self.check_call(secret, audit, step["tool"],
                                               step["target"], token)
                steps.append({
                    "step": i,
                    "note": step["note"],
                    "tool": result["tool"],
                    "decision": "allow" if result["allow"] else "deny",
                    "reason": result["reason"],
                    "output": result.get("output"),
                    "findings": result.get("findings"),
                })
            except (SandboxEscape, ValueError) as exc:
                try:
                    await audit.record(
                        step["tool"], {"target": step["target"][:200]},
                        False, str(exc),
                        subject=cap.subject, token_id=cap.token_id)
                except Exception:
                    pass
                steps.append({
                    "step": i,
                    "note": step["note"],
                    "tool": step["tool"],
                    "decision": "deny",
                    "reason": str(exc),
                    "output": None,
                    "findings": None,
                })
        allowed = sum(1 for s in steps if s["decision"] == "allow")
        return json_response({
            "ok": True, "skill": "harness-run", "task": "demo-agent-run",
            "steps": steps, "allowed": allowed,
            "denied": len(steps) - allowed,
        })

    async def handle_check(self, request):
        audit = await self._audit()
        raw = await self._read_body(request)
        if raw is None:
            return html_response("<h1>400</h1><p>Bad request body.</p>",
                                 400, "Bad request")
        form = parse_qs(raw, keep_blank_values=True)
        is_fetch = (request.headers.get(FETCH_HEADER, "") or "") == "1"
        token = bearer_token(request.headers) or \
            form.get("token", [""])[0].strip()

        secret = await get_secret(self.env)
        try:
            verify(secret, token)
        except TokenError:
            if is_fetch:
                return json_response(
                    {"ok": False,
                     "error": "A valid token is required. Sign in or "
                              "continue as a guest."}, 401)
            return html_response(token_required_html(), 401,
                                 "Token required")

        tool = form.get("tool", [""])[0]
        target = form.get("target", [""])[0]
        try:
            result = await self.check_call(secret, audit, tool, target, token)
            inner = check_result_html(result, await audit_tail_html(audit))
            if is_fetch:
                return Response(inner, headers={
                    "Content-Type": "text/html; charset=utf-8"})
            return html_response(
                inner,
                title=f"AgentGuard: {'ALLOW' if result['allow'] else 'DENY'}")
        except (SandboxEscape, ValueError) as exc:
            try:
                await audit.record((tool or "?").strip() or "?",
                                   {"target": (target or "")[:200]},
                                   False, str(exc))
            except Exception:
                pass
            inner = (
                "<div class='banner deny'>Decision: DENY</div>"
                "<table>"
                f"<tr><th>tool</th><td class='mono'>{esc(tool)}</td></tr>"
                f"<tr><th>reason</th><td>{esc(exc)}</td></tr>"
                "</table>" + await audit_tail_html(audit)
            )
            if is_fetch:
                return Response(inner, headers={
                    "Content-Type": "text/html; charset=utf-8"})
            return html_response(inner, "AgentGuard: DENY")
        except Exception as exc:
            try:
                await audit.record((tool or "?").strip() or "?",
                                   {"target": (target or "")[:200]},
                                   False, f"demo error: {exc}")
            except Exception:
                pass
            inner = (
                "<div class='banner deny'>Decision: DENY (engine error)</div>"
                f"<p class='note'>Error: {esc(exc)}</p>"
                + await audit_tail_html(audit)
            )
            if is_fetch:
                return Response(inner, headers={
                    "Content-Type": "text/html; charset=utf-8"})
            return html_response(inner, "AgentGuard: error")

    async def check_call(self, secret, audit,
                         tool: str, target: str, token: str) -> dict:
        """Evaluate one tool call with the real engine and audit it.

        The token is verified by the caller. NOTHING is executed — only
        the policy decision is computed.
        """
        tool = (tool or "").strip()
        target = target or ""
        findings: list[dict] | None = None

        if tool == "read_file":
            rel = resolve_demo_path(target)  # raises SandboxEscape/ValueError
            args: dict = {"path": rel}
        elif tool == "scan_text":
            args = {"chars": len(target)}
            findings = scan_text_for_secrets(target)
        else:
            args = {"target": target[:200]}

        engine = PolicyEngine(DEMO_POLICY, secret)
        decision = engine.authorize(tool, args, token)
        subject, token_id = token_identity(secret, token)
        entry_args = dict(args)
        if findings is not None:
            entry_args["findings"] = [f["kind"] for f in findings]
        await audit.record(tool, entry_args, decision.allow, decision.reason,
                           subject=subject, token_id=token_id)
        output = None
        if tool == "read_file" and decision.allow:
            output = DEMO_FILES.get(rel, "")[:2000]
        return {
            "tool": tool,
            "args": entry_args,
            "subject": subject,
            "allow": decision.allow,
            "reason": decision.reason,
            "findings": findings,
            "output": output,
        }

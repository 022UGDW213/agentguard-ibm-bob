#!/usr/bin/env python3
"""AgentGuard live web demo (Python stdlib only) — hardened public version.

Serves a small HTML UI on 127.0.0.1:8765 that runs the REAL AgentGuard
policy engine (agentguard.policy.PolicyEngine) against submitted tool
calls and records every decision in the REAL append-only audit ledger
(agentguard.audit.AuditLog). No mocks, no stubs, no simulated decisions.

Hardening (this demo is public-facing):
  * NOTHING is ever executed: no subprocess, no os.system, no eval/exec,
    no network fetch. Only policy decisions are evaluated.
  * Tool allowlist: only `read_file` (sandboxed to ./demo_files/) and
    `scan_text` (scans pasted text with the real secret-pattern regexes,
    no filesystem). Anything else is denied by default.
  * Path sandboxing: absolute paths, `..`, and anything outside
    ./demo_files/ are denied with "path escapes sandbox" BEFORE any
    filesystem access.
  * The raw audit ledger is never served; only an HTML-escaped rendered
    tail (last 20 entries) is shown. No absolute paths are disclosed.

Run:
    python3 web_demo.py
Then open http://127.0.0.1:8765/ in a browser.
"""

from __future__ import annotations

import html
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

# Resolve the agentguard package from this file's directory.
PROJECT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_DIR))

from agentguard import tokens as _tokens  # noqa: E402
from agentguard.audit import AuditLog  # noqa: E402
from agentguard.policy import Policy, PolicyEngine  # noqa: E402
from agentguard.scanner import SECRET_PATTERNS  # noqa: E402

HOST = "127.0.0.1"
PORT = 8765
DEMO_DIR = PROJECT_DIR / "demo_files"
AUDIT_PATH = PROJECT_DIR / "web_demo_audit.jsonl"
MAX_BODY = 64 * 1024  # max POST body size
MAX_SCAN_LINES = 500
MAX_FINDINGS = 50

# Server-wide HMAC secret for demo tokens (fresh on every start).
SECRET = secrets.token_bytes(32)

# Demo policy: only the two demo tools are allowed. Path confinement for
# read_file is enforced in code (resolve_demo_path) before the engine runs.
DEMO_POLICY = Policy.from_dict({
    "rules": [
        {"effect": "allow", "tool": "read_file"},
        {"effect": "allow", "tool": "scan_text"},
    ]
})

ENGINE = PolicyEngine(DEMO_POLICY, SECRET)
AUDIT = AuditLog(AUDIT_PATH)

DEMO_TOKEN_SCOPES = ["tool:read_file", "tool:scan_text"]


class SandboxEscape(Exception):
    """Raised when a read_file target tries to leave the demo directory."""


def ensure_demo_files() -> None:
    """Create the demo directory with canned harmless files on first run."""
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    canned = {
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
    for name, content in canned.items():
        path = DEMO_DIR / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def resolve_demo_path(target: str) -> str:
    """Validate a read_file target; return its demo-relative name.

    Rejects absolute paths, `..` segments, and anything that resolves
    outside the demo directory — BEFORE any filesystem access to the
    target. Raises SandboxEscape or ValueError.
    """
    name = (target or "").strip()
    if not name:
        raise ValueError("target is required")
    if name.startswith(("/", "\\", "~")) or ":" in name[:3]:
        raise SandboxEscape("path escapes sandbox")
    candidate = Path(name)
    if ".." in candidate.parts or candidate.is_absolute():
        raise SandboxEscape("path escapes sandbox")
    root = DEMO_DIR.resolve()
    resolved = (root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise SandboxEscape("path escapes sandbox")
    # Confined to the demo dir: this metadata check is safe.
    if not resolved.is_file():
        raise ValueError("file not found in demo directory")
    return resolved.relative_to(root).as_posix()


def scan_text_for_secrets(text: str) -> list[dict]:
    """Scan pasted text with the REAL secret-pattern regexes.

    Pure string matching — no filesystem access.
    """
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


def token_identity(token: str) -> tuple[str, str]:
    """Best-effort subject/token_id extraction for the audit record."""
    try:
        cap = _tokens.verify(SECRET, token)
        return cap.subject, cap.token_id
    except _tokens.TokenError:
        return "", ""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


PAGE_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
     max-width:860px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.6rem} .sub{color:#555;margin-top:-0.5rem}
.sandbox-note{background:#fff8c5;border:1px solid #d4a72c;border-radius:8px;
     padding:.7rem 1rem;margin:1rem 0;font-weight:600}
form{background:#f6f8fa;border:1px solid #ddd;border-radius:8px;
     padding:1rem;margin:1rem 0}
label{display:block;margin:.6rem 0 .2rem;font-weight:600}
input[type=text],textarea{width:100%;box-sizing:border-box;
     padding:.5rem;border:1px solid #bbb;border-radius:4px;font-size:1rem}
button{margin-top:.8rem;padding:.6rem 1.2rem;font-size:1rem;
       background:#0969da;color:#fff;border:0;border-radius:6px;cursor:pointer}
.banner{padding:.8rem 1rem;border-radius:8px;margin:1rem 0;font-weight:600}
.allow{background:#dafbe1;border:1px solid #4ac26b}
.deny{background:#ffebe9;border:1px solid #ff8182}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin-top:.5rem}
th,td{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}
th{background:#f0f0f0} .mono{font-family:ui-monospace,Menlo,monospace}
.note{color:#555;font-size:.9rem}
"""

FORM_HTML = """
<h1>AgentGuard live demo</h1>
<p class="sub">Model-agnostic security harness for AI agents &mdash;
every tool call below is evaluated by the <span class="mono">real</span>
deny-by-default policy engine and written to the <span class="mono">real</span>
append-only audit ledger. No mocks, no simulated decisions.</p>
<div class="sandbox-note">Demo sandbox &mdash; policy decisions only,
nothing is executed.</div>
<form method="post" action="/check">
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
  <label for="token">Capability token (optional)</label>
  <textarea id="token" name="token" rows="2"
    placeholder="Leave blank for a server-minted demo token"></textarea>
  <button type="submit">Check tool call</button>
</form>
<p class="note">Try: <span class="mono">read_file</span> on
<span class="mono">welcome.txt</span> (allowed) vs
<span class="mono">/etc/passwd</span> or
<span class="mono">../../etc/passwd</span> (denied: path escapes sandbox),
<span class="mono">run_command</span> on anything (denied), or
<span class="mono">scan_text</span> on text containing
<span class="mono">AKIAIOSFODNN7EXAMPLE</span> (flagged).</p>
"""


def audit_tail_html(limit: int = 20) -> str:
    try:
        entries = AUDIT.read_all()
        summary = AUDIT.summary()
    except Exception as exc:  # never let a ledger read break the page
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


def page(body: str, title: str = "AgentGuard live demo") -> bytes:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{esc(title)}</title>"
        f"<style>{PAGE_CSS}</style></head><body>{body}</body></html>"
    ).encode("utf-8")


def check_call(tool: str, target: str, token: str) -> dict:
    """Evaluate one tool call with the real engine and audit the decision.

    NOTHING is executed — no subprocess, no eval, no network, no file
    reads of user targets. Only the policy decision is computed.
    """
    tool = (tool or "").strip()
    target = target or ""
    findings: list[dict] | None = None

    if tool == "read_file":
        # Sandboxing first: denied before any filesystem access.
        rel = resolve_demo_path(target)  # raises SandboxEscape/ValueError
        args: dict = {"path": rel}
    elif tool == "scan_text":
        args = {"chars": len(target)}
        findings = scan_text_for_secrets(target)
    else:
        # Unknown tool: straight to the real engine, which denies by
        # default (no allow rule matches).
        args = {"target": target[:200]}

    if not token.strip():
        token = _tokens.mint(SECRET, "web-demo",
                             DEMO_TOKEN_SCOPES, ttl_seconds=3600)
        token_source = "server-minted demo token"
    else:
        token = token.strip()
        token_source = "user-supplied token"

    decision = ENGINE.authorize(tool, args, token)
    subject, token_id = token_identity(token)
    entry_args = dict(args)
    if findings is not None:
        entry_args["findings"] = [f["kind"] for f in findings]
    entry = AUDIT.record(tool, entry_args, decision.allow, decision.reason,
                         subject=subject, token_id=token_id)
    return {
        "tool": tool,
        "args": entry_args,
        "token_source": token_source,
        "allow": decision.allow,
        "reason": decision.reason,
        "findings": findings,
        "entry": entry,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuardDemo/1.0"

    def log_message(self, *args):  # keep stdout quiet
        pass

    def _send(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/":
            self._send(page("<h1>404</h1><p>Not found.</p>",
                            "Not found"), 404)
            return
        self._send(page(FORM_HTML + audit_tail_html()))

    def do_POST(self) -> None:
        if self.path != "/check":
            self._send(page("<h1>404</h1><p>Not found.</p>",
                            "Not found"), 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send(page("<h1>400</h1><p>Bad request body.</p>",
                            "Bad request"), 400)
            return
        try:
            raw = self.rfile.read(length).decode("utf-8", "replace")
            form = parse_qs(raw, keep_blank_values=True)
            tool = form.get("tool", [""])[0]
            target = form.get("target", [""])[0]
            token = form.get("token", [""])[0]
        except Exception as exc:
            self._send(page("<h1>400</h1><p>Could not parse form: "
                            f"{esc(exc)}</p>", "Bad request"), 400)
            return

        try:
            result = check_call(tool, target, token)
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
            body = (
                f"<div class='banner {cls}'>Decision: {verdict}</div>"
                + findings_html +
                "<table>"
                f"<tr><th>tool</th><td class='mono'>{esc(result['tool'])}</td></tr>"
                f"<tr><th>args</th><td class='mono'>{esc(result['args'])}</td></tr>"
                f"<tr><th>token</th><td>{esc(result['token_source'])}</td></tr>"
                f"<tr><th>reason</th><td>{esc(result['reason'])}</td></tr>"
                "</table>"
                "<p><a href='/'>&larr; back to demo</a></p>"
                + audit_tail_html()
            )
            self._send(page(body, f"AgentGuard: {verdict}"))
        except (SandboxEscape, ValueError) as exc:
            # Denied before any filesystem access; still audit the attempt.
            try:
                AUDIT.record((tool or "?").strip() or "?",
                             {"target": (target or "")[:200]},
                             False, str(exc))
            except Exception:
                pass
            body = (
                "<div class='banner deny'>Decision: DENY</div>"
                "<table>"
                f"<tr><th>tool</th><td class='mono'>{esc(tool)}</td></tr>"
                f"<tr><th>reason</th><td>{esc(exc)}</td></tr>"
                "</table>"
                "<p><a href='/'>&larr; back to demo</a></p>"
                + audit_tail_html()
            )
            self._send(page(body, "AgentGuard: DENY"))
        except Exception as exc:
            try:
                AUDIT.record((tool or "?").strip() or "?",
                             {"target": (target or "")[:200]},
                             False, f"demo error: {exc}")
            except Exception:
                pass
            body = (
                "<div class='banner deny'>Decision: DENY (engine error)</div>"
                f"<p class='note'>Error: {esc(exc)}</p>"
                "<p><a href='/'>&larr; back to demo</a></p>"
                + audit_tail_html()
            )
            self._send(page(body, "AgentGuard: error"))


def main() -> int:
    ensure_demo_files()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"AgentGuard demo serving on http://{HOST}:{PORT}/ "
          f"(demo files: {DEMO_DIR})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

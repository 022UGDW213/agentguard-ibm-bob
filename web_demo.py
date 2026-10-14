#!/usr/bin/env python3
"""AgentGuard live web demo (Python stdlib only) — hardened public version.

Serves a small HTML UI on 127.0.0.1:8765 that runs the REAL AgentGuard
policy engine (agentguard.policy.PolicyEngine) against submitted tool
calls and records every decision in the REAL append-only audit ledger
(agentguard.audit.AuditLog). No mocks, no stubs, no simulated decisions.

Token-based login:
  * POST /api/guest -> mints a limited guest capability token (1h TTL).
    One click, no signup — this is the zero-friction path for visitors.
  * POST /api/login {username, password} -> mints a user capability token
    (8h TTL). The demo credential comes ONLY from the environment
    (AG_DEMO_USER / AG_DEMO_PASSWORD); nothing is hardcoded or committed.
    Password login is disabled when AG_DEMO_PASSWORD is unset.
  * The frontend keeps the token in localStorage and presents it as
    `Authorization: Bearer <token>` on every /check request.
  * /check verifies the token server-side on each request (signature +
    expiry + scopes). No token, or a bad one, -> 401, never a decision.

Secrets hygiene:
  * The HMAC signing key comes from AG_HMAC_SECRET (base64 or raw) when
    set, otherwise a fresh random key is generated per process start.
    No key is ever committed to the repo.

Hardening (this demo is public-facing):
  * NOTHING is ever executed: no subprocess, no os.system, no eval/exec,
    no network fetch. Only policy decisions are evaluated.
  * Tool allowlist: only `read_file` (sandboxed to ./demo_files/) and
    `scan_text` (scans pasted text with the real secret-pattern regexes,
    no filesystem). Anything else is denied by default.
  * Path sandboxing: absolute paths, `..`, and anything outside
    ./demo_files/ are denied with "path escapes sandbox" BEFORE any
    filesystem access to the target.
  * The raw audit ledger is never served; only an HTML-escaped rendered
    tail (last 20 entries) is shown. No absolute paths are disclosed.

Run:
    AG_DEMO_USER=demo AG_DEMO_PASSWORD=agentguard python3 web_demo.py
Then open http://127.0.0.1:8765/ in a browser.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sys
import threading
import time
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
FETCH_HEADER = "X-AgentGuard-Fetch"  # sent by the page JS on fetch calls


def _load_secret() -> bytes:
    """HMAC signing key: env var first, else fresh random per start.

    AG_HMAC_SECRET may be base64 or a raw string. Never committed.
    """
    raw = os.environ.get("AG_HMAC_SECRET", "").strip()
    if raw:
        try:
            return base64.b64decode(raw)
        except Exception:
            return raw.encode("utf-8")
    return secrets.token_bytes(32)


# Server-wide HMAC secret for demo tokens.
SECRET = _load_secret()

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
GUEST_TOKEN_TTL = 3600
USER_TOKEN_TTL = 8 * 3600

# Demo password login. The credential lives ONLY in the environment —
# nothing is hardcoded here or committed to the repo. When
# AG_DEMO_PASSWORD is unset, password login is disabled and the landing
# page offers the guest path only.
DEMO_AUTH_USER = os.environ.get("AG_DEMO_USER", "demo")
DEMO_AUTH_PASSWORD = os.environ.get("AG_DEMO_PASSWORD", "")


class SandboxEscape(Exception):
    """Raised when a read_file target tries to leave the demo directory."""


def password_login_enabled() -> bool:
    """True when a demo password credential is configured via env."""
    return bool(DEMO_AUTH_PASSWORD)


def check_demo_credentials(username: str, password: str) -> bool:
    """Verify the demo username/password against the env-configured value."""
    if not DEMO_AUTH_PASSWORD:
        return False
    if (username or "") != DEMO_AUTH_USER:
        # Compare anyway so a wrong username costs the same as a wrong
        # password (no cheap user enumeration).
        hmac.compare_digest(password or "", DEMO_AUTH_PASSWORD)
        return False
    return hmac.compare_digest(password or "", DEMO_AUTH_PASSWORD)


def mint_guest_token() -> str:
    """Mint a limited guest capability token (short TTL)."""
    return _tokens.mint(SECRET, "guest", DEMO_TOKEN_SCOPES,
                        ttl_seconds=GUEST_TOKEN_TTL)


def mint_user_token(username: str) -> str:
    """Mint a user capability token after a successful password login."""
    return _tokens.mint(SECRET, username, DEMO_TOKEN_SCOPES,
                        ttl_seconds=USER_TOKEN_TTL)


def verify_token(token: str) -> _tokens.CapabilityToken:
    """Verify a presented token (signature + expiry). Raises TokenError."""
    return _tokens.verify(SECRET, (token or "").strip())


def bearer_token(headers) -> str:
    """Extract a `Bearer <token>` value from request headers ("" if none).

    Works with case-insensitive header maps (http.server) and plain dicts.
    """
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


def token_identity(token: str) -> tuple[str, str]:
    """Best-effort subject/token_id extraction for the audit record."""
    try:
        cap = _tokens.verify(SECRET, token)
        return cap.subject, cap.token_id
    except _tokens.TokenError:
        return "", ""


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
input[type=text],input[type=password],textarea{width:100%;box-sizing:border-box;
     padding:.5rem;border:1px solid #bbb;border-radius:4px;font-size:1rem}
button{margin-top:.8rem;padding:.6rem 1.2rem;font-size:1rem;
       background:#0969da;color:#fff;border:0;border-radius:6px;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}
.big-guest{display:block;width:100%;padding:.9rem;font-size:1.1rem;
       font-weight:600;margin:.6rem 0}
#login-card{background:#f6f8fa;border:1px solid #ddd;border-radius:8px;
     padding:1.2rem;margin:1rem 0}
#login-card h2{margin-top:0}
.error{color:#d1242f;font-weight:600;min-height:1.2em}
.banner{padding:.8rem 1rem;border-radius:8px;margin:1rem 0;font-weight:600}
.allow{background:#dafbe1;border:1px solid #4ac26b}
.deny{background:#ffebe9;border:1px solid #ff8182}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin-top:.5rem}
th,td{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}
th{background:#f0f0f0} .mono{font-family:ui-monospace,Menlo,monospace}
.note{color:#555;font-size:.9rem}
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


def landing_html() -> str:
    """Landing page: login card (guest one-click + optional password form),
    the demo section (revealed by JS after login), and the audit tail."""
    if password_login_enabled():
        login_form = f"""
  <p style="margin-top:1.2rem">Or sign in with the demo account:</p>
  <form id="login-form">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" value="{esc(DEMO_AUTH_USER)}"
           autocomplete="username">
    <label for="password">Password</label>
    <input type="password" id="password" name="password"
           autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
  <p class="note">Demo credentials: <span class="mono">{esc(DEMO_AUTH_USER)}</span> /
  <span class="mono">{esc(DEMO_AUTH_PASSWORD)}</span> — same access as a guest,
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
<div class="sandbox-note">Demo sandbox &mdash; policy decisions only,
nothing is executed.</div>
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
</div>
<noscript><p class="error">This demo needs JavaScript for the sign-in step.
You can also run it locally from the repo: <span class="mono">python3
web_demo.py</span></p></noscript>
""" + audit_tail_html() + LOGIN_JS


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


def check_result_html(result: dict, tail: str) -> str:
    """Inner HTML for a /check decision (fragment for fetch, or page body)."""
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


def check_call(tool: str, target: str, token: str) -> dict:
    """Evaluate one tool call with the real engine and audit the decision.

    The token must already be verified by the caller. NOTHING is executed —
    no subprocess, no eval, no network, no file reads of user targets.
    Only the policy decision is computed.
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

    decision = ENGINE.authorize(tool, args, token)
    subject, token_id = token_identity(token)
    entry_args = dict(args)
    if findings is not None:
        entry_args["findings"] = [f["kind"] for f in findings]
    AUDIT.record(tool, entry_args, decision.allow, decision.reason,
                 subject=subject, token_id=token_id)
    return {
        "tool": tool,
        "args": entry_args,
        "subject": subject,
        "allow": decision.allow,
        "reason": decision.reason,
        "findings": findings,
    }


def _audit_auth(kind: str, subject: str, allow: bool, reason: str) -> None:
    try:
        AUDIT.record(f"auth.{kind}", {"subject": subject}, allow, reason,
                     subject=subject)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuardDemo/2.0"

    def log_message(self, *args):  # keep stdout quiet
        pass

    def _send(self, body: bytes, status: int = 200,
              ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: dict, status: int = 200) -> None:
        self._send(json.dumps(obj).encode("utf-8"), status,
                   "application/json")

    def _read_body(self) -> str | None:
        """Read the POST body; None when missing or over the limit."""
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            return self.rfile.read(length).decode("utf-8", "replace")
        except Exception:
            return None

    def _is_fetch(self) -> bool:
        return (self.headers.get(FETCH_HEADER, "") or "") == "1"

    # -- GET ------------------------------------------------------------
    def do_GET(self) -> None:
        if self.path == "/":
            self._send(page(landing_html()))
            return
        if self.path == "/api/me":
            token = bearer_token(self.headers)
            try:
                cap = verify_token(token)
            except _tokens.TokenError:
                self._send_json({"ok": False, "error": "invalid token"}, 401)
                return
            now = int(time.time())
            self._send_json({
                "ok": True,
                "subject": cap.subject,
                "scopes": cap.scopes,
                "expires_in": max(0, cap.expires_at - now),
            })
            return
        self._send(page("<h1>404</h1><p>Not found.</p>", "Not found"), 404)

    # -- POST -----------------------------------------------------------
    def do_POST(self) -> None:
        if self.path == "/api/guest":
            token = mint_guest_token()
            _audit_auth("guest", "guest", True, "guest token minted")
            self._send_json({"ok": True, "token": token, "subject": "guest",
                             "expires_in": GUEST_TOKEN_TTL})
            return
        if self.path == "/api/login":
            raw = self._read_body()
            if raw is None:
                self._send_json({"ok": False,
                                 "error": "Bad request body."}, 400)
                return
            try:
                data = json.loads(raw)
                username = str(data.get("username", ""))
                password = str(data.get("password", ""))
            except Exception:
                form = parse_qs(raw, keep_blank_values=True)
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
            if check_demo_credentials(username, password):
                token = mint_user_token(DEMO_AUTH_USER)
                _audit_auth("login", DEMO_AUTH_USER, True,
                            "password login accepted")
                self._send_json({"ok": True, "token": token,
                                 "subject": DEMO_AUTH_USER,
                                 "expires_in": USER_TOKEN_TTL})
            else:
                _audit_auth("login", (username or "?")[:64], False,
                            "password login rejected")
                self._send_json({
                    "ok": False,
                    "error": "Hmm, that didn't match — check the demo "
                             "credentials, or just continue as a guest.",
                }, 401)
            return
        if self.path == "/check":
            self._handle_check()
            return
        self._send(page("<h1>404</h1><p>Not found.</p>", "Not found"), 404)

    def _handle_check(self) -> None:
        raw = self._read_body()
        if raw is None:
            self._send(page("<h1>400</h1><p>Bad request body.</p>",
                            "Bad request"), 400)
            return
        form = parse_qs(raw, keep_blank_values=True)
        # Authorization header wins; the form field is a fallback for
        # non-JS clients (the page JS always uses the header).
        token = bearer_token(self.headers) or \
            form.get("token", [""])[0].strip()
        try:
            verify_token(token)
        except _tokens.TokenError:
            if self._is_fetch():
                self._send_json({"ok": False,
                                 "error": "A valid token is required. "
                                          "Sign in or continue as a guest."},
                                401)
            else:
                body = (
                    "<h1>Token required</h1>"
                    "<p>This demo checks a capability token on every request. "
                    "Grab one first — it takes one click:</p>"
                    "<p><a href='/'>Back to the demo sign-in</a></p>"
                    "<p class='note'>API: <span class='mono'>POST /api/guest"
                    "</span> returns <span class='mono'>{\"token\": \"...\"}"
                    "</span> — then call <span class='mono'>/check</span> with "
                    "<span class='mono'>Authorization: Bearer &lt;token&gt;"
                    "</span>.</p>"
                )
                self._send(page(body, "Token required"), 401)
            return

        tool = form.get("tool", [""])[0]
        target = form.get("target", [""])[0]
        try:
            result = check_call(tool, target, token)
            inner = check_result_html(result, audit_tail_html())
            if self._is_fetch():
                self._send(inner.encode("utf-8"))
            else:
                self._send(page(inner, f"AgentGuard: "
                            f"{'ALLOW' if result['allow'] else 'DENY'}"))
        except (SandboxEscape, ValueError) as exc:
            # Denied before any filesystem access; still audit the attempt.
            try:
                AUDIT.record((tool or "?").strip() or "?",
                             {"target": (target or "")[:200]},
                             False, str(exc))
            except Exception:
                pass
            inner = (
                "<div class='banner deny'>Decision: DENY</div>"
                "<table>"
                f"<tr><th>tool</th><td class='mono'>{esc(tool)}</td></tr>"
                f"<tr><th>reason</th><td>{esc(exc)}</td></tr>"
                "</table>" + audit_tail_html()
            )
            if self._is_fetch():
                self._send(inner.encode("utf-8"))
            else:
                self._send(page(inner, "AgentGuard: DENY"))
        except Exception as exc:
            try:
                AUDIT.record((tool or "?").strip() or "?",
                             {"target": (target or "")[:200]},
                             False, f"demo error: {exc}")
            except Exception:
                pass
            inner = (
                "<div class='banner deny'>Decision: DENY (engine error)</div>"
                f"<p class='note'>Error: {esc(exc)}</p>"
                + audit_tail_html()
            )
            if self._is_fetch():
                self._send(inner.encode("utf-8"))
            else:
                self._send(page(inner, "AgentGuard: error"))


def main() -> int:
    ensure_demo_files()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"AgentGuard demo serving on http://{HOST}:{PORT}/ "
          f"(demo files: {DEMO_DIR})", flush=True)
    print(f"Password login: {'enabled' if password_login_enabled() else 'disabled'} "
          f"(AG_DEMO_PASSWORD {'set' if password_login_enabled() else 'unset'})",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

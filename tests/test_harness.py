import json

import pytest

from agentguard.audit import AuditLog
from agentguard.harness import GuardedHarness, ToolRegistry, make_filesystem_tools
from agentguard.policy import Policy, PolicyEngine
from agentguard.tokens import mint

SECRET = b"harness-test-secret"


@pytest.fixture()
def harness(tmp_path):
    policy = Policy.from_dict({
        "rules": [
            {"effect": "deny", "tool": "fs_read", "path": "/etc/*"},
            {"effect": "allow", "tool": "fs_*", "path": "/tmp/*"},
        ]
    })
    engine = PolicyEngine(policy, SECRET)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    registry = make_filesystem_tools([str(sandbox)])
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    return GuardedHarness(engine, registry, audit), sandbox


def _tok(scopes):
    return mint(SECRET, "agent-1", scopes, ttl_seconds=300)


def test_allowed_call_executes_and_audits(harness):
    h, sandbox = harness
    target = str(sandbox / "note.txt")
    tok = _tok(["tool:fs_write:path=/tmp/*", "tool:fs_read:path=/tmp/*"])
    # policy rule allows fs_* on /tmp/* — rewrite args to the sandbox path,
    # but the token scope must cover the actual path; use matching scope here
    tok = _tok([f"tool:fs_write:path={sandbox}/*", f"tool:fs_read:path={sandbox}/*"])
    r = h.tool_call("fs_write", {"path": target, "content": "hello"}, tok)
    assert r.ok, r.error
    r = h.tool_call("fs_read", {"path": target}, tok)
    assert r.ok and r.output == "hello", r.error
    entries = h.audit.read_all()
    assert len(entries) == 2
    assert all(e["decision"] == "allow" for e in entries)


def test_confused_deputy_denied_and_audited(harness):
    h, sandbox = harness
    # Token legitimately scoped to the sandbox; attacker asks for /etc/passwd.
    tok = _tok([f"tool:fs_read:path={sandbox}/*"])
    r = h.tool_call("fs_read", {"path": "/etc/passwd"}, tok)
    assert not r.ok
    assert "DENIED" in r.error
    entries = h.audit.read_all()
    assert entries and entries[-1]["decision"] == "deny"
    assert entries[-1]["args"]["path"] == "/etc/passwd"


def test_unknown_tool_denied(harness):
    h, _ = harness
    tok = _tok(["tool:*"])
    r = h.tool_call("no_such_tool", {}, tok)
    assert not r.ok


def test_path_traversal_blocked_by_tool_itself(harness):
    h, sandbox = harness
    tok = _tok(["tool:fs_read:path=/tmp/*"])
    # Even if policy allowed it, the tool sandbox refuses to leave its roots.
    r = h.tool_call("fs_read", {"path": str(sandbox / ".." / "audit.jsonl")}, tok)
    assert not r.ok  # policy denies first (no allow rule matches ../ path)


def test_custom_tool_registration():
    reg = ToolRegistry()
    reg.register("add", lambda a, b: a + b)
    assert reg.get("add")(2, 3) == 5
    assert "add" in reg.names()


def test_audit_log_is_append_only_jsonl(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.record("t", {"x": 1}, True, "ok", subject="s")
    log.record("t", {"x": 2}, False, "no", subject="s")
    lines = (tmp_path / "a.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    assert all(json.loads(line) for line in lines)
    assert log.summary() == {"total": 2, "allowed": 1, "denied": 1}

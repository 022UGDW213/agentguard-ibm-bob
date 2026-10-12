import pytest

from agentguard.policy import Policy, PolicyEngine
from agentguard.tokens import mint

SECRET = b"policy-test-secret"

POLICY = Policy.from_dict({
    "rules": [
        {"effect": "deny", "tool": "fs_write", "path": "/etc/*"},
        {"effect": "allow", "tool": "fs_read", "path": "/tmp/*"},
        {"effect": "allow", "tool": "fs_write", "path": "/tmp/*"},
    ]
})


def _engine():
    return PolicyEngine(POLICY, SECRET)


def _tok(scopes):
    return mint(SECRET, "agent-1", scopes, ttl_seconds=300)


def test_allow_with_matching_rule_and_scope():
    d = _engine().authorize("fs_read", {"path": "/tmp/a.txt"},
                            _tok(["tool:fs_read:path=/tmp/*"]))
    assert d.allow, d.reason


def test_deny_by_default_no_matching_rule():
    d = _engine().authorize("shell_exec", {"cmd": "ls"},
                            _tok(["tool:shell_exec"]))
    assert not d.allow
    assert "deny by default" in d.reason


def test_explicit_deny_wins_over_allow():
    d = _engine().authorize("fs_write", {"path": "/etc/hosts"},
                            _tok(["tool:fs_write:path=/etc/*"]))
    assert not d.allow
    assert "denied by rule" in d.reason


def test_allow_rule_but_scope_too_narrow():
    d = _engine().authorize("fs_read", {"path": "/tmp/a.txt"},
                            _tok(["tool:fs_read:path=/var/*"]))
    assert not d.allow
    assert "scopes" in d.reason


def test_bad_token_rejected():
    d = _engine().authorize("fs_read", {"path": "/tmp/a.txt"}, "garbage.token")
    assert not d.allow
    assert "token rejected" in d.reason


def test_wildcard_scope():
    d = _engine().authorize("fs_write", {"path": "/tmp/x"},
                            _tok(["tool:*"]))
    assert d.allow, d.reason


def test_bad_policy_rejected():
    with pytest.raises(ValueError):
        Policy.from_dict({"rules": [{"effect": "maybe", "tool": "x"}]})
    with pytest.raises(ValueError):
        Policy.from_dict({"rules": [{"effect": "allow"}]})

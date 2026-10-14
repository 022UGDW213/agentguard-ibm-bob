"""Round-trip tests for agentguard.json_io."""

import json

import pytest

from agentguard import json_io
from agentguard.audit import AuditLog
from agentguard.policy import Decision, Policy, PolicyEngine
from agentguard.tokens import CapabilityToken, mint, verify

SECRET = b"test-secret-for-json-io"


def test_policy_round_trip():
    policy = Policy.from_dict(
        {
            "rules": [
                {"effect": "allow", "tool": "fs_read", "path": "/tmp/*"},
                {"effect": "deny", "tool": "fs_write", "path": "/etc/*"},
            ]
        }
    )
    blob = json_io.policy_to_json(policy)
    # Canonical: sorted keys, stable across runs.
    assert blob == json_io.policy_to_json(policy)
    assert json.loads(blob)["rules"][0]["effect"] == "allow"
    restored = json_io.policy_from_json(blob)
    assert restored.rules == policy.rules


def test_policy_from_json_rejects_bad_rules():
    with pytest.raises(ValueError):
        json_io.policy_from_json('{"rules": [{"effect": "maybe"}]}')
    with pytest.raises(ValueError):
        json_io.policy_from_json("[1, 2, 3]")  # not an object
    with pytest.raises(ValueError):
        json_io.policy_from_json("not json at all")


def test_token_round_trip():
    cap = CapabilityToken(
        subject="agent-7",
        scopes=["tool:fs_read", "tool:fs_write:path=/tmp/*"],
        expires_at=2_000_000_000,
        token_id="abc123",
        issued_at=1_700_000_000,
    )
    blob = json_io.token_to_json(cap)
    restored = json_io.token_from_json(blob)
    assert restored == cap


def test_token_from_json_rejects_garbage():
    with pytest.raises(ValueError):
        json_io.token_from_json('{"subject": "x"}')  # missing fields


def test_token_payload_matches_signed_body():
    """The JSON payload shape here mirrors the signed token body fields."""
    token = mint(SECRET, "agent-9", ["tool:*"], ttl_seconds=600)
    cap = verify(SECRET, token)
    blob = json_io.token_to_json(cap)
    parsed = json.loads(blob)
    assert parsed["subject"] == "agent-9"
    assert parsed["scopes"] == ["tool:*"]
    assert parsed["token_id"]  # jti survived the round trip


def test_audit_entry_round_trip(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    entry = log.record(
        "fs_read", {"path": "/tmp/a.txt"}, True, "allowed",
        subject="agent-7", token_id="tok1",
    )
    blob = json_io.audit_entry_to_json(entry)
    restored = json_io.audit_entry_from_json(blob)
    assert restored == entry
    # Stable canonical encoding: identical bytes every time.
    assert json_io.audit_entry_to_json(restored) == blob


def test_audit_entry_from_json_validates():
    with pytest.raises(ValueError):
        json_io.audit_entry_from_json('{"tool": "x"}')  # missing fields
    bad = json.loads(json_io.audit_entry_to_json({
        "ts": 1, "tool": "t", "args": {}, "args_hash": "h",
        "decision": "allow", "reason": "r", "subject": "s", "token_id": "t",
    }))
    bad["decision"] = "maybe"
    with pytest.raises(ValueError):
        json_io.audit_entry_from_json(json.dumps(bad))


def test_decision_round_trip():
    engine = PolicyEngine(
        Policy.from_dict({"rules": [{"effect": "allow", "tool": "fs_read"}]}),
        SECRET,
    )
    token = mint(SECRET, "agent-7", ["tool:fs_read"])
    decision = engine.authorize("fs_read", {}, token)
    assert decision.allow
    restored = json_io.decision_from_json(json_io.decision_to_json(decision))
    assert restored.allow == decision.allow
    assert restored.reason == decision.reason
    assert restored.matched_rule == decision.matched_rule

"""Tests for GuardedHarness.run_task() — scripted tasks through the guard.

Every step of a task plan must go through policy-check + token-verify and
be audited, exactly like the live demo's harness-run skill.
"""

import pytest

from agentguard.audit import AuditLog
from agentguard.harness import GuardedHarness, ToolRegistry
from agentguard.policy import Policy, PolicyEngine
from agentguard.tokens import mint


@pytest.fixture
def harness(tmp_path):
    secret = b"test-harness-secret-32bytes!!!!"
    policy = Policy.from_dict({"rules": [{"effect": "allow", "tool": "echo"}]})
    engine = PolicyEngine(policy, secret)
    registry = ToolRegistry()
    registry.register("echo", lambda msg="": f"echo:{msg}")
    audit = AuditLog(tmp_path / "audit.jsonl")
    return GuardedHarness(engine, registry, audit), audit, secret


def _token(secret, scopes):
    return mint(secret, "tester", scopes, ttl_seconds=3600)


def test_run_task_transcript(harness):
    harness_obj, audit, secret = harness
    token = _token(secret, ["tool:echo"])
    plan = [
        {"tool": "echo", "args": {"msg": "hi"}},
        {"tool": "rm", "args": {"target": "/tmp/x"}},
    ]
    transcript = harness_obj.run_task(plan, token)
    assert len(transcript.steps) == 2
    assert transcript.allowed == 1
    assert transcript.denied == 1

    first = transcript.steps[0]
    assert first.allow is True
    assert first.output == "echo:hi"
    assert first.error == ""

    second = transcript.steps[1]
    assert second.allow is False
    assert "deny" in second.reason.lower() or "DENIED" in second.error

    # Every step was audited.
    entries = audit.read_all()
    assert len(entries) == 2
    assert [e["decision"] for e in entries] == ["allow", "deny"]


def test_run_task_bad_token_denies_everything(harness):
    harness_obj, audit, secret = harness
    transcript = harness_obj.run_task(
        [{"tool": "echo", "args": {"msg": "hi"}}], "bogus.token")
    assert transcript.allowed == 0
    assert transcript.denied == 1
    assert len(audit.read_all()) == 1


def test_run_task_scope_enforced(harness):
    harness_obj, audit, secret = harness
    # Token holds no scopes covering echo -> denied even though the
    # policy has an allow rule for it.
    token = _token(secret, ["tool:other"])
    transcript = harness_obj.run_task(
        [{"tool": "echo", "args": {"msg": "hi"}}], token)
    assert transcript.denied == 1
    assert "scopes" in transcript.steps[0].reason

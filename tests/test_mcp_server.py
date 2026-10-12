"""Exercise the MCP tool functions directly (same code Bob calls)."""

import asyncio
import json
import os

import pytest

os.environ.setdefault("AGENTGUARD_SECRET", "mcp-test-secret")

from agentguard import mcp_server  # noqa: E402
from agentguard.tokens import mint  # noqa: E402


@pytest.fixture()
def policy_file(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({
        "rules": [
            {"effect": "deny", "tool": "fs_write", "path": "/etc/*"},
            {"effect": "allow", "tool": "fs_write", "path": "/tmp/*"},
        ]
    }))
    return str(p)


def _call(tool_name, **kwargs):
    tool = next(t for t in mcp_server.mcp._tool_manager._tools.values()
                if t.name == tool_name)
    result = tool.fn(**kwargs)  # tools are sync; same function Bob invokes
    return asyncio.run(result) if asyncio.iscoroutine(result) else result


def test_mcp_check_policy_allows(policy_file):
    token = mint(b"mcp-test-secret", "bob", ["tool:fs_write:path=/tmp/*"])
    out = json.loads(_call("check_policy", policy_path=policy_file,
                           tool="fs_write", args_json='{"path": "/tmp/a"}',
                           token=token))
    assert out["allow"] is True


def test_mcp_check_policy_denies(policy_file):
    token = mint(b"mcp-test-secret", "bob", ["tool:fs_write:path=/etc/*"])
    out = json.loads(_call("check_policy", policy_path=policy_file,
                           tool="fs_write", args_json='{"path": "/etc/x"}',
                           token=token))
    assert out["allow"] is False


def test_mcp_scan_codebase(tmp_path):
    (tmp_path / "app.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"\n')
    out = json.loads(_call("scan_codebase", path=str(tmp_path)))
    assert out["files_scanned"] == 1
    assert out["secrets"][0]["kind"] == "aws_access_key"


def test_mcp_audit_summary(tmp_path):
    from agentguard.audit import AuditLog
    log = AuditLog(str(tmp_path / "a.jsonl"))
    log.record("t", {}, True, "ok")
    out = json.loads(_call("audit_summary", audit_path=str(tmp_path / "a.jsonl")))
    assert out == {"total": 1, "allowed": 1, "denied": 0}

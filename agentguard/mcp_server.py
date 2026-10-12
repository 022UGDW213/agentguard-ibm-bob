"""AgentGuard as an MCP server — the IBM Bob integration.

IBM Bob consumes MCP servers declared in ``.bob/mcp.json`` (project) or
``~/.bob/settings/mcp.json`` (global); see
https://bob.ibm.com/docs/ide/configuration/mcp/mcp-in-bob

This server exposes AgentGuard's guardrails as tools Bob can call inside its
own agentic workflow — e.g. Bob asks ``check_policy`` before running a shell
command, or runs ``scan_codebase`` after generating code.

Run over stdio (how Bob launches it)::

    python -m agentguard.mcp_server

Requires ``AGENTGUARD_SECRET`` in the environment for token verification.
"""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from .audit import AuditLog
from .policy import Policy, PolicyEngine
from .scanner import scan_all

mcp = FastMCP("agentguard")


def _secret() -> bytes:
    secret = os.environ.get("AGENTGUARD_SECRET", "")
    if not secret:
        raise RuntimeError("AGENTGUARD_SECRET env var is required")
    return secret.encode()


@mcp.tool()
def check_policy(policy_path: str, tool: str, args_json: str, token: str) -> str:
    """Dry-run an agent tool call against a policy file.

    policy_path: path to a JSON policy file (see agentguard/policy.py format).
    tool: tool name the agent wants to call, e.g. "fs_write".
    args_json: JSON object of the tool arguments, e.g. '{"path": "/tmp/x"}'.
    token: the agent's capability token string.
    Returns JSON: {"allow": bool, "reason": str}.
    """
    with open(policy_path, encoding="utf-8") as fh:
        policy = Policy.from_dict(json.load(fh))
    engine = PolicyEngine(policy, _secret())
    decision = engine.authorize(tool, json.loads(args_json or "{}"), token)
    return json.dumps({"allow": decision.allow, "reason": decision.reason})


@mcp.tool()
def scan_codebase(path: str) -> str:
    """Scan a codebase for leaked secrets and dependency vulnerabilities.

    path: directory to scan. Returns the JSON scan report (files scanned,
    secret findings, dependency-check results). Dependency checks shell out to
    real tooling (pip-audit / npm audit) when installed.
    """
    return json.dumps(scan_all(path).to_dict(), indent=2)


@mcp.tool()
def audit_summary(audit_path: str) -> str:
    """Summarize an AgentGuard audit log: total calls, allowed, denied."""
    return json.dumps(AuditLog(audit_path).summary(), indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

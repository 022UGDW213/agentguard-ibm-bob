# IBM Bob integration

AgentGuard integrates with IBM Bob in **two verified directions**. Both are
grounded in IBM's own documentation — nothing here is invented.

## What IBM Bob exposes (verified)

| Surface | What it is | Doc |
|---|---|---|
| Bob Shell CLI (`bob`) | Headless non-interactive runs, e.g. automation & CI | https://bob.ibm.com/docs/shell/getting-started/install-and-setup |
| API keys (General / Inference scopes) | Authenticate Bob Shell without browser sign-in; **available on trial plans** | https://bob.ibm.com/docs/ide/account/api-keys |
| MCP client | Bob connects to *your* MCP servers (project `.bob/mcp.json` or global `~/.bob/settings/mcp.json`), stdio or streamable-http | https://bob.ibm.com/docs/ide/configuration/mcp/mcp-in-bob |
| Bob IDE / web UI | Interactive use (VS Code extension, bob.ibm.com) | https://bob.ibm.com/docs |

**Honest limitation:** IBM publishes **no public REST API** for third-party
Bob inference. The programmatic path is the Bob Shell CLI. Any project
claiming a `api.bob.ibm.com/v1/...` endpoint is making it up — we don't.

## Direction 1 — Bob calls AgentGuard (primary)

This repo ships a real MCP server (`agentguard/mcp_server.py`, built on the
official `mcp` Python SDK) exposing three tools:

- `check_policy(policy_path, tool, args_json, token)` — authorize/deny an
  agent tool call against a policy, with the reason.
- `scan_codebase(path)` — secret + dependency-vulnerability scan of a repo.
- `audit_summary(audit_path)` — allow/deny totals from the audit ledger.

`.bob/mcp.json` in this repo wires it into Bob for any checkout of this
project: open the repo in Bob IDE and the `agentguard` server appears under
Settings → MCP. Ask Bob to "check the policy before running shell commands"
and it will call `check_policy` itself — guardrails *inside* Bob's workflow.

## Direction 2 — AgentGuard governs Bob (secondary)

`agentguard/backends.py` provides `BobShellBackend`, a `ModelBackend` that
drives Bob headlessly via subprocess:

```python
from agentguard.backends import BobShellBackend
bob = BobShellBackend()  # needs `bob` on PATH + BOBSHELL_API_KEY
print(bob.generate("Explain what this function does: ..."))
```

The harness can wrap any backend, so the same policy/audit choke point that
governs local tools also governs a Bob-powered agent loop.

## What Juan must do himself (human steps)

1. **Trial signup** (we can't do this for you): https://bob.ibm.com — sign
   in with / create an IBMid.
2. **Install Bob Shell**: https://bob.ibm.com/docs/shell/getting-started/install-and-setup
   then `bob --version` to verify.
3. **Create an API key** (Inference scope is enough):
   https://bob.ibm.com/docs/ide/account/api-keys — copy it once, then
   `export BOBSHELL_API_KEY="<key>"` and `export AGENTGUARD_SECRET="<random>"`.
4. **Connect the MCP server**: open this repo in Bob IDE → Settings → MCP →
   confirm `agentguard` is connected (or point Bob at `.bob/mcp.json`).

Without steps 1–3, `BobShellBackend` raises `BackendUnavailable` with
instructions instead of failing silently — by design, never a fake success.

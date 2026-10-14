# AgentGuard — model-agnostic security harness for AI agents

**Team CodeBase Loops · AngelHack "Building with IBM Bob" hackathon**

AgentGuard fixes the **confused-deputy problem** for AI agents: every tool
call an agent attempts passes through a deny-by-default policy engine that
only honors **capability tokens** — HMAC-signed, narrowly-scoped, expiring
credentials bound to the agent. No token, no scope, no call. Every decision
(allow or deny) is written to an append-only audit ledger.

It also ships a **secure-codebase scanner** (secret patterns + real
`pip-audit` / `npm audit` dependency checks) and a **two-way IBM Bob
integration**: Bob consumes AgentGuard as an MCP server, and AgentGuard can
govern a Bob-powered agent loop through the Bob Shell CLI.

No mocks. No stubs. No Llama anywhere. Every component below runs for real.

## Quickstart

```bash
pip install -r requirements.txt
export AGENTGUARD_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# 1. See the confused-deputy fix end to end
python3 -m agentguard.cli demo

# 2. Scan a codebase for leaked secrets and vulnerable dependencies
python3 -m agentguard.cli scan /path/to/repo

# 3. Mint a capability token and dry-run a tool call against a policy
python3 -m agentguard.cli token --subject my-agent --scope "tool:fs_read:path=/tmp/*"
python3 -m agentguard.cli check --policy examples/policy.json --tool fs_read \
    --arg path=/tmp/x --token <token>
```

## Layout

```
agentguard/
  policy.py      deny-by-default engine (allow/deny rules, token-scope checks)
  tokens.py      HMAC-SHA256 capability tokens (mint/verify, expiry)
  audit.py       append-only JSONL audit ledger
  harness.py     GuardedHarness — the tool-call choke point + sandboxed fs tools
  scanner.py     secret scan + real pip-audit / npm audit dependency checks
  backends.py    ModelBackend interface + BobShellBackend (drives IBM Bob CLI)
  mcp_server.py  AgentGuard as an MCP server for IBM Bob (check_policy,
                 scan_codebase, audit_summary)
  cli.py         CLI: demo | scan | check | token
.bob/mcp.json    project MCP config so Bob picks up the server automatically
docs/bob-integration.md   verified Bob integration surfaces + human setup steps
tests/           pytest suite (62 tests; 1 live-Bob test skips without a key)
Dockerfile       container image
```

## Testing

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -v
```

Expected: **62 passed, 1 skipped**. The skipped test needs a real Bob Shell
install + `BOBSHELL_API_KEY` (see below); it never fakes a result.

## IBM Bob integration

Full detail: [`docs/bob-integration.md`](docs/bob-integration.md).

**Direction 1 — Bob calls AgentGuard (primary).** Run the MCP server and
point Bob at it:

```bash
pip install "mcp<2"
export AGENTGUARD_SECRET="<secret>"
python -m agentguard.mcp_server        # stdio; Bob launches this itself
```

`.bob/mcp.json` is already in this repo — open the repo in Bob IDE and the
`agentguard` server connects automatically (Settings → MCP).

**Direction 2 — AgentGuard governs Bob.** Install Bob Shell and create an
API key (Inference scope is enough), all at https://bob.ibm.com:

```bash
# https://bob.ibm.com/docs/shell/getting-started/install-and-setup
export BOBSHELL_API_KEY="<key from https://bob.ibm.com/docs/ide/account/api-keys>"
python3 -c "
from agentguard.backends import BobShellBackend
print(BobShellBackend().generate('Say hi in five words or less.'))"
```

Honest note: IBM publishes **no public REST API** for Bob inference — the
programmatic path is the Bob Shell CLI. `BobShellBackend` raises
`BackendUnavailable` with setup instructions when `bob` or the key is
missing, instead of pretending to work.

## Policy format

```json
{"rules": [
  {"effect": "deny",  "tool": "fs_write", "path": "/etc/*"},
  {"effect": "allow", "tool": "fs_*",     "path": "/tmp/*"}
]}
```

Deny rules win over allow rules; anything unmatched is denied. Token scopes
use `tool:<name>` with optional `:path=<glob>` / `:host=<glob>` constraints.

## Docker

```bash
docker build -t agentguard .
docker run -e AGENTGUARD_SECRET=<secret> agentguard demo
```

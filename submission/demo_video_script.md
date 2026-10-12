# AgentGuard — Demo Video Script (≤ 3:00)
**Team CodeBase Loops · AngelHack "Building with IBM Bob"**

Total narration target: ~400 words (≈2:50 at 140 wpm). Record screen + voiceover; unlisted YouTube link for submission.

---

## 0:00–0:20 — HOOK
**On screen:** Title card: "AgentGuard — guardrails for AI agents" + team name.
**Narration:**
"AI agents act. They read files, run commands, call APIs — with your credentials. But nothing checks whether they're actually allowed to. One confused agent can leak your secrets or wreck your system. I'm Juan Serrano, team CodeBase Loops, and I built the checkpoint every agent tool call must pass. This is AgentGuard."

## 0:20–0:50 — THE PROBLEM
**On screen:** Terminal showing an agent attempting `read_file /etc/passwd`.
**Narration:**
"This is the confused-deputy problem. An agent tricked by a malicious prompt, a poisoned tool description, or a compromised plugin will happily read your system files — as you. Traditional security tooling was built for humans, not for software acting at machine speed. AgentGuard answers with three things: a deny-by-default policy engine, HMAC-signed capability tokens, and an append-only audit ledger."

## 0:50–1:40 — LIVE DEMO: ALLOW AND DENY
**On screen:** Live demo at agentguard.o22ugdw213.network. Run each case.
**Narration:**
"Live demo. First, a legitimate call — reading a project file with a valid capability token. Allowed. Now the attack: read /etc/passwd. Denied — the path escapes the sandbox. A traversal trick with dot-dot-slash. Denied. A tool the policy never heard of. Denied by default. Notice the pattern: deny rules beat allow rules, and anything unmatched dies. Every attempt — allow or deny — lands in the audit ledger below, with the reason. Tokens are HMAC-signed, scoped to a single tool and path, and they expire — steal one and it's useless outside its narrow job. That ledger is the whole product: proof of what your agents tried to do."

## 1:40–2:05 — SECRET SCANNING
**On screen:** The scan_text form; paste text containing a fake AWS key.
**Narration:**
"Agents also leak secrets. Paste text containing an AWS key into the scanner — flagged on the spot, using real detection patterns. And the repo scanner goes further, running live pip-audit and npm audit checks against your actual dependencies. No stubs, no simulated findings."

## 2:05–2:35 — IBM BOB INTEGRATION
**On screen:** Code view of mcp_server.py and .bob/mcp.json; Bob IDE MCP settings if available.
**Narration:**
"Built with IBM Bob, in two directions. First, Bob consumes AgentGuard as an MCP server — check policy, scan codebases, summarize audits — auto-wired into Bob IDE through .bob/mcp.json, so the guardrails live inside Bob's own workflow. Second, AgentGuard governs Bob-driven agent loops through the Bob Shell CLI. And an honest note: IBM publishes no public REST API for Bob, so we built on the verified surfaces — CLI and MCP — instead of inventing endpoints."

## 2:35–3:00 — CLOSE
**On screen:** Test run output (28 passed), repo URL, demo URL.
**Narration:**
"Twenty-eight tests pass, it's Dockerized, and every component runs for real. For the judges: the MCP server is the depth-of-Bob-adoption play, and the policy engine is one choke point you can audit. Agents are already acting in production today — yours should have guardrails. Code and docs at github.com/022UGDW213/agentguard-ibm-bob. Team CodeBase Loops. Thanks for watching."

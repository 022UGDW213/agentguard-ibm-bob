# AgentGuard — Pitch Deck Outline
**Team CodeBase Loops · AngelHack "Building with IBM Bob" · Solo: Juan Serrano**

Target: 10 slides. Speaker notes under each slide.

---

## Slide 1 — Title
**AgentGuard: guardrails for AI agents, enforced by default**
Team CodeBase Loops · Built with IBM Bob · github.com/022UGDW213/agentguard-ibm-bob
- *Notes: One breath. "AI agents act — they call tools, move files, hit APIs. Nobody checks whether they're allowed to. AgentGuard is the checkpoint every agent tool call must pass."*

## Slide 2 — The problem: the confused deputy
Agents are the new attack surface. An agent tricked by a malicious prompt, a poisoned tool description, or a compromised plugin will happily read /etc/passwd or exfiltrate keys — with *your* credentials. Red-team/blue-team tooling was built for humans, not for software acting at machine speed.
- *Notes: Make it visceral. "Your agent is a deputy with your keys. Anyone who confuses it becomes you." Cite the demo moment coming in slide 6.*

## Slide 3 — The solution: deny by default
AgentGuard puts a policy engine in front of every tool call. Rules are explicit; anything unmatched is denied. Authorization travels as HMAC-signed, narrowly-scoped, expiring capability tokens bound to the agent — no token, no scope, no call. Every decision lands in an append-only audit ledger.
- *Notes: Three pillars, one line each: deny-by-default policy, capability tokens, audit ledger. "This is the confused-deputy fix, and it works with any model."*

## Slide 4 — Model-agnostic by design
The harness wraps a `ModelBackend` interface — the same choke point governs local tools, a Bob-driven loop, or any future model. Plus a secure-codebase scanner: secret-pattern detection plus live `pip-audit` / `npm audit` dependency checks.
- *Notes: "We don't care which model you use. The guardrail is the same." This is the startup thesis, not just a hackathon trick.*

## Slide 5 — IBM Bob integration (two directions)
**Bob → AgentGuard (primary):** a real MCP server (`check_policy`, `scan_codebase`, `audit_summary`) built on the official MCP SDK; `.bob/mcp.json` auto-wires it into Bob IDE — guardrails *inside* Bob's own workflow.
**AgentGuard → Bob:** `BobShellBackend` drives Bob headlessly via the Bob Shell CLI, so a Bob-powered agent loop is governed by the same policy engine.
Honest note: IBM publishes no public REST API for Bob — CLI + MCP are the verified surfaces, and we built on exactly those.
- *Notes: This is the 30% "depth of Bob adoption" slide. Stress verified surfaces: "We read the docs. We didn't invent endpoints."*

## Slide 6 — Live demo
agentguard.o22ugdw213.network — try it: an allowed file read succeeds; `read_file /etc/passwd` is **denied** on screen with the reason; pasting an AWS key into the scanner gets flagged; the audit log records all of it.
- *Notes: Don't narrate over the demo — let the DENY land. "That denial is the whole product."*

## Slide 7 — Architecture
One diagram: Agent → GuardedHarness (policy engine + token verifier) → Tools / Bob backend; sidecar: audit ledger + scanner. Deny rules beat allow rules; unmatched calls die.
- *Notes: Walk the diagram in 20 seconds. Point at the harness: "One choke point. That's the entire security model."*

## Slide 8 — It actually works: tests
28 tests pass, 1 skipped (the live-Bob test skips cleanly without a key — it never fakes a result). CLI verified end to end: allowed calls succeed, `/etc/passwd` denied, audit shows 2 allow / 1 deny. Dockerized. No mocks, no stubs.
- *Notes: "A security tool you can't test is a rumor. Ours has 28 passing tests."*

## Slide 9 — What's next
Ship the audit ledger to tamper-evident storage, add per-team policy packs, a hosted policy API, and deeper Bob IDE workflows (pre-tool-call hooks). Long-term: the all-in-one agent security platform — beyond red-team/blue-team.
- *Notes: Show this is a beginning. Tie back to the startup: "The hackathon project is the first module of the company."*

## Slide 10 — Ask
Team CodeBase Loops · Juan Serrano · github.com/022UGDW213/agentguard-ibm-bob · Live demo: agentguard.o22ugdw213.network
"Agents are acting in production today. Give them guardrails."
- *Notes: End on the line. Contact + repo + demo on screen. Stop talking.*

"""AgentGuard CLI.

Commands:
  scan <path>            Scan a codebase for secrets and dependency vulns.
  check --policy P --tool T [--arg k=v ...] --token TOK
                         Evaluate one tool call against a policy (dry run).
  token --subject S --scope SCOPE... [--ttl SECONDS]
                         Mint a capability token (needs AGENTGUARD_SECRET env).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .audit import AuditLog
from .harness import GuardedHarness, make_filesystem_tools
from .policy import Policy, PolicyEngine
from .scanner import scan_all
from .tokens import mint


def _secret() -> bytes:
    secret = os.environ.get("AGENTGUARD_SECRET", "")
    if not secret:
        print("error: AGENTGUARD_SECRET env var is required", file=sys.stderr)
        sys.exit(2)
    return secret.encode()


def cmd_scan(args: argparse.Namespace) -> int:
    report = scan_all(args.path)
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if not report.secrets else 1


def cmd_check(args: argparse.Namespace) -> int:
    with open(args.policy, encoding="utf-8") as fh:
        policy = Policy.from_dict(json.load(fh))
    call_args = dict(kv.split("=", 1) for kv in args.arg)
    engine = PolicyEngine(policy, _secret())
    decision = engine.authorize(args.tool, call_args, args.token)
    print(json.dumps(
        {"allow": decision.allow, "reason": decision.reason}, indent=2
    ))
    return 0 if decision.allow else 1


def cmd_token(args: argparse.Namespace) -> int:
    token = mint(_secret(), args.subject, args.scope, ttl_seconds=args.ttl)
    print(token)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """End-to-end guarded run against a temp sandbox: proves the choke point."""
    import tempfile

    secret = _secret()
    policy = Policy.from_dict({
        "rules": [
            {"effect": "deny", "tool": "fs_read", "path": "/etc/*"},
            {"effect": "allow", "tool": "fs_*", "path": "/tmp/*"},
        ]
    })
    engine = PolicyEngine(policy, secret)
    with tempfile.TemporaryDirectory() as tmp:
        registry = make_filesystem_tools([tmp])
        audit = AuditLog(os.path.join(tmp, "audit.jsonl"))
        harness = GuardedHarness(engine, registry, audit)
        good_token = mint(secret, "demo-agent", ["tool:fs_write:path=/tmp/*",
                                                 "tool:fs_read:path=/tmp/*"])
        evil_token = mint(secret, "demo-agent", ["tool:fs_read:path=/tmp/*"])

        target = os.path.join(tmp, "note.txt")
        r1 = harness.tool_call("fs_write", {"path": target, "content": "hello"},
                               good_token)
        r2 = harness.tool_call("fs_read", {"path": target}, good_token)
        # Confused deputy attempt: token only covers /tmp/*, asking for /etc/*
        r3 = harness.tool_call("fs_read", {"path": "/etc/passwd"}, evil_token)
        audit_summary = audit.summary()

    print(json.dumps({
        "write_allowed": r1.ok,
        "read_allowed": r2.ok,
        "read_output": r2.output,
        "etc_passwd_denied": not r3.ok,
        "deny_reason": r3.error,
        "audit_summary": audit_summary,
    }, indent=2))
    return 0 if (r1.ok and r2.ok and not r3.ok) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard",
                                     description="Model-agnostic security harness for AI agents")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan a codebase for secrets and vulns")
    p.add_argument("path")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("check", help="dry-run one tool call against a policy")
    p.add_argument("--policy", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--arg", action="append", default=[], metavar="k=v")
    p.add_argument("--token", required=True)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("token", help="mint a capability token")
    p.add_argument("--subject", required=True)
    p.add_argument("--scope", action="append", default=[])
    p.add_argument("--ttl", type=int, default=3600)
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("demo", help="run the guarded end-to-end demo")
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

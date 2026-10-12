"""Deny-by-default policy engine for agent tool calls.

The engine answers one question: given a tool name, its arguments, and the
capability token presented, is this call authorized?

Evaluation order:
  1. The token must verify and not be expired.
  2. Explicit DENY rules are checked first (deny always wins).
  3. ALLOW rules are checked next. A call is allowed only if an allow rule
     matches AND the token carries a scope covering the tool.
  4. Anything else is denied (deny by default).

Scope syntax (token scopes):
    "tool:<name>"                 — the tool at all
    "tool:<name>:path=<glob>"     — the tool, restricted to a path argument
    "tool:<name>:host=<glob>"     — the tool, restricted to a host argument
    "tool:*"                      — every tool (use sparingly)

Policy rules are plain dicts, loadable from JSON/YAML:
    {"effect": "allow", "tool": "fs_read", "path": "/tmp/*"}
    {"effect": "deny",  "tool": "fs_write", "path": "/etc/*"}
    {"effect": "allow", "tool": "http_get", "host": "api.internal.example"}
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from . import tokens as _tokens


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    matched_rule: dict | None = None


@dataclass
class Policy:
    rules: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = data.get("rules", [])
        for rule in rules:
            if rule.get("effect") not in ("allow", "deny"):
                raise ValueError(f"rule has bad effect: {rule!r}")
            if "tool" not in rule:
                raise ValueError(f"rule missing 'tool': {rule!r}")
        return cls(rules=list(rules))


def _rule_matches(rule: dict, tool: str, args: dict) -> bool:
    if not fnmatch.fnmatchcase(tool, rule["tool"]):
        return False
    for key in ("path", "host"):
        if key in rule:
            value = str(args.get(key, ""))
            if not fnmatch.fnmatchcase(value, rule[key]):
                return False
    return True


def _scope_covers(scopes: list[str], tool: str, args: dict) -> bool:
    for scope in scopes:
        parts = scope.split(":")
        if len(parts) < 2 or parts[0] != "tool":
            continue
        if not fnmatch.fnmatchcase(tool, parts[1]):
            continue
        ok = True
        for constraint in parts[2:]:
            if "=" not in constraint:
                ok = False
                break
            key, pattern = constraint.split("=", 1)
            if not fnmatch.fnmatchcase(str(args.get(key, "")), pattern):
                ok = False
                break
        if ok:
            return True
    return False


class PolicyEngine:
    """Evaluates tool calls against a Policy plus a capability token."""

    def __init__(self, policy: Policy, secret: bytes):
        self.policy = policy
        self.secret = secret

    def authorize(self, tool: str, args: dict, token: str) -> Decision:
        try:
            cap = _tokens.verify(self.secret, token)
        except _tokens.TokenError as exc:
            return Decision(False, f"token rejected: {exc}")

        for rule in self.policy.rules:
            if rule["effect"] == "deny" and _rule_matches(rule, tool, args):
                return Decision(False, f"denied by rule: {rule}", matched_rule=rule)

        allowed_by_rule = any(
            rule["effect"] == "allow" and _rule_matches(rule, tool, args)
            for rule in self.policy.rules
        )
        if not allowed_by_rule:
            return Decision(False, "no allow rule matched (deny by default)")

        if not _scope_covers(cap.scopes, tool, args):
            return Decision(
                False,
                f"token scopes {cap.scopes} do not cover {tool} with args {args}",
            )

        return Decision(True, f"allowed: token {cap.token_id} covers {tool}")

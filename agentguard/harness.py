"""The guarded harness: every agent tool call goes through here.

`GuardedHarness.tool_call()` is the confused-deputy choke point. An agent
(or a model backend driving an agent loop) never touches a tool directly —
it asks the harness, which authorizes via the policy engine, executes only on
allow, and audits every decision.

`GuardedHarness.run_task()` executes a scripted task plan through the same
pipeline: each step goes through policy-check (engine.authorize) plus
token-verify, then executes through `tool_call`, which audits the decision.
The returned TaskTranscript is the demo agent's full run record.

Tools are real callables registered in a ToolRegistry. Two filesystem tools
ship built in, sandboxed to directories you configure; anything else an agent
needs (HTTP, shell, database) is registered by the embedding application with
its own policy rules.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import tokens as _tokens
from .audit import AuditLog
from .policy import Decision, PolicyEngine


@dataclass
class TaskStepResult:
    """One step of a scripted task: the decision and what happened."""

    tool: str
    args: dict
    allow: bool
    reason: str
    output: object = None
    error: str = ""


@dataclass
class TaskTranscript:
    """The full record of a scripted task run through the guard."""

    steps: list[TaskStepResult] = field(default_factory=list)

    @property
    def allowed(self) -> int:
        return sum(1 for s in self.steps if s.allow)

    @property
    def denied(self) -> int:
        return sum(1 for s in self.steps if not s.allow)


@dataclass
class ToolResult:
    ok: bool
    output: object = None
    error: str = ""


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Callable[..., object]] = {}

    def register(self, name: str, func: Callable[..., object]) -> None:
        self._tools[name] = func

    def get(self, name: str) -> Callable[..., object] | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)


def _inside(path: str, roots: list[str]) -> str | None:
    """Return the resolved path if it stays inside one of roots, else None."""
    resolved = str(Path(path).resolve())
    for root in roots:
        r = str(Path(root).resolve())
        if resolved == r or resolved.startswith(r + "/"):
            return resolved
    return None


def make_filesystem_tools(allowed_roots: list[str]) -> ToolRegistry:
    """Real filesystem tools, sandboxed to allowed_roots (path traversal safe)."""
    reg = ToolRegistry()

    def fs_read(path: str) -> str:
        safe = _inside(path, allowed_roots)
        if safe is None:
            raise PermissionError(f"path outside allowed roots: {path}")
        return Path(safe).read_text(encoding="utf-8", errors="replace")

    def fs_write(path: str, content: str) -> str:
        safe = _inside(path, allowed_roots)
        if safe is None:
            raise PermissionError(f"path outside allowed roots: {path}")
        p = Path(safe)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes to {safe}"

    def fs_list(path: str) -> list[str]:
        safe = _inside(path, allowed_roots)
        if safe is None:
            raise PermissionError(f"path outside allowed roots: {path}")
        return sorted(p.name for p in Path(safe).iterdir())

    reg.register("fs_read", fs_read)
    reg.register("fs_write", fs_write)
    reg.register("fs_list", fs_list)
    return reg


class GuardedHarness:
    """Wraps a ToolRegistry with policy authorization and auditing."""

    def __init__(self, engine: PolicyEngine, registry: ToolRegistry, audit: AuditLog):
        self.engine = engine
        self.registry = registry
        self.audit = audit

    def tool_call(self, tool: str, args: dict, token: str) -> ToolResult:
        decision: Decision = self.engine.authorize(tool, args, token)

        subject = token_id = ""
        try:
            cap = _tokens.verify(self.engine.secret, token)
            subject, token_id = cap.subject, cap.token_id
        except _tokens.TokenError:
            pass

        self.audit.record(
            tool=tool,
            args=args,
            allow=decision.allow,
            reason=decision.reason,
            subject=subject,
            token_id=token_id,
        )

        if not decision.allow:
            return ToolResult(ok=False, error=f"DENIED: {decision.reason}")

        func = self.registry.get(tool)
        if func is None:
            return ToolResult(ok=False, error=f"DENIED: unknown tool '{tool}'")

        try:
            return ToolResult(ok=True, output=func(**args))
        except TypeError as exc:
            return ToolResult(ok=False, error=f"tool argument error: {exc}")
        except Exception as exc:  # noqa: BLE001 — tool failures are reported, not raised
            return ToolResult(ok=False, error=f"tool failed: {exc}")

    def tools_matching(self, pattern: str) -> list[str]:
        return [n for n in self.registry.names() if fnmatch.fnmatchcase(n, pattern)]

    def run_task(self, plan: list[dict], token: str) -> TaskTranscript:
        """Execute a scripted task plan through the guard's skill pipeline.

        Each plan step is a {"tool": ..., "args": {...}} dict. Every step
        goes through policy-check (engine.authorize) and token-verify, then
        executes via tool_call(), which audits the decision. Nothing
        bypasses the choke point.
        """
        transcript = TaskTranscript()
        for step in plan:
            tool = step.get("tool", "")
            args = dict(step.get("args", {}))
            # Policy-check + token-verify: pure decision, no side effects.
            decision: Decision = self.engine.authorize(tool, args, token)
            # Guarded execution: audits the decision, runs only on allow.
            result = self.tool_call(tool, args, token)
            transcript.steps.append(TaskStepResult(
                tool=tool,
                args=args,
                allow=result.ok,
                reason=decision.reason,
                output=result.output,
                error=result.error,
            ))
        return transcript

"""Append-only JSONL audit log of every tool-call decision.

Every call the harness evaluates — allowed or denied — is recorded with a
timestamp, the tool, a hash of the arguments (arguments themselves are stored
too, so reviewers can replay exactly what was attempted), the decision, the
reason, and the token subject. The log is append-only: there is no API to
modify or delete entries.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


def _args_hash(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        tool: str,
        args: dict,
        allow: bool,
        reason: str,
        subject: str = "",
        token_id: str = "",
    ) -> dict:
        entry = {
            "ts": int(time.time()),
            "tool": tool,
            "args": args,
            "args_hash": _args_hash(args),
            "decision": "allow" if allow else "deny",
            "reason": reason,
            "subject": subject,
            "token_id": token_id,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return entry

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def summary(self) -> dict:
        entries = self.read_all()
        return {
            "total": len(entries),
            "allowed": sum(1 for e in entries if e["decision"] == "allow"),
            "denied": sum(1 for e in entries if e["decision"] == "deny"),
        }

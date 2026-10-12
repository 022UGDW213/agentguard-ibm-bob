"""Secure-codebase scanning: real checks, no stubs.

- Secret scanning: well-known credential patterns over file contents.
- Dependency vulnerabilities: shells out to the real `pip-audit` (for
  requirements.txt) and `npm audit` (for package-lock.json) when those tools
  are installed. If a tool is missing, the report says so honestly instead of
  pretending to scan.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("generic_password_assign", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]")),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz"}


@dataclass
class SecretFinding:
    file: str
    line: int
    kind: str


@dataclass
class ScanReport:
    root: str
    files_scanned: int = 0
    secrets: list[SecretFinding] = field(default_factory=list)
    dependency_checks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "secrets": [vars(s) for s in self.secrets],
            "dependency_checks": self.dependency_checks,
        }


def scan_secrets(root: str | Path) -> tuple[int, list[SecretFinding]]:
    root = Path(root)
    findings: list[SecretFinding] = []
    files_scanned = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeError):
            continue
        files_scanned += 1
        for i, line in enumerate(text.splitlines(), 1):
            for kind, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(SecretFinding(str(path), i, kind))
                    break
    return files_scanned, findings


def _run(cmd: list[str], cwd: str) -> tuple[bool, str, str]:
    """Run a command; returns (ran, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=300
        )
    except FileNotFoundError:
        return False, "", "tool not installed"
    except subprocess.TimeoutExpired:
        return False, "", "tool timed out"
    return True, proc.stdout, proc.stderr


def check_python_deps(root: str | Path) -> dict:
    """Run real `pip-audit` against requirements.txt if present."""
    root = Path(root)
    req = root / "requirements.txt"
    if not req.exists():
        return {"ecosystem": "pip", "status": "skipped", "detail": "no requirements.txt"}
    if shutil.which("pip-audit") is None:
        return {
            "ecosystem": "pip",
            "status": "tool-not-installed",
            "detail": "pip-audit is not installed; run: pip install pip-audit",
        }
    ran, out, err = _run(["pip-audit", "-r", "requirements.txt", "-f", "json"], str(root))
    if not ran:
        return {"ecosystem": "pip", "status": "error", "detail": err}
    try:
        parsed = json.loads(out or "{}")
    except json.JSONDecodeError:
        return {"ecosystem": "pip", "status": "error", "detail": "unparseable pip-audit output"}
    # pip-audit >= 2.7 wraps results: {"dependencies": [...], "fixes": [...]}
    vulns = parsed.get("dependencies", parsed) if isinstance(parsed, dict) else parsed
    if not isinstance(vulns, list):
        return {"ecosystem": "pip", "status": "error", "detail": "unparseable pip-audit output"}
    return {
        "ecosystem": "pip",
        "status": "ok",
        "vulnerabilities": [
            {
                "package": v.get("name"),
                "version": v.get("version"),
                "vuln_id": (v.get("vulns") or [{}])[0].get("id"),
                "fix": (v.get("vulns") or [{}])[0].get("fix_versions"),
            }
            for v in vulns
        ],
    }


def check_npm_deps(root: str | Path) -> dict:
    """Run real `npm audit` against package-lock.json if present."""
    root = Path(root)
    if not (root / "package-lock.json").exists():
        return {"ecosystem": "npm", "status": "skipped", "detail": "no package-lock.json"}
    if shutil.which("npm") is None:
        return {"ecosystem": "npm", "status": "tool-not-installed",
                "detail": "npm is not installed"}
    ran, out, err = _run(["npm", "audit", "--json"], str(root))
    if not ran:
        return {"ecosystem": "npm", "status": "error", "detail": err}
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return {"ecosystem": "npm", "status": "error", "detail": "unparseable npm audit output"}
    advisories = data.get("advisories", {})
    vulns = data.get("vulnerabilities", {})
    return {
        "ecosystem": "npm",
        "status": "ok",
        "summary": data.get("metadata", {}).get("vulnerabilities"),
        "advisory_count": len(advisories) if advisories else len(vulns),
    }


def scan_all(root: str | Path) -> ScanReport:
    report = ScanReport(root=str(root))
    report.files_scanned, report.secrets = scan_secrets(root)
    report.dependency_checks = [check_python_deps(root), check_npm_deps(root)]
    return report

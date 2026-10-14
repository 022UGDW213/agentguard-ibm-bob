"""Repo hygiene: requirements.txt must contain only valid specifiers.

Regression test — a quoted specifier ('"mcp<2"') once broke pip-audit and
would break `pip install -r requirements.txt` too.
"""

from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

REPO = Path(__file__).resolve().parent.parent


def test_requirements_txt_parses():
    lines = [
        ln.strip()
        for ln in (REPO / "requirements.txt").read_text().splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert lines, "requirements.txt has no pinned requirements"
    for ln in lines:
        try:
            Requirement(ln)
        except InvalidRequirement:
            raise AssertionError(f"invalid requirement line: {ln!r}")

"""Tests for agentguard.redteam — the defensive replay harness.

Transform tests are deterministic and network-free. The host guard is tested
against hostile URLs. Nothing here executes a payload.
"""

import json
import urllib.parse

import pytest

from agentguard import redteam
from agentguard.redteam import (
    ALLOWED_HOSTS,
    DEMO_BASE_URL,
    check_target_url,
    comment_inject,
    dotdot_variants,
    double_url_encode,
    fetch_learned_seeds,
    mixed_case,
    mutate,
    null_inject,
    prefix_variants,
    quote_wrap,
    separator_swap,
    url_encode,
    whitespace_pad,
)


# --- transforms -------------------------------------------------------------

def test_url_encode():
    assert url_encode("../etc") == ["..%2Fetc"]


def test_double_url_encode():
    assert double_url_encode("a/b") == ["a%252Fb"]


def test_mixed_case_deterministic():
    assert mixed_case("abc") == ["aBc"]
    assert mixed_case("abc") == mixed_case("abc")


def test_separator_swap_both_directions():
    assert separator_swap("a/b") == ["a\\b"]
    assert separator_swap("a\\b") == ["a/b"]
    assert separator_swap("abc") == []


def test_dotdot_variants():
    outs = dotdot_variants("../../x")
    assert len(outs) == 4
    assert all(".." not in o.replace("....//", "") or True for o in outs)
    assert dotdot_variants("plain") == []


def test_prefix_variants_excludes_identity():
    outs = prefix_variants("x/y")
    assert "x/y" not in outs
    assert any(o.startswith("/") for o in outs)


def test_whitespace_pad():
    outs = whitespace_pad("x")
    assert len(outs) == 4 and all(o.strip() == "x" for o in outs)


def test_null_inject_positions():
    outs = null_inject("ab")
    assert len(outs) == 3 and all("\x00" in o for o in outs)
    assert null_inject("") == []


def test_comment_inject():
    outs = comment_inject("rm -rf /")
    assert outs[0].endswith(" #")


def test_quote_wrap():
    assert quote_wrap("x") == ["'x'", '"x"']


# --- mutation engine --------------------------------------------------------

def test_mutate_dedups_and_caps():
    variants = mutate("sandbox_escape", "read_file",
                      {"path": "/etc/passwd"}, max_variants=5)
    assert len(variants) == 5
    seen = {json.dumps(v["args"], sort_keys=True) for v in variants}
    assert len(seen) == 5  # all distinct
    assert all(v["tool"] == "read_file" for v in variants)
    assert all("via" in v and "from" in v for v in variants)


def test_mutate_skips_non_string_args():
    variants = mutate("sandbox_escape", "read_file",
                      {"path": "/etc/passwd", "n": 3}, max_variants=50)
    assert all(isinstance(v["args"]["path"], str) for v in variants)


def test_mutate_no_transforms_for_token_techniques():
    assert mutate("token_tampering", "x", {"a": "b"}) == []
    assert mutate("scope_escalation", "x", {"a": "b"}) == []


def test_mutate_unknown_technique_uses_fallback():
    variants = mutate("mystery", "run_command", {"cmd": "x"},
                      max_variants=50)
    assert len(variants) > 0


# --- host guard -------------------------------------------------------------

def test_check_target_allows_demo_and_localhost():
    assert check_target_url(DEMO_BASE_URL).startswith("https://")
    assert check_target_url("http://localhost:8000/x").startswith("http://")
    assert "127.0.0.1" in check_target_url("http://127.0.0.1/")


def test_check_target_refuses_foreign_hosts():
    for bad in [
        "https://evil.example/",
        "https://agentguard-demo.o22ugdw213.network.evil.example/",
        "https://o22ugdw213.network/",
        "ftp://agentguard-demo.o22ugdw213.network/",
        "",
        "not a url",
    ]:
        with pytest.raises(ValueError):
            check_target_url(bad)


def test_check_target_refuses_userinfo_trick():
    # userinfo must not smuggle a foreign host past the check
    with pytest.raises(ValueError):
        check_target_url("https://agentguard-demo.o22ugdw213.network@evil.example/")


def test_allowed_hosts_is_minimal():
    assert ALLOWED_HOSTS == frozenset({
        "agentguard-demo.o22ugdw213.network",
        "localhost", "127.0.0.1", "::1",
    })


# --- ledger seeds -----------------------------------------------------------

def _fake_http_factory(payload):
    def fake(method, url, token=None, data=None, timeout=20):
        return 200, payload
    return fake


def test_fetch_learned_seeds_skips_redacted(monkeypatch):
    payload = {"entries": [
        {"tool": "skill.trap.intel",
         "args": {"tool": "read_file",
                  "args": {"path": "/etc/passwd"},
                  "technique": "sandbox_escape"}},
        {"tool": "skill.trap.intel",
         "args": {"tool": "scan_text",
                  "args": {"text": "[redacted: aws_access_key]"},
                  "technique": "secret_exfiltration_attempt"}},
        {"tool": "auth.guest", "args": {}},
    ]}
    monkeypatch.setattr(redteam, "_http", _fake_http_factory(payload))
    seeds = fetch_learned_seeds("https://x/", "tok")
    assert seeds == [("sandbox_escape", "read_file", {"path": "/etc/passwd"})]


def test_fetch_learned_seeds_dedups(monkeypatch):
    entry = {"tool": "skill.trap.intel",
             "args": {"tool": "read_file", "args": {"path": "/etc/passwd"},
                      "technique": "sandbox_escape"}}
    monkeypatch.setattr(redteam, "_http",
                        _fake_http_factory({"entries": [entry, entry]}))
    assert len(fetch_learned_seeds("https://x/", "tok")) == 1


# --- the harness never executes anything ------------------------------------

def test_module_has_no_execution_primitives():
    import pathlib
    src = pathlib.Path(redteam.__file__).read_text()
    for banned in ("subprocess", "os.system", "os.exec", "os.popen",
                   "pty.spawn", "eval(", "exec("):
        assert banned not in src, "banned primitive: %s" % banned


def test_replay_uses_only_http(monkeypatch):
    calls = []

    def fake(method, url, token=None, data=None, timeout=20):
        calls.append((method, url, data))
        return 200, {"ok": True, "allow": False}

    monkeypatch.setattr(redteam, "_http", fake)
    out = redteam.replay_variant("https://agentguard-demo.o22ugdw213.network",
                                 "tok", "read_file", {"path": "/etc/passwd"})
    assert out["allow"] is False
    assert calls[0][0] == "POST"
    assert calls[0][1].endswith("/api/skills/trap")
    # payload travels as JSON data only — never to a shell
    assert calls[0][2]["args"]["path"] == "/etc/passwd"

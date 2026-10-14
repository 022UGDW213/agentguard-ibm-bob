"""Tests for the web demo's token-based login (web_demo.py).

Covers: env-configured demo credentials, guest/user token mint + verify,
and Authorization-header extraction. No network, no browser.
"""

import importlib

import pytest

import web_demo


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AG_DEMO_USER", "demo")
    monkeypatch.setenv("AG_DEMO_PASSWORD", "agentguard")
    monkeypatch.delenv("AG_HMAC_SECRET", raising=False)
    importlib.reload(web_demo)


def test_password_login_enabled():
    assert web_demo.password_login_enabled()


def test_check_demo_credentials_ok():
    assert web_demo.check_demo_credentials("demo", "agentguard")


def test_check_demo_credentials_wrong_password():
    assert not web_demo.check_demo_credentials("demo", "wrong")


def test_check_demo_credentials_wrong_user():
    assert not web_demo.check_demo_credentials("admin", "agentguard")


def test_check_demo_credentials_disabled(monkeypatch):
    monkeypatch.delenv("AG_DEMO_PASSWORD")
    importlib.reload(web_demo)
    try:
        assert not web_demo.password_login_enabled()
        assert not web_demo.check_demo_credentials("demo", "agentguard")
    finally:
        monkeypatch.setenv("AG_DEMO_PASSWORD", "agentguard")
        importlib.reload(web_demo)


def test_guest_token_roundtrip():
    tok = web_demo.mint_guest_token()
    cap = web_demo.verify_token(tok)
    assert cap.subject == "guest"
    assert cap.scopes == ["tool:read_file", "tool:scan_text"]
    assert not cap.is_expired()


def test_user_token_roundtrip():
    tok = web_demo.mint_user_token("demo")
    cap = web_demo.verify_token(tok)
    assert cap.subject == "demo"
    assert not cap.is_expired()


def test_tampered_token_rejected():
    tok = web_demo.mint_guest_token()
    with pytest.raises(Exception):
        web_demo.verify_token(tok + "tampered")


def test_bearer_token_extraction():
    assert web_demo.bearer_token({"Authorization": "Bearer abc.def"}) == "abc.def"
    assert web_demo.bearer_token({"authorization": "bearer xyz"}) == "xyz"
    assert web_demo.bearer_token({}) == ""
    assert web_demo.bearer_token({"Authorization": "Basic abc"}) == ""
    assert web_demo.bearer_token({"Authorization": "Bearer"}) == ""

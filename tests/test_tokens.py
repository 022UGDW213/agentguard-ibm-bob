import time

import pytest

from agentguard import tokens

SECRET = b"test-secret-123"


def test_mint_and_verify_roundtrip():
    tok = tokens.mint(SECRET, "agent-1", ["tool:fs_read"], ttl_seconds=60)
    cap = tokens.verify(SECRET, tok)
    assert cap.subject == "agent-1"
    assert cap.scopes == ["tool:fs_read"]
    assert not cap.is_expired()


def test_wrong_secret_rejected():
    tok = tokens.mint(SECRET, "agent-1", ["tool:fs_read"])
    with pytest.raises(tokens.TokenError):
        tokens.verify(b"other-secret", tok)


def test_tampered_payload_rejected():
    tok = tokens.mint(SECRET, "agent-1", ["tool:fs_read"])
    body, sig = tok.split(".")
    tampered = body[:-2] + ("AA" if not body.endswith("AA") else "BB")
    with pytest.raises(tokens.TokenError):
        tokens.verify(SECRET, f"{tampered}.{sig}")


def test_expired_token_rejected():
    tok = tokens.mint(SECRET, "agent-1", ["tool:fs_read"], ttl_seconds=1)
    with pytest.raises(tokens.TokenError):
        tokens.verify(SECRET, tok, now=int(time.time()) + 3600)


def test_malformed_token_rejected():
    for bad in ["", "no-dot-here", ".", "a.b.c"]:
        with pytest.raises(tokens.TokenError):
            tokens.verify(SECRET, bad)

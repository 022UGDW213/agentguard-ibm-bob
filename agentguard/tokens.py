"""HMAC-signed capability tokens for AgentGuard.

A capability token binds a subject (an agent identity) to a set of scopes,
e.g. ["tool:fs_read", "tool:fs_write:path=/tmp/*"], with an expiry. The
policy engine only honors scopes presented in a token it can verify — this is
the core of the confused-deputy fix: possession of a valid, narrowly-scoped
token is what authorizes a tool call, not the agent's say-so.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field


class TokenError(ValueError):
    """Raised when a token is malformed, expired, or fails verification."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii") + b"=" * (-len(data) % 4))


@dataclass
class CapabilityToken:
    """A parsed, verified capability token payload."""

    subject: str
    scopes: list[str]
    expires_at: int
    token_id: str = field(default_factory=lambda: secrets.token_hex(8))
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def is_expired(self, now: int | None = None) -> bool:
        return int(now if now is not None else time.time()) >= self.expires_at


def mint(
    secret: bytes,
    subject: str,
    scopes: list[str],
    ttl_seconds: int = 3600,
) -> str:
    """Mint a new signed capability token string."""
    payload = {
        "sub": subject,
        "scopes": list(scopes),
        "iat": int(time.time()),
        "exp": int(time.time()) + int(ttl_seconds),
        "jti": secrets.token_hex(8),
    }
    body = _b64url_encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
    sig = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(sig)}"


def verify(secret: bytes, token: str, now: int | None = None) -> CapabilityToken:
    """Verify a token string and return its payload. Raises TokenError."""
    try:
        body, sig_b64 = token.split(".", 1)
        expected = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
        actual = _b64url_decode(sig_b64)
    except (ValueError, Exception) as exc:  # noqa: BLE001 — any parse failure
        raise TokenError(f"malformed token: {exc}") from exc
    if not hmac.compare_digest(expected, actual):
        raise TokenError("invalid signature")
    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
        cap = CapabilityToken(
            subject=str(payload["sub"]),
            scopes=list(payload["scopes"]),
            expires_at=int(payload["exp"]),
            token_id=str(payload.get("jti", "")),
            issued_at=int(payload.get("iat", 0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError(f"invalid payload: {exc}") from exc
    if cap.is_expired(now):
        raise TokenError("token expired")
    return cap

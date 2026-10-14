"""Clean JSON serialization for AgentGuard's core objects.

This module converts policies, capability tokens, audit entries, and
decisions to and from JSON strings. Everything round-trips: parsing what
this module emits always rebuilds an equal object.

Canonical form: ``json.dumps(..., sort_keys=True)`` with UTF-8 encoding.
Note this is the *same* canonical JSON the token signer uses, so the
``body`` half of a token string is exactly what ``token_to_json`` would
produce for its payload (modulo the key names: tokens use the compact
``sub``/``exp``/``iat``/``jti`` wire names).
"""

from __future__ import annotations

import json

from .policy import Decision, Policy
from .tokens import CapabilityToken


def _dumps(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


def _loads(data: str) -> dict:
    parsed = json.loads(data)
    if not isinstance(parsed, dict):
        raise ValueError("expected a JSON object")
    return parsed


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


def policy_to_json(policy: Policy) -> str:
    """Serialize a Policy to a canonical JSON string."""
    return _dumps({"rules": policy.rules})


def policy_from_json(data: str) -> Policy:
    """Parse a JSON string back into a Policy (validates every rule)."""
    return Policy.from_dict(_loads(data))


# ---------------------------------------------------------------------------
# Capability tokens (payloads, not the signed token string)
# ---------------------------------------------------------------------------


def token_to_json(cap: CapabilityToken) -> str:
    """Serialize a verified token payload to canonical JSON."""
    return _dumps(
        {
            "subject": cap.subject,
            "scopes": list(cap.scopes),
            "expires_at": cap.expires_at,
            "token_id": cap.token_id,
            "issued_at": cap.issued_at,
        }
    )


def token_from_json(data: str) -> CapabilityToken:
    """Parse a JSON string back into a CapabilityToken payload."""
    obj = _loads(data)
    try:
        return CapabilityToken(
            subject=str(obj["subject"]),
            scopes=list(obj["scopes"]),
            expires_at=int(obj["expires_at"]),
            token_id=str(obj.get("token_id", "")),
            issued_at=int(obj.get("issued_at", 0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid token JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Audit ledger entries
# ---------------------------------------------------------------------------

_AUDIT_FIELDS = (
    "ts",
    "tool",
    "args",
    "args_hash",
    "decision",
    "reason",
    "subject",
    "token_id",
)


def audit_entry_to_json(entry: dict) -> str:
    """Serialize one audit entry dict to canonical JSON."""
    return _dumps({k: entry.get(k) for k in _AUDIT_FIELDS})


def audit_entry_from_json(data: str) -> dict:
    """Parse a JSON string back into an audit entry dict."""
    obj = _loads(data)
    missing = [k for k in _AUDIT_FIELDS if k not in obj]
    if missing:
        raise ValueError(f"audit entry missing fields: {missing}")
    if obj["decision"] not in ("allow", "deny"):
        raise ValueError(f"bad decision value: {obj['decision']!r}")
    return {k: obj[k] for k in _AUDIT_FIELDS}


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def decision_to_json(decision: Decision) -> str:
    """Serialize a PolicyEngine Decision to canonical JSON."""
    return _dumps(
        {
            "allow": bool(decision.allow),
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
        }
    )


def decision_from_json(data: str) -> Decision:
    """Parse a JSON string back into a Decision."""
    obj = _loads(data)
    return Decision(
        allow=bool(obj["allow"]),
        reason=str(obj.get("reason", "")),
        matched_rule=obj.get("matched_rule"),
    )

"""Capability token mint, parse, encode, and verify (§11.3).

A capability token is a JSON object signed by the granting authority
and base64url-encoded for transport in the
``Authorization: PhIP-Capability <token>`` header. This module covers
the client-side issuing path (mint + encode) and the verifier path
(parse + verify).

Wire format mirrors `schemas/capability-token.json`. The signature
covers the JCS canonicalization of the token with the ``signature``
field stripped.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from phip.canonicalize import canonical_bytes
from phip.crypto import sign, verify
from phip.errors import InvalidCapability, InvalidSignature

Token = dict[str, Any]
"""A capability token as a typed dict."""


_VALID_SCOPES: frozenset[str] = frozenset(
    {
        "push_events",
        "push_state",
        "push_measurements",
        "push_relations",
        "read_state",
        "read_history",
        "read_topology",
        "read_query",
    }
)

GRANTED_TO_ANYONE = "*"
"""Sentinel for presenter-anonymous tokens (§11.3.1). When a token's
``granted_to`` is this literal string, ``verify_token`` skips the
requesting-actor match. Intended for low-leakage scopes — notably
``read_topology``; using ``"*"`` with ``read_history``, ``read_query``,
or any push scope is effectively a publication and SHOULD be rejected
at policy-review time."""


def mint_token(
    *,
    granted_by: str,
    granted_to: str,
    scope: str,
    object_filter: str,
    not_before: str,
    expires: str,
    private_key: Ed25519PrivateKey,
    key_id: str,
    token_id: str,
) -> Token:
    """Construct and sign a capability token.

    All time fields are caller-provided ISO 8601 strings — the library
    deliberately does not pick `now()` or generate a UUID for you,
    because operator policies for token windows and replay-id schemes
    differ. The CLI / SDK higher layer should add convenient
    ``now() + timedelta`` defaults.

    Returns the signed token dict (ready to ``encode_token``).
    """
    if scope not in _VALID_SCOPES:
        raise ValueError(f"unknown scope {scope!r}; valid: {sorted(_VALID_SCOPES)}")
    if not object_filter:
        raise ValueError("object_filter MUST be a non-empty glob pattern")
    if granted_to == GRANTED_TO_ANYONE and scope not in {"read_topology"}:
        # §11.3.1: "*" tokens SHOULD only be issued for low-leakage scopes.
        # The library refuses outright for write scopes and read_history /
        # read_query, which would effectively publish the resource. Operators
        # who deliberately want an authority-wide grant can bypass by
        # constructing the dict by hand.
        if scope.startswith("push_") or scope in {"read_history", "read_query", "read_state"}:
            raise ValueError(
                f"granted_to='*' combined with scope={scope!r} is effectively a "
                "publication; refuse per §11.3.1. Use scope='read_topology' for "
                "presenter-anonymous tokens, or construct the dict by hand if "
                "you truly want this."
            )
    unsigned: Token = {
        "phip_capability": "1.0",
        "token_id": token_id,
        "granted_by": granted_by,
        "granted_to": granted_to,
        "scope": scope,
        "object_filter": object_filter,
        "not_before": not_before,
        "expires": expires,
    }
    sig_value = sign(private_key, canonical_bytes(unsigned))
    unsigned["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": sig_value,
    }
    return unsigned


def encode_token(token: Token) -> str:
    """Base64url-encode the JCS form of a token for the `Authorization` header."""
    return base64.urlsafe_b64encode(canonical_bytes(token)).rstrip(b"=").decode("ascii")


def parse_token(transport_b64url: str) -> Token:
    """Decode a base64url token (as carried in `Authorization: PhIP-Capability`).

    Raises ``InvalidCapability`` on malformed encoding or wrong shape.
    """
    if not isinstance(transport_b64url, str):
        raise InvalidCapability("token must be a string")
    s = transport_b64url
    # Tolerate both "PhIP-Capability <token>" and bare token forms.
    prefix = "PhIP-Capability "
    if s.startswith(prefix):
        s = s[len(prefix):]
    pad = (-len(s)) % 4
    try:
        raw = base64.urlsafe_b64decode(s + ("=" * pad))
    except Exception as e:
        raise InvalidCapability(f"token is not valid base64url: {e}") from e
    try:
        import json

        token = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise InvalidCapability(f"token is not valid JSON: {e}") from e
    if not isinstance(token, dict) or token.get("phip_capability") != "1.0":
        raise InvalidCapability("token has wrong shape or version")
    return token


def _glob_match(pattern: str, value: str) -> bool:
    """Match a glob pattern (`*` only) against a value, anchored.

    PhIP's `object_filter` glob uses `*` as the only wildcard (§11.3.1).
    No regex, no `?`, no character classes.
    """
    # Escape regex metachars except `*`, then translate `*` → `.*`.
    parts = [re.escape(p) for p in pattern.split("*")]
    regex = "^" + ".*".join(parts) + "$"
    return re.match(regex, value) is not None


def verify_token(
    token: Token,
    public_key: Ed25519PublicKey,
    *,
    requesting_actor: str | None = None,
    requested_object: str | None = None,
    requested_scope: str | None = None,
    verification_time: datetime | None = None,
) -> None:
    """Verify a capability token end-to-end per §11.3.4.

    Performs each step in order:

      2. Cryptographic signature against ``public_key``.
      3. Validity window vs ``verification_time`` (defaults to now).
      4. ``granted_to`` matches ``requesting_actor`` (skipped if None).
      5. ``object_filter`` matches ``requested_object`` (skipped if None).
      6. ``scope`` covers ``requested_scope`` (skipped if None).

    Step 1 (decoding) is ``parse_token``; pass the dict here.

    Raises:
        InvalidSignature: signature failed (401 in HTTP terms).
        InvalidCapability: any other failure (403).
    """
    if not isinstance(token, dict):
        raise InvalidCapability("token is not an object")

    # Step 2: signature.
    sig = token.get("signature")
    if not isinstance(sig, dict) or not isinstance(sig.get("value"), str):
        raise InvalidCapability("token is unsigned")
    unsigned = {k: v for k, v in token.items() if k != "signature"}
    try:
        ok = verify(public_key, canonical_bytes(unsigned), sig["value"])
    except ValueError as e:
        raise InvalidSignature(f"token signature malformed: {e}") from e
    if not ok:
        raise InvalidSignature("token signature verification failed")

    # Step 3: validity window.
    now = verification_time or datetime.now(timezone.utc)
    nb = _parse_dt(token.get("not_before"))
    if nb is not None and now < nb:
        raise InvalidCapability("token is not yet valid", {"not_before": token.get("not_before")})
    exp = _parse_dt(token.get("expires"))
    if exp is not None and now > exp:
        raise InvalidCapability("token has expired", {"expires": token.get("expires")})

    # Step 4: granted_to. The literal "*" disables this check (§11.3.1).
    granted_to = token.get("granted_to")
    if (
        requesting_actor is not None
        and granted_to != GRANTED_TO_ANYONE
        and granted_to != requesting_actor
    ):
        raise InvalidCapability(
            "token granted_to does not match requesting actor",
            {"granted_to": granted_to, "requesting_actor": requesting_actor},
        )

    # Step 5: object_filter.
    if requested_object is not None:
        f = token.get("object_filter")
        if not isinstance(f, str) or not _glob_match(f, requested_object):
            raise InvalidCapability(
                "token object_filter does not match requested object",
                {"object_filter": f, "requested_object": requested_object},
            )

    # Step 6: scope.
    if requested_scope is not None:
        token_scope = token.get("scope")
        if token_scope == requested_scope:
            return
        # read_history covers read_state per §11.5.2.
        if requested_scope == "read_state" and token_scope == "read_history":
            return
        # read_history MAY also serve topology requests per §11.5.6.2.
        if requested_scope == "read_topology" and token_scope == "read_history":
            return
        raise InvalidCapability(
            f"token scope {token_scope!r} does not cover requested {requested_scope!r}",
            {"token_scope": token_scope, "requested_scope": requested_scope},
        )


def _parse_dt(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp, returning aware UTC datetime or None."""
    if not isinstance(value, str) or not value:
        return None
    s = value
    # datetime.fromisoformat handles +00:00 but not "Z" until 3.11+.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

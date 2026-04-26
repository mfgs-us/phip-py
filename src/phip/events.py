"""Event signing, verification, and hash-chain helpers (§10, §11.1).

PhIP events are JSON objects with a fixed top-level shape (§10.1):

    event_id, phip_id, type, timestamp, actor, previous_hash, payload, signature

The signature covers the JCS canonicalization of the event with the
``signature`` field stripped (§11.1). The hash-chain `previous_hash`
field of event N is the SHA-256 (with `sha256:` prefix) of the JCS
canonicalization of event N-1 — including its signature (§10.3).

This module exposes:

* ``sign_event(event, private_key, key_id)`` — produces a signed event
* ``verify_event(event, public_key)`` — returns True/False
* ``hash_event(event)`` — returns ``"sha256:" + 64-hex``
* ``verify_chain(events, public_key_resolver)`` — walks a chain
"""

from __future__ import annotations

from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from phip.canonicalize import canonical_bytes
from phip.crypto import sha256_hex, sign, verify

Event = dict[str, Any]
"""A PhIP event is just a typed dict for now. v0.2 may add a dataclass."""


def hash_event(event: Event) -> str:
    """Compute the ``sha256:<hex>`` hash of an event for chain linkage."""
    return "sha256:" + sha256_hex(canonical_bytes(event))


def sign_event(
    event: Event, private_key: Ed25519PrivateKey, key_id: str
) -> Event:
    """Return a copy of `event` with a fresh ``signature`` field.

    Any existing ``signature`` field is dropped before canonicalization,
    so this function is safe to call on an already-signed event.
    """
    unsigned = {k: v for k, v in event.items() if k != "signature"}
    sig_value = sign(private_key, canonical_bytes(unsigned))
    unsigned["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": sig_value,
    }
    return unsigned


def verify_event(event: Event, public_key: Ed25519PublicKey) -> bool:
    """Verify an event's signature against the supplied public key.

    Returns True iff the signature cryptographically verifies. Returns
    False when the signature field is missing/malformed or the
    cryptographic verification fails. Does NOT verify hash-chain
    continuity, key validity windows, or capability scope — those are
    higher-level checks (see ``verify_chain``, the access module, etc.).
    """
    sig = event.get("signature")
    if not isinstance(sig, dict):
        return False
    sig_value = sig.get("value")
    if not isinstance(sig_value, str):
        return False
    unsigned = {k: v for k, v in event.items() if k != "signature"}
    try:
        return verify(public_key, canonical_bytes(unsigned), sig_value)
    except ValueError:
        return False


PublicKeyResolver = Callable[[str], Ed25519PublicKey | None]
"""Callable that maps a `signature.key_id` to a public key, or None
if the key cannot be resolved (foreign authority unreachable, etc.)."""


def verify_chain(
    events: list[Event],
    public_key_resolver: PublicKeyResolver,
    *,
    require_signatures: bool = True,
) -> None:
    """Walk an event history end-to-end, raising on any integrity failure.

    Verifies, for each event N (0-indexed):

    1. ``previous_hash`` equals ``hash_event(events[N-1])`` for N > 0,
       or the literal string ``"genesis"`` for N == 0.
    2. The event's signature verifies against the key returned by
       ``public_key_resolver(event["signature"]["key_id"])``.

    If ``require_signatures`` is False, step 2 is skipped (useful when
    importing a bundle whose embedded keys aren't loaded yet — but the
    spec never permits this for a final accept; always re-verify before
    trusting).

    Raises:
        InvalidEvent: malformed event structure or hash chain break.
        InvalidSignature: signature verification fails.
        KeyNotFound: resolver returned None for a referenced key.
    """
    from phip.errors import InvalidEvent, InvalidSignature, KeyNotFound

    if not events:
        return  # empty history is trivially valid

    for i, event in enumerate(events):
        if not isinstance(event, dict):
            raise InvalidEvent(f"event[{i}] is not an object")

        expected_prev = "genesis" if i == 0 else hash_event(events[i - 1])
        actual_prev = event.get("previous_hash")
        if actual_prev != expected_prev:
            raise InvalidEvent(
                f"event[{i}].previous_hash mismatch",
                {"expected": expected_prev, "actual": actual_prev},
            )

        if not require_signatures:
            continue

        sig = event.get("signature")
        if not isinstance(sig, dict) or not isinstance(sig.get("key_id"), str):
            raise InvalidEvent(f"event[{i}] missing or malformed signature")
        key_id = sig["key_id"]
        public_key = public_key_resolver(key_id)
        if public_key is None:
            raise KeyNotFound(
                f"could not resolve key_id for event[{i}]",
                {"key_id": key_id},
            )
        if not verify_event(event, public_key):
            raise InvalidSignature(
                f"event[{i}] signature verification failed",
                {"key_id": key_id},
            )

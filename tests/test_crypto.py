"""Crypto primitives: Ed25519 sign/verify and SHA-256 hash, against vectors."""

from __future__ import annotations

import base64

import pytest

from phip.canonicalize import canonical_bytes
from phip.crypto import (
    keypair_from_pkcs8,
    public_key_from_b64url,
    sha256_hex,
    sign,
    verify,
)


@pytest.fixture(scope="module")
def keypairs(keypair_data) -> dict:
    """Load test keypairs by id."""
    out: dict[str, dict] = {}
    for k in keypair_data:
        kp = keypair_from_pkcs8(base64.b64decode(k["private_pkcs8_b64"]))
        out[k["id"]] = {
            "kp": kp,
            "public_b64url": k["public_raw_b64url"],
        }
    return out


def test_keypair_public_matches_vector(keypairs, keypair_data) -> None:
    """Loading a private key MUST yield the documented public key."""
    for entry in keypair_data:
        derived = keypairs[entry["id"]]["kp"].public_b64url
        assert derived == entry["public_raw_b64url"]


def test_sha256_known(hash_cases) -> None:
    """Hash vectors: hash = sha256: + sha256(canonical_bytes(input))."""
    for case in hash_cases:
        got = "sha256:" + sha256_hex(canonical_bytes(case["input"]))
        assert got == case["hash"], f"{case['name']}"


def test_raw_signatures_reproduce(keypairs, ed25519_cases) -> None:
    """Each `raw` case: signing the message with the private key
    yields the documented base64url signature (Ed25519 is deterministic)."""
    for c in ed25519_cases["raw"]:
        kp = keypairs[c["key_id"]]["kp"]
        msg = bytes.fromhex(c["message_hex"])
        got = sign(kp.private, msg)
        assert got == c["signature_b64url"], f"raw/{c['name']}"


def test_raw_signatures_verify(keypairs, ed25519_cases) -> None:
    """The documented signatures verify against the corresponding public key."""
    for c in ed25519_cases["raw"]:
        pub = public_key_from_b64url(keypairs[c["key_id"]]["public_b64url"])
        msg = bytes.fromhex(c["message_hex"])
        assert verify(pub, msg, c["signature_b64url"]), f"raw/{c['name']}"


def test_event_canonical_bytes_match(keypairs, ed25519_cases) -> None:
    """Each event case's `canonical_bytes_hex` matches our JCS output of
    the unsigned event."""
    for c in ed25519_cases["events"]:
        got_hex = canonical_bytes(c["event_unsigned"]).hex()
        assert got_hex == c["canonical_bytes_hex"], f"event/{c['name']}"


def test_event_signatures_reproduce(keypairs, ed25519_cases) -> None:
    """Signing the unsigned event yields the documented signature."""
    for c in ed25519_cases["events"]:
        kp = keypairs[c["key_id"]]["kp"]
        got = sign(kp.private, canonical_bytes(c["event_unsigned"]))
        assert got == c["signature_b64url"], f"event/{c['name']}"


def test_event_signed_form_verifies(keypairs, ed25519_cases) -> None:
    """The signed_event in each case verifies against the documented key."""
    for c in ed25519_cases["events"]:
        pub = public_key_from_b64url(keypairs[c["key_id"]]["public_b64url"])
        signed = c["signed_event"]
        sig_value = signed["signature"]["value"]
        # Signature covers the event with the `signature` field stripped.
        unsigned = {k: v for k, v in signed.items() if k != "signature"}
        assert verify(pub, canonical_bytes(unsigned), sig_value), f"event/{c['name']}"

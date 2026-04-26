"""Event signing, verification, and chain walking against vectors."""

from __future__ import annotations

import base64

import pytest

from phip.crypto import keypair_from_pkcs8, public_key_from_b64url
from phip.errors import InvalidEvent, InvalidSignature, KeyNotFound
from phip.events import hash_event, sign_event, verify_chain, verify_event


@pytest.fixture(scope="module")
def keypairs(keypair_data) -> dict:
    return {
        k["id"]: {
            "kp": keypair_from_pkcs8(base64.b64decode(k["private_pkcs8_b64"])),
            "public_b64url": k["public_raw_b64url"],
        }
        for k in keypair_data
    }


def test_event_hash_matches_hashchain_vectors(hashchain_data) -> None:
    expected_hashes = hashchain_data["expected_hashes"]
    events = hashchain_data["events"]
    assert len(events) == len(expected_hashes)
    for i, ev in enumerate(events):
        assert hash_event(ev) == expected_hashes[i], f"event[{i}] hash mismatch"


def test_chain_verifies_with_resolver(keypairs, hashchain_data, keypair_data) -> None:
    """The hashchain vector's events all sign with the test keypairs."""
    # Map signing-actor URI → public key (vector uses test-key-alice
    # and test-key-bob; map by inspecting the events' key_ids).
    by_keyid = {}
    for k in keypair_data:
        # In the hashchain vector, key_id is the keypair id (no
        # phip:// prefix); but events reference the bare id directly.
        by_keyid[k["id"]] = public_key_from_b64url(k["public_raw_b64url"])

    def resolver(key_id: str):
        return by_keyid.get(key_id)

    verify_chain(hashchain_data["events"], resolver)


def test_chain_rejects_broken_previous_hash(keypairs, hashchain_data, keypair_data) -> None:
    bad = [dict(e) for e in hashchain_data["events"]]
    bad[1]["previous_hash"] = "sha256:" + "0" * 64

    by_keyid = {k["id"]: public_key_from_b64url(k["public_raw_b64url"]) for k in keypair_data}

    with pytest.raises(InvalidEvent):
        verify_chain(bad, lambda kid: by_keyid.get(kid))


def test_chain_rejects_unresolved_key(hashchain_data) -> None:
    with pytest.raises(KeyNotFound):
        verify_chain(hashchain_data["events"], lambda kid: None)


def test_chain_rejects_forged_signature(keypairs, hashchain_data, keypair_data) -> None:
    bad = [dict(e) for e in hashchain_data["events"]]
    # Mutate the LAST event's payload after signing; recompute previous
    # hashes so the only check that fails is signature verification.
    bad[-1] = dict(bad[-1])
    bad[-1]["payload"] = {"text": "FORGED"}

    by_keyid = {k["id"]: public_key_from_b64url(k["public_raw_b64url"]) for k in keypair_data}

    with pytest.raises(InvalidSignature):
        verify_chain(bad, lambda kid: by_keyid.get(kid))


def test_sign_event_round_trips(keypairs) -> None:
    """Sign an event, then verify it with the corresponding public key."""
    alice = keypairs["test-key-alice"]
    event = {
        "event_id": "00000000-0000-4000-a000-000000000099",
        "phip_id": "phip://example.com/parts/x",
        "type": "note",
        "timestamp": "2026-06-01T00:00:00Z",
        "actor": "phip://example.com/actors/alice",
        "previous_hash": "genesis",
        "payload": {"text": "hello"},
    }
    signed = sign_event(event, alice["kp"].private, "test-key-alice")
    assert "signature" in signed
    pub = public_key_from_b64url(alice["public_b64url"])
    assert verify_event(signed, pub)


def test_sign_event_strips_existing_signature(keypairs) -> None:
    """Re-signing an already-signed event uses the new signature."""
    alice = keypairs["test-key-alice"]
    event = {
        "event_id": "00000000-0000-4000-a000-000000000098",
        "phip_id": "phip://example.com/parts/x",
        "type": "note",
        "timestamp": "2026-06-01T00:00:00Z",
        "actor": "phip://example.com/actors/alice",
        "previous_hash": "genesis",
        "payload": {"text": "hello"},
        "signature": {"algorithm": "Ed25519", "key_id": "old", "value": "x" * 86},
    }
    signed = sign_event(event, alice["kp"].private, "test-key-alice")
    pub = public_key_from_b64url(alice["public_b64url"])
    assert verify_event(signed, pub)
    assert signed["signature"]["key_id"] == "test-key-alice"


def test_bootstrap_vector_self_signs(bootstrap_example, keypair_data) -> None:
    """The bootstrap event verifies against the public key embedded in
    its OWN payload (Section 11.2.4 self-signed bootstrap pattern)."""
    event = bootstrap_example["created_event"]
    jwk = event["payload"]["attributes"]["phip:keys"]
    pub = public_key_from_b64url(jwk["x"])
    assert verify_event(event, pub)
    assert event["actor"] == event["phip_id"], "self-signed bootstrap"

"""Bundle tests — verify against vectors, plus pack/unpack round trip."""

from __future__ import annotations

import base64

import pytest

from phip.bundle import (
    BUNDLE_VERSION,
    bundle_from_dict,
    make_bundle,
    pack_bundle,
    unpack_bundle,
    verify_bundle,
)
from phip.crypto import keypair_from_pkcs8
from phip.errors import InvalidEvent, InvalidSignature, KeyNotFound
from phip.events import sign_event


def test_bundle_vectors_one_object_verifies(bundle_cases) -> None:
    case = next(b for b in bundle_cases if b["name"] == "one-object")
    bundle = bundle_from_dict(case)
    verify_bundle(bundle)  # MUST NOT raise


def test_bundle_vectors_multi_object_verifies(bundle_cases) -> None:
    case = next(b for b in bundle_cases if b["name"] == "multi-object")
    bundle = bundle_from_dict(case)
    verify_bundle(bundle)  # MUST NOT raise


def test_bundle_vectors_tampered_event_rejected(bundle_cases) -> None:
    """The tampered case has a valid manifest signature but a mutated
    event payload — chain verification must reject."""
    case = next(b for b in bundle_cases if b["name"] == "tampered-event")
    bundle = bundle_from_dict(case)
    with pytest.raises((InvalidSignature, InvalidEvent)):
        verify_bundle(bundle)


def test_make_bundle_round_trip(keypair_data) -> None:
    """Build a bundle from a single object's history; verify it; pack
    to tar; unpack; verify again."""
    alice = next(k for k in keypair_data if k["id"] == "test-key-alice")
    kp = keypair_from_pkcs8(base64.b64decode(alice["private_pkcs8_b64"]))
    key_uri = "phip://acme.example/keys/alice"

    obj_phip_id = "phip://acme.example/parts/widget-001"
    create_event = sign_event(
        {
            "event_id": "00000000-0000-4000-a000-000000000001",
            "phip_id": obj_phip_id,
            "type": "created",
            "timestamp": "2026-04-01T00:00:00Z",
            "actor": key_uri,
            "previous_hash": "genesis",
            "payload": {
                "object_type": "component",
                "state": "stock",
                "identity": {"serial": "WGT-001"},
            },
        },
        kp.private,
        key_uri,
    )

    objects = [{"phip_id": obj_phip_id}]
    history = {obj_phip_id: [create_event]}
    keys = {
        key_uri: {
            "phip_id": key_uri,
            "object_type": "actor",
            "state": "active",
            "attributes": {
                "phip:keys": {
                    **kp.jwk,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                },
            },
            "history": [],
        }
    }

    bundle = make_bundle(
        authority="acme.example",
        created_by=key_uri,
        created_at="2026-04-15T00:00:00Z",
        objects=objects,
        history=history,
        keys=keys,
        private_key=kp.private,
        key_id=key_uri,
    )

    assert bundle.manifest["bundle_version"] == BUNDLE_VERSION
    assert bundle.manifest["authority"] == "acme.example"
    verify_bundle(bundle)

    # Pack to tar bytes, unpack, verify again.
    tar_bytes = pack_bundle(bundle)
    assert isinstance(tar_bytes, bytes) and len(tar_bytes) > 0

    restored = unpack_bundle(tar_bytes)
    assert restored.manifest == bundle.manifest
    assert restored.objects == bundle.objects
    assert restored.history == bundle.history
    assert restored.keys == bundle.keys
    verify_bundle(restored)


def test_unknown_event_key_rejected(keypair_data) -> None:
    """An event signed by a key not embedded in the bundle MUST be
    rejected with KeyNotFound."""
    alice = next(k for k in keypair_data if k["id"] == "test-key-alice")
    bob = next(k for k in keypair_data if k["id"] == "test-key-bob")
    alice_kp = keypair_from_pkcs8(base64.b64decode(alice["private_pkcs8_b64"]))
    bob_kp = keypair_from_pkcs8(base64.b64decode(bob["private_pkcs8_b64"]))
    key_uri = "phip://acme.example/keys/alice"
    bob_key_uri = "phip://acme.example/keys/bob"

    obj_phip_id = "phip://acme.example/parts/x"
    # Event signed by Bob, but Bob's key actor is NOT embedded.
    bob_signed = sign_event(
        {
            "event_id": "00000000-0000-4000-a000-000000000002",
            "phip_id": obj_phip_id,
            "type": "created",
            "timestamp": "2026-04-01T00:00:00Z",
            "actor": bob_key_uri,
            "previous_hash": "genesis",
            "payload": {"object_type": "component", "state": "stock"},
        },
        bob_kp.private,
        bob_key_uri,
    )

    bundle = make_bundle(
        authority="acme.example",
        created_by=key_uri,
        created_at="2026-04-15T00:00:00Z",
        objects=[{"phip_id": obj_phip_id}],
        history={obj_phip_id: [bob_signed]},
        keys={
            # Only Alice embedded; Bob's key actor missing.
            key_uri: {
                "phip_id": key_uri,
                "object_type": "actor",
                "state": "active",
                "attributes": {
                    "phip:keys": {
                        **alice_kp.jwk,
                        "not_before": "2020-01-01T00:00:00Z",
                        "not_after": "2099-01-01T00:00:00Z",
                    }
                },
                "history": [],
            }
        },
        private_key=alice_kp.private,
        key_id=key_uri,
    )

    with pytest.raises(KeyNotFound):
        verify_bundle(bundle)


def test_bare_keyid_with_foreign_actor_rejected(keypair_data) -> None:
    """Forgery vector: an event whose `actor` claims a foreign actor URI
    but whose `signature.key_id` is a bare unknown id. The producer-key
    fallback in `_resolve_event_key` MUST refuse to handle it, otherwise
    a malicious bundle could mint events that *appear* to come from
    other actors but are actually signed by the producer."""
    alice = next(k for k in keypair_data if k["id"] == "test-key-alice")
    kp = keypair_from_pkcs8(base64.b64decode(alice["private_pkcs8_b64"]))
    producer_uri = "phip://acme.example/keys/alice"
    obj_phip_id = "phip://acme.example/parts/x"

    # Sign an event WITH the producer's key but claim a foreign actor.
    forged = sign_event(
        {
            "event_id": "00000000-0000-4000-a000-000000000099",
            "phip_id": obj_phip_id,
            "type": "created",
            "timestamp": "2026-04-01T00:00:00Z",
            "actor": "phip://other-org.example/actors/innocent-bystander",
            "previous_hash": "genesis",
            "payload": {"object_type": "component", "state": "stock"},
        },
        kp.private,
        "unknown-bare-id",  # signed_event records this as key_id
    )

    bundle = make_bundle(
        authority="acme.example",
        created_by=producer_uri,
        created_at="2026-04-15T00:00:00Z",
        objects=[{"phip_id": obj_phip_id}],
        history={obj_phip_id: [forged]},
        keys={
            producer_uri: {
                "phip_id": producer_uri,
                "object_type": "actor",
                "state": "active",
                "attributes": {
                    "phip:keys": {
                        **kp.jwk,
                        "not_before": "2020-01-01T00:00:00Z",
                        "not_after": "2099-01-01T00:00:00Z",
                    }
                },
                "history": [],
            }
        },
        private_key=kp.private,
        key_id=producer_uri,
    )

    with pytest.raises(KeyNotFound):
        verify_bundle(bundle)


def test_bundle_with_snapshot_of_round_trips(keypair_data) -> None:
    alice = next(k for k in keypair_data if k["id"] == "test-key-alice")
    kp = keypair_from_pkcs8(base64.b64decode(alice["private_pkcs8_b64"]))
    key_uri = "phip://acme.example/keys/alice"
    obj_phip_id = "phip://acme.example/parts/x"
    event = sign_event(
        {
            "event_id": "00000000-0000-4000-a000-000000000003",
            "phip_id": obj_phip_id,
            "type": "created",
            "timestamp": "2026-04-01T00:00:00Z",
            "actor": key_uri,
            "previous_hash": "genesis",
            "payload": {"object_type": "component", "state": "stock"},
        },
        kp.private,
        key_uri,
    )
    bundle = make_bundle(
        authority="acme.example",
        created_by=key_uri,
        created_at="2026-04-15T00:00:00Z",
        snapshot_of="2026-04-15T00:00:00Z",
        objects=[{"phip_id": obj_phip_id}],
        history={obj_phip_id: [event]},
        keys={
            key_uri: {
                "phip_id": key_uri,
                "object_type": "actor",
                "state": "active",
                "attributes": {
                    "phip:keys": {
                        **kp.jwk,
                        "not_before": "2020-01-01T00:00:00Z",
                        "not_after": "2099-01-01T00:00:00Z",
                    }
                },
                "history": [],
            }
        },
        private_key=kp.private,
        key_id=key_uri,
    )
    assert bundle.manifest["snapshot_of"] == "2026-04-15T00:00:00Z"
    verify_bundle(bundle)

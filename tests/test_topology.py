"""Topology disclosure tests (§11.5.6)."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest

from phip.crypto import keypair_from_pkcs8, public_key_from_b64url
from phip.errors import InvalidCapability, InvalidEvent, InvalidSignature
from phip.tokens import GRANTED_TO_ANYONE, mint_token, verify_token
from phip.topology import (
    DISCLOSURE_TOPOLOGY,
    build_topology_envelope,
    stitch_pages,
    topology_entry_for,
    verify_first_page,
    verify_topology_response,
    walk_topology_chain,
)


@pytest.fixture(scope="module")
def keys(keypair_data) -> dict:
    return {
        k["id"]: {
            "kp": keypair_from_pkcs8(base64.b64decode(k["private_pkcs8_b64"])),
            "pub": public_key_from_b64url(k["public_raw_b64url"]),
        }
        for k in keypair_data
    }


# ── vector fixtures ──────────────────────────────────────────────────


def test_vector_cases_verify(topology_cases, keys):
    """Every shared topology vector verifies exactly as the JSON says."""
    for c in topology_cases:
        pub = keys[c["verifying_key_id"]]["pub"]

        if "pages" in c:
            # Multi-page case: each page independently, plus inter-page link.
            expected_sigs = c["expected"]["page_signatures_verify"]
            for page, expected_sig in zip(c["pages"], expected_sigs):
                if expected_sig:
                    verify_topology_response(page, pub)  # must not raise
                else:
                    with pytest.raises((InvalidSignature, InvalidEvent)):
                        verify_topology_response(page, pub)

            if c["expected"]["inter_page_link_holds"]:
                # stitch_pages should succeed.
                flat = stitch_pages(c["pages"])
                assert len(flat) == sum(len(p["topology"]) for p in c["pages"])
            else:
                with pytest.raises(InvalidEvent):
                    stitch_pages(c["pages"])
            continue

        # Single-response case.
        expected_sig = c["expected"]["signature_verifies"]
        expected_walk = c["expected"]["chain_walk_succeeds"]

        if expected_sig and expected_walk:
            verify_topology_response(c["response"], pub)  # must not raise
        else:
            with pytest.raises((InvalidSignature, InvalidEvent)):
                verify_topology_response(c["response"], pub)


def test_walk_topology_chain_detects_break(topology_cases):
    """The chain-walk helper returns the index of the first break."""
    for c in topology_cases:
        if "response" not in c:
            continue
        topology = c["response"]["topology"]
        break_at = walk_topology_chain(topology)
        if c["name"] == "tampered-chain-link":
            assert break_at == 1
        else:
            assert break_at is None


# ── round-trip via the build/verify helpers ──────────────────────────


def test_build_and_verify_round_trip(keys):
    """build_topology_envelope produces an output that verify_topology_response accepts."""
    kp = keys["test-key-alice"]
    # Build a 2-event chain — the second event's previous_hash must equal
    # the first event's hash for the chain walk to succeed.
    from phip.events import hash_event

    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    evt1 = {
        "event_id": "10000000-0000-4000-a000-000000000002",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "state_transition",
        "timestamp": "2026-01-22T14:30:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": hash_event(evt0),
        "payload": {"from": "design", "to": "qualified"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    topology = [topology_entry_for(evt0), topology_entry_for(evt1)]

    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=topology,
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    # Round-trip: the produced envelope verifies.
    verify_topology_response(response, kp["pub"])
    verify_first_page(response, kp["pub"])

    assert response["disclosure"] == DISCLOSURE_TOPOLOGY
    assert response["page_length"] == 2


def test_verify_rejects_envelope_with_swapped_phip_id(keys):
    """Tamper resistance: mutating phip_id after signing fails verification."""
    kp = keys["test-key-alice"]
    from phip.events import hash_event

    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt0)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    response["phip_id"] = "phip://acme.example/projects/widget-IMPOSTER"
    with pytest.raises(InvalidSignature):
        verify_topology_response(response, kp["pub"])


def test_verify_rejects_extra_fields_in_signed_object(keys):
    """A response carrying additional top-level fields still verifies; the
    verifier ignores them when reconstructing the canonical signed object."""
    kp = keys["test-key-alice"]
    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt0)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    # Resolver-emitted extras MUST NOT break verification.
    response["served_at"] = "2026-05-20T12:00:00Z"
    response["request_id"] = "req-abc-123"
    verify_topology_response(response, kp["pub"])  # must not raise


def test_verify_rejects_response_missing_phip_id(keys):
    """Malformed response without phip_id → InvalidEvent, not KeyError."""
    kp = keys["test-key-alice"]
    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt0)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    del response["phip_id"]
    with pytest.raises(InvalidEvent):
        verify_topology_response(response, kp["pub"])


def test_verify_rejects_entry_with_extra_fields(keys):
    """Each topology entry MUST contain exactly the five canonical fields
    (§11.5.6.3). A resolver that leaks payload/actor/signature per-entry
    must be caught even if the envelope signature happens to verify."""
    kp = keys["test-key-alice"]
    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    # Build a normal entry, then add a forbidden extra field BEFORE signing,
    # so the signature is over the tampered shape (verifier would otherwise
    # only see a signature-mismatch).
    entry = topology_entry_for(evt0)
    entry["payload"] = {"leaked": "data"}
    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[entry],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    with pytest.raises(InvalidEvent):
        verify_topology_response(response, kp["pub"])


def test_stitch_pages_handles_empty_leading_page(keys):
    """stitch_pages must use 'genesis' as the expected previous_hash for
    the first NON-EMPTY page, not the first iteration position. A leading
    empty page must not break the 'genesis' invariant."""
    kp = keys["test-key-alice"]
    from phip.events import hash_event

    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    # Empty page first, real page second.
    empty_page = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    real_page = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt0)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    flat = stitch_pages([empty_page, real_page])
    assert len(flat) == 1
    assert flat[0]["previous_hash"] == "genesis"


def test_verify_rejects_entry_missing_event_hash(keys):
    """Missing fields on an entry are caught by the same set-equality check
    that catches extra fields."""
    kp = keys["test-key-alice"]
    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    entry = topology_entry_for(evt0)
    del entry["event_hash"]
    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[entry],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    with pytest.raises(InvalidEvent):
        verify_topology_response(response, kp["pub"])


def test_verify_rejects_non_ed25519_algorithm(keys):
    """topology_signature.algorithm MUST be 'Ed25519' (§11.5.6.4)."""
    kp = keys["test-key-alice"]
    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt0)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    response["topology_signature"]["algorithm"] = "Ed448"
    with pytest.raises(InvalidEvent):
        verify_topology_response(response, kp["pub"])


def test_stitch_pages_with_public_key_verifies_each_page(keys):
    """stitch_pages(pages, public_key=...) verifies each non-empty page."""
    kp = keys["test-key-alice"]
    from phip.events import hash_event

    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "created",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "genesis",
        "payload": {"object_type": "design", "state": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    evt1 = {
        "event_id": "10000000-0000-4000-a000-000000000002",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "state_transition",
        "timestamp": "2026-01-22T14:30:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": hash_event(evt0),
        "payload": {"from": "design", "to": "qualified"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    page1 = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt0)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    page2 = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt1)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    flat = stitch_pages([page1, page2], public_key=kp["pub"])
    assert len(flat) == 2

    # Tampering one page's phip_id post-sign → stitch refuses.
    page2["phip_id"] = "phip://acme.example/projects/widget-IMPOSTER"
    from phip.errors import InvalidSignature
    with pytest.raises(InvalidSignature):
        stitch_pages([page1, page2], public_key=kp["pub"])


def test_mint_token_rejects_empty_granted_to(keys):
    kp = keys["test-key-alice"]
    with pytest.raises(ValueError):
        mint_token(
            granted_by="phip://acme.example/keys/test-key-alice",
            granted_to="",
            scope="read_topology",
            object_filter="phip://acme.example/*",
            not_before="2026-01-01T00:00:00Z",
            expires="2099-01-01T00:00:00Z",
            private_key=kp["kp"].private,
            key_id="phip://acme.example/keys/test-key-alice",
            token_id="00000000-0000-4000-a000-0000000000ee",
        )


def test_verify_first_page_requires_genesis_marker(keys):
    """verify_first_page rejects a topology whose first entry's previous_hash
    is not the literal 'genesis'."""
    kp = keys["test-key-alice"]
    from phip.events import hash_event

    evt0 = {
        "event_id": "10000000-0000-4000-a000-000000000001",
        "phip_id": "phip://acme.example/projects/widget-v3",
        "type": "state_transition",
        "timestamp": "2026-01-15T09:00:00Z",
        "actor": "phip://acme.example/keys/test-key-alice",
        "previous_hash": "sha256:" + "a" * 64,  # not genesis
        "payload": {"from": "concept", "to": "design"},
        "signature": {"algorithm": "Ed25519", "key_id": "x", "value": "AA"},
    }
    response = build_topology_envelope(
        phip_id="phip://acme.example/projects/widget-v3",
        topology=[topology_entry_for(evt0)],
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
    )
    # Plain verify passes (it doesn't enforce genesis-first).
    verify_topology_response(response, kp["pub"])
    # First-page verify rejects.
    with pytest.raises(InvalidEvent):
        verify_first_page(response, kp["pub"])


# ── token interactions ───────────────────────────────────────────────


def test_mint_token_accepts_read_topology(keys):
    kp = keys["test-key-alice"]
    t = mint_token(
        granted_by="phip://acme.example/keys/test-key-alice",
        granted_to=GRANTED_TO_ANYONE,
        scope="read_topology",
        object_filter="phip://acme.example/projects/widget-v3",
        not_before="2026-01-01T00:00:00Z",
        expires="2099-01-01T00:00:00Z",
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
        token_id="00000000-0000-4000-a000-000000000099",
    )
    assert t["scope"] == "read_topology"
    assert t["granted_to"] == "*"


def test_mint_token_rejects_star_with_high_leakage_scopes(keys):
    """granted_to='*' with read_history / read_query / push_* MUST raise."""
    kp = keys["test-key-alice"]
    for bad_scope in ("read_history", "read_query", "read_state", "push_events", "push_state"):
        with pytest.raises(ValueError):
            mint_token(
                granted_by="phip://acme.example/keys/test-key-alice",
                granted_to="*",
                scope=bad_scope,
                object_filter="phip://acme.example/*",
                not_before="2026-01-01T00:00:00Z",
                expires="2099-01-01T00:00:00Z",
                private_key=kp["kp"].private,
                key_id="phip://acme.example/keys/test-key-alice",
                token_id="00000000-0000-4000-a000-0000000000aa",
            )


def test_verify_token_star_skips_actor_match(keys):
    """A '*' token verifies regardless of which requesting actor is supplied."""
    kp = keys["test-key-alice"]
    t = mint_token(
        granted_by="phip://acme.example/keys/test-key-alice",
        granted_to="*",
        scope="read_topology",
        object_filter="phip://acme.example/*",
        not_before="2026-01-01T00:00:00Z",
        expires="2099-01-01T00:00:00Z",
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
        token_id="00000000-0000-4000-a000-0000000000bb",
    )
    # Any requesting actor — no exception.
    verify_token(
        t,
        kp["pub"],
        requesting_actor="phip://reader.example/actors/alice",
        verification_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    verify_token(
        t,
        kp["pub"],
        requesting_actor="phip://other.example/actors/bob",
        verification_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )


def test_verify_token_read_history_covers_topology(keys):
    """A read_history token MAY also serve topology requests (§11.5.6.2)."""
    kp = keys["test-key-alice"]
    t = mint_token(
        granted_by="phip://acme.example/keys/test-key-alice",
        granted_to="phip://acme.example/keys/test-key-alice",
        scope="read_history",
        object_filter="phip://acme.example/*",
        not_before="2026-01-01T00:00:00Z",
        expires="2099-01-01T00:00:00Z",
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
        token_id="00000000-0000-4000-a000-0000000000cc",
    )
    # read_topology requested, read_history token: passes.
    verify_token(
        t,
        kp["pub"],
        requested_scope="read_topology",
        verification_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )


def test_verify_token_read_topology_does_not_cover_state(keys):
    """A read_topology token does NOT cover GET state (§11.5.6.1)."""
    kp = keys["test-key-alice"]
    t = mint_token(
        granted_by="phip://acme.example/keys/test-key-alice",
        granted_to="*",
        scope="read_topology",
        object_filter="phip://acme.example/*",
        not_before="2026-01-01T00:00:00Z",
        expires="2099-01-01T00:00:00Z",
        private_key=kp["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
        token_id="00000000-0000-4000-a000-0000000000dd",
    )
    with pytest.raises(InvalidCapability):
        verify_token(
            t,
            kp["pub"],
            requested_scope="read_state",
            verification_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )

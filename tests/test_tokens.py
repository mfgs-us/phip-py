"""Capability token vectors: each case verifies as the spec dictates."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest

from phip.crypto import keypair_from_pkcs8, public_key_from_b64url
from phip.errors import InvalidCapability, InvalidSignature
from phip.tokens import encode_token, mint_token, parse_token, verify_token


@pytest.fixture(scope="module")
def keypairs(keypair_data) -> dict:
    return {
        k["id"]: {
            "kp": keypair_from_pkcs8(base64.b64decode(k["private_pkcs8_b64"])),
            "public_b64url": k["public_raw_b64url"],
        }
        for k in keypair_data
    }


def _verifying_key(keypairs, key_id: str):
    return public_key_from_b64url(keypairs[key_id]["public_b64url"])


def _at(iso: str) -> datetime:
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    return datetime.fromisoformat(iso).astimezone(timezone.utc)


def test_token_signatures_match_expected(token_cases, keypairs) -> None:
    """Each case's signature is what verify_token sees — either it
    cryptographically verifies or it doesn't, by case ``expected``."""
    for c in token_cases:
        pub = _verifying_key(keypairs, c["verifying_key_id"])
        try:
            verify_token(c["signed_token"], pub)
            verified = True
        except InvalidSignature:
            verified = False
        except InvalidCapability:
            # Other failures (expired, malformed) are not signature failures.
            verified = True

        if c["expected"] == "invalid_signature":
            assert not verified, f"{c['name']}: expected invalid signature"
        else:
            assert verified, f"{c['name']}: expected valid signature"


def test_transport_round_trips(token_cases) -> None:
    """The base64url transport form decodes to the same JSON object."""
    for c in token_cases:
        decoded = parse_token(c["transport_b64url"])
        assert decoded == c["signed_token"], f"{c['name']} round trip"


def test_expired_token_rejected(token_cases, keypairs) -> None:
    case = next(c for c in token_cases if c["name"] == "expired-token")
    pub = _verifying_key(keypairs, case["verifying_key_id"])
    with pytest.raises(InvalidCapability) as exc:
        verify_token(case["signed_token"], pub, verification_time=_at(case["verification_time"]))
    assert "expired" in str(exc.value)


def test_not_yet_valid_token_rejected(token_cases, keypairs) -> None:
    case = next(c for c in token_cases if c["name"] == "not-yet-valid-token")
    pub = _verifying_key(keypairs, case["verifying_key_id"])
    with pytest.raises(InvalidCapability) as exc:
        verify_token(case["signed_token"], pub, verification_time=_at(case["verification_time"]))
    assert "not yet valid" in str(exc.value)


def test_object_filter_mismatch_rejected(token_cases, keypairs) -> None:
    case = next(c for c in token_cases if c["name"] == "object-filter-mismatch")
    pub = _verifying_key(keypairs, case["verifying_key_id"])
    with pytest.raises(InvalidCapability):
        verify_token(
            case["signed_token"],
            pub,
            verification_time=_at(case["verification_time"]),
            requested_object=case["requested_object"],
        )


def test_object_filter_match_accepted(token_cases, keypairs) -> None:
    """A token with object_filter='phip://acme.example/parts/*' should
    accept any object under that prefix."""
    case = next(c for c in token_cases if c["name"] == "valid-push-token")
    pub = _verifying_key(keypairs, case["verifying_key_id"])
    verify_token(
        case["signed_token"],
        pub,
        verification_time=_at(case["verification_time"]),
        requested_object="phip://acme.example/parts/widget-001",
    )


def test_read_history_covers_read_state(token_cases, keypairs) -> None:
    case = next(c for c in token_cases if c["name"] == "read-history-token")
    pub = _verifying_key(keypairs, case["verifying_key_id"])
    # read_history token serving a read_state operation: should pass.
    verify_token(
        case["signed_token"],
        pub,
        verification_time=_at(case["verification_time"]),
        requested_scope="read_state",
    )


def test_read_state_does_not_cover_read_history(keypairs) -> None:
    """Inverse: a read_state token cannot serve read_history."""
    alice = keypairs["test-key-alice"]
    token = mint_token(
        granted_by="phip://acme.example/keys/test-key-alice",
        granted_to="phip://acme.example/keys/test-key-alice",
        scope="read_state",
        object_filter="phip://acme.example/*",
        not_before="2026-01-15T00:00:00Z",
        expires="2099-01-01T00:00:00Z",
        private_key=alice["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
        token_id="00000000-0000-4000-a000-000000000099",
    )
    pub = public_key_from_b64url(alice["public_b64url"])
    with pytest.raises(InvalidCapability):
        verify_token(token, pub, requested_scope="read_history")


def test_mint_round_trip(keypairs) -> None:
    """A freshly minted token verifies, encodes, parses, and re-verifies."""
    alice = keypairs["test-key-alice"]
    token = mint_token(
        granted_by="phip://acme.example/keys/test-key-alice",
        granted_to="phip://acme.example/keys/test-key-alice",
        scope="push_events",
        object_filter="phip://acme.example/parts/*",
        not_before="2026-01-15T00:00:00Z",
        expires="2099-01-01T00:00:00Z",
        private_key=alice["kp"].private,
        key_id="phip://acme.example/keys/test-key-alice",
        token_id="00000000-0000-4000-a000-000000000100",
    )
    encoded = encode_token(token)
    parsed = parse_token(encoded)
    assert parsed == token
    pub = public_key_from_b64url(alice["public_b64url"])
    verify_token(parsed, pub, verification_time=_at("2026-06-01T00:00:00Z"))


def test_parse_rejects_garbage() -> None:
    with pytest.raises(InvalidCapability):
        parse_token("not-a-token")
    with pytest.raises(InvalidCapability):
        parse_token(base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode())
    bad_json = base64.urlsafe_b64encode(json.dumps({"not": "a token"}).encode()).rstrip(b"=").decode()
    with pytest.raises(InvalidCapability):
        parse_token(bad_json)

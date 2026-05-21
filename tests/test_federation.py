"""Federation client tests — SSRF defense, cache TTL clamp, key resolution."""

from __future__ import annotations

import pytest

from phip.federation import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    FederationClient,
    _clamp_ttl,
    _parse_max_age,
    is_private_address,
)

# ── private-address filter — matches the Node reference's coverage ──


@pytest.mark.parametrize(
    "addr,expected",
    [
        # IPv4 private
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("192.168.1.1", True),
        ("169.254.1.1", True),
        ("100.64.0.1", True),
        ("224.0.0.1", True),
        ("255.255.255.255", True),
        # IPv4 public
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("172.32.0.1", False),
        ("100.63.0.1", False),
        # IPv6 private
        ("::1", True),
        ("::", True),
        ("fe80::1", True),
        ("fe81::1", True),
        ("fe88::1", True),
        ("fe8f::1", True),
        ("fe9a::1", True),
        ("fea0::1", True),
        ("febf::ffff", True),
        ("fc00::1", True),
        ("fd00::1", True),
        ("fdff::ffff", True),
        ("ff00::1", True),
        ("::ffff:127.0.0.1", True),
        # IPv6 public
        ("2001:db8::1", False),
        ("fe::1", False),  # 0x00fe::1
        ("fc::1", False),  # 0x00fc::1
        ("ff::1", False),  # 0x00ff::1
        # Garbage
        ("not-an-ip", True),
        ("", True),
    ],
)
def test_is_private_address(addr: str, expected: bool) -> None:
    assert is_private_address(addr) is expected


# ── cache TTL clamp ──────────────────────────────────────────────


def test_parse_max_age_present() -> None:
    assert _parse_max_age({"cache-control": "public, max-age=3600"}) == 3600
    assert _parse_max_age({"Cache-Control": "MAX-AGE=42"}) == 42


def test_parse_max_age_absent() -> None:
    assert _parse_max_age({}) == 0
    assert _parse_max_age({"cache-control": "no-cache"}) == 0


def test_clamp_ttl_bounds() -> None:
    assert _clamp_ttl(0) == DEFAULT_TTL_SECONDS
    assert _clamp_ttl(-5) == DEFAULT_TTL_SECONDS
    assert _clamp_ttl(60) == 60
    # Foreign-supplied huge max-age MUST be capped at 24 hours.
    assert _clamp_ttl(99_999_999) == MAX_TTL_SECONDS


# ── federation client construction ───────────────────────────────


def test_default_refuses_http() -> None:
    fed = FederationClient()
    assert fed.allow_http is False
    assert fed.allow_private_addresses is False


def test_test_mode_allows_localhost() -> None:
    fed = FederationClient(allow_http=True)
    assert fed.allow_http is True
    assert fed.allow_private_addresses is True  # follows allow_http


def test_url_builder_override() -> None:
    fed = FederationClient(url_builder=lambda authority, path: f"http://127.0.0.1:9999{path}")
    assert (
        fed._build_url("alice.local", "/.well-known/phip/meta")
        == "http://127.0.0.1:9999/.well-known/phip/meta"
    )


# ── live federation against the reference resolver ───────────────


@pytest.mark.asyncio
async def test_resolve_key_against_reference(reference_server) -> None:
    """End-to-end: spin a reference resolver, register a bootstrap key
    actor, and resolve it via the federation client. Skipped if the
    reference isn't available."""
    import os
    import socket
    import subprocess
    import time
    import uuid
    from datetime import datetime, timezone
    from pathlib import Path

    from phip import Client, generate_keypair, sign_event

    # Reuse the integration_reference fixture pattern: spin our own
    # short-lived reference here (the existing fixture is for sync
    # tests; this is async-only).
    reference_path = Path(
        os.environ.get(
            "PHIP_REFERENCE_PATH",
            Path(__file__).resolve().parents[2] / "phip" / "reference",
        )
    ).resolve()
    if not reference_path.exists() or not (reference_path / "node_modules").exists():
        pytest.skip("reference resolver unavailable")

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    authority = "fed-test.local"
    proc = subprocess.Popen(
        ["node", str(reference_path / "src" / "index.js")],
        env={**os.environ, "PHIP_AUTHORITY": authority, "PHIP_PORT": str(port)},
        cwd=reference_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # Wait for port.
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.skip("reference resolver didn't open port")

        # Register a bootstrap actor we'll then resolve via federation.
        sync = Client(base_url=f"http://127.0.0.1:{port}", authority=authority)
        kp = generate_keypair()
        run_id = uuid.uuid4().hex[:8]
        key_phip_id = f"phip://{authority}/keys/bootstrap-{run_id}"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sync.create(
            sign_event(
                {
                    "event_id": str(uuid.uuid4()),
                    "phip_id": key_phip_id,
                    "type": "created",
                    "timestamp": now,
                    "actor": key_phip_id,
                    "previous_hash": "genesis",
                    "payload": {
                        "object_type": "actor",
                        "state": "active",
                        "attributes": {
                            "phip:keys": {
                                **kp.jwk,
                                "not_before": "2020-01-01T00:00:00Z",
                                "not_after": "2099-01-01T00:00:00Z",
                            },
                        },
                    },
                },
                kp.private,
                key_phip_id,
            )
        )
        sync.close()

        # Now use federation client to fetch that key actor by URI.
        # url_builder maps the authority name to localhost:port.
        fed = FederationClient(
            allow_http=True,
            url_builder=lambda auth, path: f"http://127.0.0.1:{port}{path}",
        )
        jwk = await fed.resolve_key(key_phip_id)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["x"] == kp.public_b64url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# Stub fixture for the test above — pytest discovers it by name.
@pytest.fixture
def reference_server() -> None:
    """Sentinel; the actual logic lives in the test body."""
    return None

"""AsyncClient unit tests with mocked HTTP transport. Mirrors test_client.py."""

from __future__ import annotations

import pytest

from phip import AsyncClient, ChainConflict, InvalidTransition, ObjectNotFound


@pytest.fixture
async def client() -> AsyncClient:
    c = AsyncClient(base_url="https://acme.example", authority="acme.example")
    try:
        yield c
    finally:
        await c.aclose()


async def test_get_returns_object(httpx_mock, client: AsyncClient) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/resolve/parts/widget-001",
        json={"phip_id": "phip://acme.example/parts/widget-001", "state": "stock"},
    )
    obj = await client.get("phip://acme.example/parts/widget-001")
    assert obj["state"] == "stock"


async def test_get_404_raises(httpx_mock, client: AsyncClient) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/resolve/parts/missing",
        status_code=404,
        json={"error": {"code": "OBJECT_NOT_FOUND", "message": "not here"}},
    )
    with pytest.raises(ObjectNotFound):
        await client.get("phip://acme.example/parts/missing")


async def test_push_chain_conflict(httpx_mock, client: AsyncClient) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/push/parts/widget-001",
        method="POST",
        status_code=409,
        json={
            "error": {
                "code": "CHAIN_CONFLICT",
                "message": "stale",
                "details": {"current_head": "sha256:abc"},
            }
        },
    )
    with pytest.raises(ChainConflict) as exc:
        await client.push(
            "phip://acme.example/parts/widget-001",
            {"phip_id": "phip://acme.example/parts/widget-001", "type": "note"},
        )
    assert exc.value.current_head == "sha256:abc"


async def test_invalid_transition_typed(httpx_mock, client: AsyncClient) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/push/parts/x",
        method="POST",
        status_code=422,
        json={"error": {"code": "INVALID_TRANSITION", "message": "nope"}},
    )
    with pytest.raises(InvalidTransition):
        await client.push(
            "phip://acme.example/parts/x",
            {"phip_id": "phip://acme.example/parts/x", "type": "state_transition"},
        )


async def test_authorization_header(httpx_mock) -> None:
    client = AsyncClient(
        base_url="https://acme.example",
        authority="acme.example",
        capability_token="abc123",
    )
    try:
        httpx_mock.add_response(
            url="https://acme.example/.well-known/phip/resolve/parts/x",
            json={"phip_id": "phip://acme.example/parts/x"},
            match_headers={"Authorization": "PhIP-Capability abc123"},
        )
        await client.get("phip://acme.example/parts/x")
    finally:
        await client.aclose()

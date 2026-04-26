"""Synchronous Client unit tests with mocked HTTP transport."""

from __future__ import annotations

import pytest

from phip import (
    ChainConflict,
    Client,
    InvalidEvent,
    InvalidTransition,
    ObjectExists,
    ObjectNotFound,
    PhipError,
)


@pytest.fixture
def client() -> Client:
    return Client(base_url="https://acme.example", authority="acme.example")


def test_get_returns_object(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/resolve/parts/widget-001",
        json={"phip_id": "phip://acme.example/parts/widget-001", "state": "stock"},
    )
    obj = client.get("phip://acme.example/parts/widget-001")
    assert obj["state"] == "stock"


def test_get_404_raises_object_not_found(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/resolve/parts/missing",
        status_code=404,
        json={"error": {"code": "OBJECT_NOT_FOUND", "message": "not here"}},
    )
    with pytest.raises(ObjectNotFound) as exc:
        client.get("phip://acme.example/parts/missing")
    assert exc.value.code == "OBJECT_NOT_FOUND"
    assert exc.value.status == 404


def test_create_dispatches_namespace_from_event(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/objects/parts",
        method="POST",
        status_code=201,
        json={"phip_id": "phip://acme.example/parts/x", "state": "concept"},
    )
    event = {
        "phip_id": "phip://acme.example/parts/x",
        "type": "created",
        "payload": {"object_type": "component", "state": "concept"},
    }
    obj = client.create(event)
    assert obj["state"] == "concept"


def test_push_chain_conflict_carries_current_head(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/push/parts/widget-001",
        method="POST",
        status_code=409,
        json={
            "error": {
                "code": "CHAIN_CONFLICT",
                "message": "stale",
                "details": {"current_head": "sha256:abc123"},
            }
        },
    )
    with pytest.raises(ChainConflict) as exc:
        client.push(
            "phip://acme.example/parts/widget-001",
            {"phip_id": "phip://acme.example/parts/widget-001", "type": "note"},
        )
    assert exc.value.current_head == "sha256:abc123"


def test_object_exists_on_duplicate_create(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/objects/parts",
        method="POST",
        status_code=409,
        json={"error": {"code": "OBJECT_EXISTS", "message": "already there"}},
    )
    with pytest.raises(ObjectExists):
        client.create(
            {"phip_id": "phip://acme.example/parts/x", "type": "created", "payload": {}}
        )


def test_invalid_transition_typed(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/push/parts/x",
        method="POST",
        status_code=422,
        json={"error": {"code": "INVALID_TRANSITION", "message": "nope"}},
    )
    with pytest.raises(InvalidTransition):
        client.push(
            "phip://acme.example/parts/x",
            {"phip_id": "phip://acme.example/parts/x", "type": "state_transition"},
        )


def test_history_pagination_params(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/history/parts/widget-001?limit=50&order=desc&cursor=abc",
        json={"phip_id": "phip://acme.example/parts/widget-001", "history_length": 200, "events": [], "next_cursor": None},
    )
    page = client.history(
        "phip://acme.example/parts/widget-001", limit=50, order="desc", cursor="abc"
    )
    assert page["history_length"] == 200


def test_query_post(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/query/parts",
        method="POST",
        json={"matches": ["phip://acme.example/parts/widget-001"], "total": 1, "next_cursor": None},
    )
    result = client.query("parts", {"filters": {"object_type": "component"}})
    assert result["matches"] == ["phip://acme.example/parts/widget-001"]


def test_meta_returns_empty_dict_on_404(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/meta",
        status_code=404,
        json={"error": {"code": "OBJECT_NOT_FOUND", "message": "not published"}},
    )
    assert client.meta() == {}


def test_meta_returns_document(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/meta",
        json={
            "protocol_version": "0.1.0-draft",
            "authority": "acme.example",
            "namespaces": ["parts"],
        },
    )
    meta = client.meta()
    assert meta["authority"] == "acme.example"


def test_authorization_header_added_when_token_set(httpx_mock) -> None:
    client = Client(
        base_url="https://acme.example",
        authority="acme.example",
        capability_token="abc123",
    )
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/resolve/parts/x",
        json={"phip_id": "phip://acme.example/parts/x"},
        match_headers={"Authorization": "PhIP-Capability abc123"},
    )
    client.get("phip://acme.example/parts/x")


def test_per_call_token_overrides_default(httpx_mock) -> None:
    client = Client(
        base_url="https://acme.example",
        authority="acme.example",
        capability_token="default",
    )
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/resolve/parts/x",
        json={"phip_id": "phip://acme.example/parts/x"},
        match_headers={"Authorization": "PhIP-Capability override"},
    )
    client.get("phip://acme.example/parts/x", capability_token="override")


def test_unknown_authority_phip_id_rejected(client: Client) -> None:
    with pytest.raises(ValueError):
        client.get("phip://other.example/parts/x")


def test_batch_207_accepted(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/objects/parts/batch",
        method="POST",
        status_code=207,
        json={
            "results": [
                {"status": "created", "phip_id": "phip://acme.example/parts/a"},
                {"status": "error", "phip_id": "phip://acme.example/parts/b",
                 "error": {"code": "OBJECT_EXISTS", "message": "dup"}},
            ],
            "summary": {"total": 2, "succeeded": 1, "failed": 1},
        },
    )
    result = client.batch_create(
        "parts",
        [
            {"phip_id": "phip://acme.example/parts/a", "type": "created", "payload": {}},
            {"phip_id": "phip://acme.example/parts/b", "type": "created", "payload": {}},
        ],
    )
    assert result["summary"]["failed"] == 1


def test_unknown_error_code_falls_back_to_phip_error(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/resolve/parts/x",
        status_code=418,  # I'm a teapot
        json={"error": {"code": "WHATEVER_NEW_CODE", "message": "from the future"}},
    )
    with pytest.raises(PhipError) as exc:
        client.get("phip://acme.example/parts/x")
    assert exc.value.code == "WHATEVER_NEW_CODE"
    assert exc.value.status == 418


def test_invalid_event_typed_422(httpx_mock, client: Client) -> None:
    httpx_mock.add_response(
        url="https://acme.example/.well-known/phip/objects/parts",
        method="POST",
        status_code=422,
        json={"error": {"code": "INVALID_EVENT", "message": "bad"}},
    )
    with pytest.raises(InvalidEvent):
        client.create(
            {"phip_id": "phip://acme.example/parts/x", "type": "created", "payload": {}}
        )

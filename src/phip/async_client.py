"""Asynchronous PhIP HTTP client.

Mirrors ``Client`` from ``phip.client`` with an async surface. Uses
``httpx.AsyncClient`` under the hood. Suitable for FastAPI / Starlette /
aiohttp servers and other asyncio-based code.

Public surface is identical to the sync client; every method is
``async def``. Construction accepts the same keyword arguments.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx

from phip._version import PROTOCOL_VERSION
from phip.client import _quote_path
from phip.errors import PhipError, from_envelope

DEFAULT_TIMEOUT = 30.0
DEFAULT_USER_AGENT = f"phip-py/{PROTOCOL_VERSION}"


class AsyncClient:
    """Asynchronous PhIP client. See ``phip.Client`` for non-async usage."""

    def __init__(
        self,
        *,
        base_url: str,
        authority: str | None = None,
        capability_token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        follow_redirects: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.authority = authority or httpx.URL(base_url).host
        self.capability_token = capability_token
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            follow_redirects=follow_redirects,
            headers={"User-Agent": user_agent},
        )

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ── high-level operations ─────────────────────────────────────

    async def get(
        self, phip_id: str, *, capability_token: str | None = None
    ) -> dict[str, Any]:
        ns, local_id = self._split_local(phip_id)
        path = f"/.well-known/phip/resolve/{quote(ns)}/{_quote_path(local_id)}"
        return await self._request("GET", path, headers=self._auth_headers(capability_token))

    async def history(
        self,
        phip_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        order: str = "asc",
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        ns, local_id = self._split_local(phip_id)
        params: dict[str, str] = {"limit": str(limit), "order": order}
        if cursor is not None:
            params["cursor"] = cursor
        path = f"/.well-known/phip/history/{quote(ns)}/{_quote_path(local_id)}"
        return await self._request(
            "GET", path, params=params, headers=self._auth_headers(capability_token)
        )

    async def query(
        self,
        namespace: str,
        query: dict[str, Any],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        path = f"/.well-known/phip/query/{quote(namespace)}"
        return await self._request(
            "POST", path, json_body=query, headers=self._auth_headers(capability_token)
        )

    async def create(
        self, event: dict[str, Any], *, capability_token: str | None = None
    ) -> dict[str, Any]:
        ns = self._namespace_of(event)
        path = f"/.well-known/phip/objects/{quote(ns)}"
        return await self._request(
            "POST", path, json_body=event, headers=self._auth_headers(capability_token)
        )

    async def push(
        self,
        phip_id: str,
        event: dict[str, Any],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        ns, local_id = self._split_local(phip_id)
        path = f"/.well-known/phip/push/{quote(ns)}/{_quote_path(local_id)}"
        return await self._request(
            "POST", path, json_body=event, headers=self._auth_headers(capability_token)
        )

    async def batch_create(
        self,
        namespace: str,
        events: list[dict[str, Any]],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        path = f"/.well-known/phip/objects/{quote(namespace)}/batch"
        return await self._request(
            "POST",
            path,
            json_body={"events": events},
            headers=self._auth_headers(capability_token),
            allowed_status={200, 207, 422},
        )

    async def batch_push(
        self,
        namespace: str,
        events: list[dict[str, Any]],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        path = f"/.well-known/phip/push/{quote(namespace)}/batch"
        return await self._request(
            "POST",
            path,
            json_body={"events": events},
            headers=self._auth_headers(capability_token),
            allowed_status={200, 207, 422},
        )

    async def meta(self) -> dict[str, Any]:
        try:
            return await self._request("GET", "/.well-known/phip/meta")
        except PhipError as e:
            if e.status == 404:
                return {}
            raise

    # ── internals ─────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        allowed_status: set[int] | None = None,
    ) -> Any:
        try:
            response = await self._client.request(
                method, path, params=params, json=json_body, headers=headers
            )
        except httpx.RequestError as e:
            raise PhipError(f"transport error: {e}") from e
        return self._handle_response(response, allowed_status=allowed_status)

    @staticmethod
    def _handle_response(
        response: httpx.Response, *, allowed_status: set[int] | None = None
    ) -> Any:
        ok_statuses = allowed_status if allowed_status is not None else {200, 201}
        if response.status_code in ok_statuses:
            if not response.content:
                return None
            try:
                return response.json()
            except json.JSONDecodeError as e:
                raise PhipError(f"resolver returned non-JSON ({response.status_code}): {e}") from e
        try:
            envelope = response.json() if response.content else {}
        except json.JSONDecodeError:
            envelope = {}
        err = from_envelope(envelope, status=response.status_code)
        if not isinstance(envelope, dict) or "error" not in envelope:
            err = PhipError(
                f"unexpected status {response.status_code}: {response.text[:200]}"
            )
            err.status = response.status_code
        raise err

    def _auth_headers(self, override: str | None) -> dict[str, str] | None:
        token = override if override is not None else self.capability_token
        if token is None:
            return None
        return {"Authorization": f"PhIP-Capability {token}"}

    def _split_local(self, phip_id: str) -> tuple[str, str]:
        prefix = f"phip://{self.authority}/"
        if not phip_id.startswith(prefix):
            raise ValueError(
                f"phip_id {phip_id!r} does not match client authority {self.authority!r}"
            )
        rest = phip_id[len(prefix):]
        ns, _, local = rest.partition("/")
        if not ns or not local:
            raise ValueError(f"phip_id {phip_id!r} missing namespace or local-id")
        return ns, local

    def _namespace_of(self, event: dict[str, Any]) -> str:
        phip_id = event.get("phip_id")
        if not isinstance(phip_id, str):
            raise ValueError("event.phip_id missing or not a string")
        ns, _ = self._split_local(phip_id)
        return ns

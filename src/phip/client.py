"""Synchronous PhIP HTTP client.

Wraps the standard ``/.well-known/phip/*`` operations (CREATE, GET,
PUSH, QUERY, history, batch, /meta) with typed errors and a thin
ergonomic surface. Production apps that need async should use
``AsyncClient`` from ``phip.async_client``; both share the same
public method set.

Authentication: pass ``capability_token`` (transport-encoded) on
construction or per-call to populate the ``Authorization:
PhIP-Capability ...`` header. Server-issued capability tokens are
opaque to this client; mint them with ``phip.mint_token``.

Error handling: all 4xx/5xx responses are converted to typed
``PhipError`` subclasses (one per spec error code) — see
``phip.errors``.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx

from phip._version import PROTOCOL_VERSION
from phip.errors import PhipError, from_envelope

DEFAULT_TIMEOUT = 30.0
DEFAULT_USER_AGENT = f"phip-py/{PROTOCOL_VERSION}"


class Client:
    """Synchronous PhIP client.

    Construction:

        client = Client(base_url="https://acme.example", authority="acme.example")

    Optional parameters:

    * ``capability_token`` — base64url-encoded token for the
      ``Authorization`` header. Per-call override available.
    * ``timeout`` — request timeout in seconds (default 30).
    * ``transport`` — inject your own ``httpx.BaseTransport`` for
      tests / advanced HTTP setups.
    * ``user_agent`` — override the default ``User-Agent``.
    * ``follow_redirects`` — defaults to True; set False to inspect
      delegation/transfer redirects yourself.
    """

    def __init__(
        self,
        *,
        base_url: str,
        authority: str | None = None,
        capability_token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        follow_redirects: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        # Authority defaults to the URL host (matching the conformance
        # suite's behavior). Override when proxies / port forwarding
        # decouple network address from PhIP authority.
        self.authority = authority or httpx.URL(base_url).host
        self.capability_token = capability_token
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            follow_redirects=follow_redirects,
            headers={"User-Agent": user_agent},
        )

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # ── high-level operations ─────────────────────────────────────

    def get(self, phip_id: str, *, capability_token: str | None = None) -> dict[str, Any]:
        """GET an object by PhIP URI. Returns the projected state."""
        ns, local_id = self._split_local(phip_id)
        path = f"/.well-known/phip/resolve/{quote(ns)}/{_quote_path(local_id)}"
        return self._request("GET", path, headers=self._auth_headers(capability_token))

    def history(
        self,
        phip_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        order: str = "asc",
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        """GET an object's history (paginated). Returns
        ``{phip_id, history_length, events, next_cursor}``."""
        ns, local_id = self._split_local(phip_id)
        params: dict[str, str] = {"limit": str(limit), "order": order}
        if cursor is not None:
            params["cursor"] = cursor
        path = f"/.well-known/phip/history/{quote(ns)}/{_quote_path(local_id)}"
        return self._request(
            "GET", path, params=params, headers=self._auth_headers(capability_token)
        )

    def get_topology(
        self,
        phip_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        """GET an object's history in topology mode (§11.5.6).

        Returns the topology response envelope:
        ``{phip_id, page_length, disclosure, topology, topology_signature,
        next_cursor}``.

        The response is signed and chain-walkable, but this method does
        NOT verify it for you. Callers MUST pass the response to
        ``phip.topology.verify_topology_response(response, public_key)``
        (or ``verify_first_page`` if this is the first page) before
        trusting any field. For paginated reads, also call
        ``phip.topology.stitch_pages`` across the page list to confirm
        the inter-page chain link.

        Topology is always returned in ascending chain order (§11.5.6.5);
        the ``?order`` parameter from ``history()`` is intentionally
        omitted here.
        """
        ns, local_id = self._split_local(phip_id)
        params: dict[str, str] = {"limit": str(limit), "disclosure": "topology"}
        if cursor is not None:
            params["cursor"] = cursor
        path = f"/.well-known/phip/history/{quote(ns)}/{_quote_path(local_id)}"
        return self._request(
            "GET", path, params=params, headers=self._auth_headers(capability_token)
        )

    def query(
        self,
        namespace: str,
        query: dict[str, Any],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        """POST a QUERY against a namespace."""
        path = f"/.well-known/phip/query/{quote(namespace)}"
        return self._request(
            "POST", path, json_body=query, headers=self._auth_headers(capability_token)
        )

    def create(
        self, event: dict[str, Any], *, capability_token: str | None = None
    ) -> dict[str, Any]:
        """CREATE a new object via a signed `created` event.

        The event's ``phip_id`` namespace drives the endpoint path.
        Returns the resolver's projection of the newly created object.
        """
        ns = self._namespace_of(event)
        path = f"/.well-known/phip/objects/{quote(ns)}"
        return self._request(
            "POST", path, json_body=event, headers=self._auth_headers(capability_token)
        )

    def push(
        self,
        phip_id: str,
        event: dict[str, Any],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        """PUSH an event to an existing object. Returns the appended event."""
        ns, local_id = self._split_local(phip_id)
        path = f"/.well-known/phip/push/{quote(ns)}/{_quote_path(local_id)}"
        return self._request(
            "POST", path, json_body=event, headers=self._auth_headers(capability_token)
        )

    def batch_create(
        self,
        namespace: str,
        events: list[dict[str, Any]],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        """Batch CREATE (§12.5). Returns ``{results, summary}``."""
        path = f"/.well-known/phip/objects/{quote(namespace)}/batch"
        return self._request(
            "POST",
            path,
            json_body={"events": events},
            headers=self._auth_headers(capability_token),
            allowed_status={200, 207, 422},
        )

    def batch_push(
        self,
        namespace: str,
        events: list[dict[str, Any]],
        *,
        capability_token: str | None = None,
    ) -> dict[str, Any]:
        """Batch PUSH (§12.5)."""
        path = f"/.well-known/phip/push/{quote(namespace)}/batch"
        return self._request(
            "POST",
            path,
            json_body={"events": events},
            headers=self._auth_headers(capability_token),
            allowed_status={200, 207, 422},
        )

    def meta(self) -> dict[str, Any]:
        """Fetch the resolver's `/meta` document. Returns ``{}`` if the
        resolver does not publish one (404)."""
        try:
            return self._request("GET", "/.well-known/phip/meta")
        except PhipError as e:
            if e.status == 404:
                return {}
            raise

    # ── internals ─────────────────────────────────────────────────

    def _request(
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
            response = self._client.request(
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

        # Try to parse the standard error envelope; fall back to a
        # generic PhipError if the body isn't shaped right.
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
        """Split a `phip://{auth}/{ns}/{local-id...}` into (ns, local-id-with-subpath)."""
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


def _quote_path(local_id: str) -> str:
    """URL-quote a local-id, preserving ``/`` separators for sub-paths."""
    return "/".join(quote(seg, safe="") for seg in local_id.split("/"))

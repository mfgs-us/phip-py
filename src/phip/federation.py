"""Federation client — fetch foreign authorities' /meta and key resources.

When a token's signing key lives at another authority, a verifier needs
to resolve that key by GETting the corresponding actor object. This
module provides an async ``FederationClient`` that does so safely:

* HTTPS by default (HTTP requires explicit ``allow_http=True``)
* Pre-resolves the target hostname via DNS and rejects all returned
  addresses if any are private / loopback / link-local (SSRF defense
  + multi-A bypass defense)
* Caps response body size at 1 MiB, enforced mid-stream
* Clamps server-supplied ``Cache-Control: max-age`` at 24 hours
* 10s request timeout

This is the Python port of ``reference/src/federation.js`` from the
spec repo. **Known v0.1 gap:** the resolved IP is NOT pinned for the
actual connection (httpx re-resolves), so a sufficiently fast attacker
who controls DNS can in principle race a rebind between the check and
the connect. Full pinning is a v0.2 hardening; the SSRF block remains
the larger win and the rebind window is narrow on most stacks.

**Caller responsibilities not enforced here:**

* ``resolve_key`` validates ``state == "active"`` but NOT the JWK's
  ``not_before`` / ``not_after`` window. Callers verifying a token
  MUST also check the signing key was within its validity window at
  the token's claimed signing time (see Section 11.2.2).
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from phip.uri import parse_uri

DEFAULT_TTL_SECONDS = 5 * 60
MAX_TTL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1 * 1024 * 1024


UrlBuilder = Callable[[str, str], str]
"""``url_builder(authority, path) -> str``. Tests inject this to map
spec-compliant authority names (e.g. 'alice.local') to localhost ports.
The default builder produces ``https://{authority}{path}`` (or
``http://`` when ``allow_http=True``)."""


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    value: Any
    expires_at: float


@dataclass
class FederationClient:
    """Async outbound HTTPS client with SSRF defense + cache.

    Attributes:
        allow_http: Allow plain HTTP for tests / dev. Production: False.
        allow_private_addresses: Permit private/loopback/link-local
            destinations. Defaults to ``allow_http`` for test convenience.
        url_builder: Override URL construction (test hook).
        timeout_seconds: Per-request total timeout.
    """

    allow_http: bool = False
    allow_private_addresses: bool | None = None
    url_builder: UrlBuilder | None = None
    timeout_seconds: float = REQUEST_TIMEOUT_SECONDS
    _cache: dict[str, _CacheEntry] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.allow_private_addresses is None:
            object.__setattr__(self, "allow_private_addresses", self.allow_http)

    # ── public API ────────────────────────────────────────────────

    async def fetch_meta(self, authority: str) -> dict[str, Any]:
        """GET ``https://{authority}/.well-known/phip/meta``."""
        url = self._build_url(authority, "/.well-known/phip/meta")
        return await self._cached_json_get(url)

    async def fetch_key_resource(self, key_id: str) -> dict[str, Any]:
        """GET the actor object identified by `key_id`."""
        parsed = parse_uri(key_id)
        local_path = "/".join([parsed.local_id, *parsed.sub_path])
        url = self._build_url(
            parsed.authority,
            f"/.well-known/phip/resolve/{parsed.namespace}/{local_path}",
        )
        return await self._cached_json_get(url)

    async def resolve_key(self, key_id: str) -> dict[str, str]:
        """Resolve a `key_id` PhIP URI to its JWK (`phip:keys`) material.

        Raises ``ValueError`` if the target isn't an active actor or
        doesn't carry well-formed Ed25519 JWK material.
        """
        obj = await self.fetch_key_resource(key_id)
        if not isinstance(obj, dict) or obj.get("object_type") != "actor":
            raise ValueError(f"foreign key target is not an actor: {key_id}")
        if obj.get("state") != "active":
            raise ValueError(f"foreign key actor is not active: {key_id}")
        attrs = obj.get("attributes") or {}
        jwk = attrs.get("phip:keys")
        if (
            not isinstance(jwk, dict)
            or jwk.get("kty") != "OKP"
            or jwk.get("crv") != "Ed25519"
            or not jwk.get("x")
        ):
            raise ValueError(f"foreign key actor missing phip:keys material: {key_id}")
        return jwk

    def clear_cache(self) -> None:
        """Drop all cached entries. Test/dev hook."""
        self._cache.clear()

    # ── internals ─────────────────────────────────────────────────

    def _build_url(self, authority: str, path: str) -> str:
        if self.url_builder is not None:
            return self.url_builder(authority, path)
        scheme = "http" if self.allow_http else "https"
        return f"{scheme}://{authority}{path}"

    async def _cached_json_get(self, url: str) -> Any:  # noqa: ANN401  # foreign JSON
        now = time.monotonic()
        cached = self._cache.get(url)
        if cached is not None and cached.expires_at > now:
            return cached.value
        body, headers = await self._json_get(url)
        ttl = _clamp_ttl(_parse_max_age(headers))
        self._cache[url] = _CacheEntry(value=body, expires_at=now + ttl)
        return body

    async def _json_get(self, url: str) -> tuple[Any, dict[str, str]]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {parsed.scheme}")
        if parsed.scheme != "https" and not self.allow_http:
            raise ValueError("refusing to fetch over HTTP")

        # DNS pre-resolution + private-IP block. Use ALL returned
        # addresses; reject if ANY are private (defeats multi-A bypass).
        host = parsed.hostname
        if not host:
            raise ValueError(f"missing hostname in URL: {url}")
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
        except OSError as e:
            raise ValueError(f"DNS resolution failed for federation target: {e}") from e
        if not infos:
            raise ValueError("DNS resolution returned no addresses")
        addresses = list({info[4][0] for info in infos})
        if not self.allow_private_addresses:
            for addr in addresses:
                if _is_private_address(addr):
                    raise ValueError(
                        "refusing to connect to private/loopback/link-local address"
                    )

        # Stream the response so the 1 MiB cap fires mid-flight rather
        # than after a multi-GB body has been buffered into memory. We
        # already DNS-resolved + private-IP-checked above; full DNS
        # rebinding pinning (passing `host=<resolved-ip>` to httpx) is a
        # v0.2 hardening — see the module docstring for the v0.1 stance.
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            try:
                async with client.stream("GET", url) as response:
                    if response.status_code != 200:
                        raise ValueError(
                            f"federation GET returned status {response.status_code}"
                        )
                    headers = dict(response.headers)
                    body = await self._read_capped(response)
            except httpx.RequestError as e:
                raise ValueError("federation request failed") from e
            try:
                import json as _json

                return _json.loads(body), headers
            except ValueError as e:
                raise ValueError("federation response was not valid JSON") from e

    @staticmethod
    async def _read_capped(response: httpx.Response) -> bytes:
        """Drain the response body, rejecting once MAX_RESPONSE_BYTES bytes
        have arrived. The check happens DURING streaming, so an adversarial
        multi-GB body is rejected before it's buffered."""
        buf = bytearray()
        async for chunk in response.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > MAX_RESPONSE_BYTES:
                raise ValueError("federation response exceeded size cap")
        return bytes(buf)


# ── helpers ───────────────────────────────────────────────────────


def _parse_max_age(headers: dict[str, str]) -> int:
    """Extract `Cache-Control: max-age=N` in seconds. 0 if absent."""
    cc = headers.get("cache-control") or headers.get("Cache-Control") or ""
    m = re.search(r"max-age\s*=\s*(\d+)", cc, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def _clamp_ttl(seconds: int) -> int:
    """Bound a TTL to ``[DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS]``."""
    if seconds <= 0:
        return DEFAULT_TTL_SECONDS
    return min(seconds, MAX_TTL_SECONDS)


def is_private_address(addr: str) -> bool:
    """Public re-export of the private-IP check (used by tests)."""
    return _is_private_address(addr)


def _is_private_address(addr: str) -> bool:
    """Conservative check for IPv4 + IPv6 private/loopback/link-local
    ranges. When in doubt, treat as private (fail closed)."""
    if not isinstance(addr, str) or not addr:
        return True
    # IPv6 zone suffix (`fe80::1%eth0`) — strip it for parsing.
    if "%" in addr:
        addr = addr.split("%", 1)[0]
    try:
        family = socket.AF_INET if "." in addr and ":" not in addr else socket.AF_INET6
        socket.inet_pton(family, addr)
    except (OSError, ValueError):
        return True
    if family == socket.AF_INET:
        return _is_private_v4(addr)
    return _is_private_v6(addr.lower())


def _is_private_v4(addr: str) -> bool:
    parts = addr.split(".")
    try:
        a, b = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return True
    if a in (0, 127):  # this network, loopback
        return True
    if a == 10:  # RFC1918
        return True
    if a == 100 and 64 <= b <= 127:  # CGNAT
        return True
    if a == 169 and b == 254:  # link-local
        return True
    if a == 172 and 16 <= b <= 31:  # RFC1918
        return True
    if a == 192 and b == 168:  # RFC1918
        return True
    return a >= 224  # multicast / reserved / broadcast


def _is_private_v6(addr: str) -> bool:
    if addr in ("::1", "::"):
        return True
    # IPv4-mapped: ::ffff:1.2.3.4
    m = re.match(r"^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", addr)
    if m:
        return _is_private_v4(m.group(1))
    # Link-local fe80::/10 — first hextet 4 chars in canonical form.
    if re.match(r"^fe[89ab][0-9a-f]:", addr):
        return True
    # Unique local fc00::/7 — first hextet exactly 4 chars.
    if re.match(r"^f[cd][0-9a-f][0-9a-f]:", addr):
        return True
    # Multicast ff00::/8.
    return bool(re.match(r"^ff[0-9a-f][0-9a-f]:", addr))

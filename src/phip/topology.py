"""Topology disclosure — building, signing, and verifying responses (§11.5.6).

Topology disclosure is the optional read mode that exposes an object's
chain shape (event IDs, types, timestamps, ``previous_hash`` links, and
per-entry ``event_hash``) without payloads, actors, or per-event
signatures. The whole envelope is signed once by the resolver's authority
key.

This module covers:

* ``topology_entry_for(event)`` — project a full event into its five
  topology fields
* ``build_topology_envelope(...)`` — assemble + sign a topology response
* ``verify_topology_response(...)`` — signature + chain walk in one call
* ``walk_topology_chain(entries)`` — chain-link check, returned as the
  index of the first break or ``None``
* ``stitch_pages(pages)`` — concatenate paginated topology slices,
  asserting the inter-page link
"""

from __future__ import annotations

from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from phip.canonicalize import canonical_bytes
from phip.crypto import sign, verify
from phip.events import Event, hash_event
from phip.errors import InvalidEvent, InvalidSignature

TopologyEntry = dict[str, Any]
"""One entry in a topology response: event_id, type, timestamp,
previous_hash, event_hash."""

TopologyResponse = dict[str, Any]
"""The full topology response envelope: phip_id, page_length, disclosure,
topology, topology_signature, next_cursor."""

DISCLOSURE_TOPOLOGY = "topology"
TOPOLOGY_FIELDS_SIGNED: tuple[str, ...] = (
    "disclosure",
    "page_length",
    "phip_id",
    "topology",
)
"""The four canonical fields the topology_signature covers (§11.5.6.4)."""


# ── projection ────────────────────────────────────────────────────────


def topology_entry_for(event: Event) -> TopologyEntry:
    """Project a full event into its five topology fields.

    Drops payload, actor, signature. The ``event_hash`` is computed
    over the JCS of the original event (§10.3) and equals what the
    NEXT event would carry as ``previous_hash``.
    """
    return {
        "event_id": event["event_id"],
        "type": event["type"],
        "timestamp": event["timestamp"],
        "previous_hash": event["previous_hash"],
        "event_hash": hash_event(event),
    }


# ── build + sign ──────────────────────────────────────────────────────


def _canonical_signed_object(
    phip_id: str, topology: list[TopologyEntry]
) -> dict[str, Any]:
    """Return the four-field canonical object whose JCS bytes are signed."""
    return {
        "disclosure": DISCLOSURE_TOPOLOGY,
        "page_length": len(topology),
        "phip_id": phip_id,
        "topology": topology,
    }


def build_topology_envelope(
    *,
    phip_id: str,
    topology: list[TopologyEntry],
    private_key: Ed25519PrivateKey,
    key_id: str,
    next_cursor: str | None = None,
) -> TopologyResponse:
    """Build and sign a topology response envelope (§11.5.6.4).

    Topology MUST be in ascending chain order (oldest first; genesis at
    index 0 of the first page). The caller is responsible for ordering;
    this function does not re-sort.
    """
    canonical = _canonical_signed_object(phip_id, topology)
    sig_value = sign(private_key, canonical_bytes(canonical))
    return {
        "phip_id": phip_id,
        "page_length": len(topology),
        "disclosure": DISCLOSURE_TOPOLOGY,
        "topology": topology,
        "topology_signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": sig_value,
        },
        "next_cursor": next_cursor,
    }


# ── verify ────────────────────────────────────────────────────────────


def walk_topology_chain(topology: list[TopologyEntry]) -> int | None:
    """Walk the chain links within a page. Returns the 1-based index of
    the first break, or None if the chain is fully consistent.

    For entry N > 0, ``entry[N].previous_hash`` MUST equal
    ``entry[N-1].event_hash``. The first entry's ``previous_hash`` is
    NOT checked — the caller decides whether it expects ``"genesis"``
    (first page) or the previous page's last ``event_hash``
    (subsequent pages).
    """
    for i in range(1, len(topology)):
        if topology[i].get("previous_hash") != topology[i - 1].get("event_hash"):
            return i
    return None


def verify_topology_response(
    response: TopologyResponse,
    public_key: Ed25519PublicKey,
) -> None:
    """Verify a topology response envelope end-to-end (§11.5.6.4).

    Checks:

    1. ``topology_signature`` shape and presence.
    2. The signature verifies against ``public_key`` over the JCS
       canonicalization of EXACTLY ``{disclosure, page_length, phip_id,
       topology}`` (any other top-level fields are ignored).
    3. ``disclosure == "topology"``.
    4. ``page_length == len(topology)``.
    5. Within-page chain walk:
       ``entry[N].previous_hash == entry[N-1].event_hash``.

    Does NOT check that the first entry's ``previous_hash == "genesis"``
    — that's only true for the first page. Use ``verify_first_page``
    for that explicit check.

    Raises:
        InvalidSignature: signature verification failed.
        InvalidEvent: structural problem (wrong disclosure marker,
            page_length mismatch, chain-walk break).
    """
    if not isinstance(response, dict):
        raise InvalidEvent("topology response is not an object")

    sig = response.get("topology_signature")
    if not isinstance(sig, dict) or not isinstance(sig.get("value"), str):
        raise InvalidEvent("topology response missing or malformed topology_signature")

    disclosure = response.get("disclosure")
    if disclosure != DISCLOSURE_TOPOLOGY:
        raise InvalidEvent(
            f"topology response disclosure marker is {disclosure!r}, expected 'topology'",
        )

    topology = response.get("topology")
    if not isinstance(topology, list):
        raise InvalidEvent("topology field is not a list")

    page_length = response.get("page_length")
    if page_length != len(topology):
        raise InvalidEvent(
            f"page_length ({page_length}) does not match len(topology) ({len(topology)})",
        )

    canonical = _canonical_signed_object(response["phip_id"], topology)
    try:
        ok = verify(public_key, canonical_bytes(canonical), sig["value"])
    except ValueError as e:
        raise InvalidSignature(f"topology signature malformed: {e}") from e
    if not ok:
        raise InvalidSignature("topology signature verification failed")

    break_at = walk_topology_chain(topology)
    if break_at is not None:
        raise InvalidEvent(
            f"chain walk break at entry {break_at}: "
            f"previous_hash {topology[break_at].get('previous_hash')!r} != "
            f"prior event_hash {topology[break_at - 1].get('event_hash')!r}",
        )


def verify_first_page(response: TopologyResponse, public_key: Ed25519PublicKey) -> None:
    """Verify a topology response and additionally assert it is the first
    page (entry[0].previous_hash == "genesis")."""
    verify_topology_response(response, public_key)
    topology = response.get("topology") or []
    if topology and topology[0].get("previous_hash") != "genesis":
        raise InvalidEvent(
            "first-page topology must start with previous_hash='genesis'",
            {"got": topology[0].get("previous_hash")},
        )


def stitch_pages(pages: Iterable[TopologyResponse]) -> list[TopologyEntry]:
    """Concatenate paginated topology slices into a single list, asserting
    the inter-page chain link.

    Each page is assumed already verified via ``verify_topology_response``.
    Raises ``InvalidEvent`` if any page's first entry doesn't link to the
    previous page's last entry.
    """
    flat: list[TopologyEntry] = []
    prev_last_hash: str | None = None
    for i, page in enumerate(pages):
        topology = page.get("topology") or []
        if not topology:
            continue
        first_prev = topology[0].get("previous_hash")
        expected = "genesis" if i == 0 else prev_last_hash
        if first_prev != expected:
            raise InvalidEvent(
                f"inter-page link break at page {i}: first entry previous_hash "
                f"{first_prev!r} does not match prior page's last event_hash "
                f"{expected!r}",
            )
        flat.extend(topology)
        prev_last_hash = topology[-1].get("event_hash")
    return flat

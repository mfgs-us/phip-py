"""PhIP bundle pack / unpack / verify (§4.3.4).

A PhIP bundle is a signed archive of objects + their event histories +
key resources, used for offline distribution, mirror snapshots, and
air-gapped imports. The on-disk transport is a tar archive; this module
exposes both the in-memory dict form (matching the test vectors) and
helpers to pack/unpack to/from tar bytes.

Verification follows §4.3.4:

  1. Manifest signature verifies against the producer's key
  2. For each declared object, the chain hashes from genesis to the
     manifest's claimed ``history_head``
  3. Every event in the chain has a verifying signature against the
     resolved key actor
"""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import quote, unquote

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from phip.canonicalize import canonical_bytes
from phip.crypto import public_key_from_jwk, sign
from phip.errors import InvalidEvent, InvalidSignature, KeyNotFound, PhipError
from phip.events import Event, hash_event, verify_event

BUNDLE_VERSION = "1.0"


@dataclass
class Bundle:
    """In-memory PhIP bundle.

    Attributes:
        manifest: The signed manifest dict (matches `bundle-manifest.json`).
        objects: Per-object state projection, keyed by phip_id.
        history: Per-object event lists, keyed by phip_id.
        keys: Embedded key actor records, keyed by key actor phip_id.
    """

    manifest: dict[str, Any]
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    history: dict[str, list[Event]] = field(default_factory=dict)
    keys: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def created_by(self) -> str:
        return str(self.manifest["created_by"])

    @property
    def authority(self) -> str:
        return str(self.manifest["authority"])


def make_bundle(
    *,
    authority: str,
    created_by: str,
    created_at: str,
    objects: list[dict[str, Any]],
    history: dict[str, list[Event]],
    keys: dict[str, dict[str, Any]],
    private_key: Ed25519PrivateKey,
    key_id: str,
    snapshot_of: str | None = None,
) -> Bundle:
    """Construct + sign a PhIP bundle.

    Args:
        authority: Source authority name being bundled.
        created_by: PhIP URI of the actor producing the bundle.
        created_at: ISO 8601 timestamp.
        objects: Per-object state projections (one dict per phip_id).
            Each dict MUST include `phip_id`. The manifest's `objects[]`
            integrity entries are derived from `history` (last event
            per phip_id → history_head).
        history: Per-object event lists in chain order.
        keys: Embedded key actor records (typically the producer's key).
        private_key: Signing key (typically the producer's).
        key_id: PhIP URI for the manifest's `signature.key_id`.
        snapshot_of: Optional ISO 8601 timestamp marking the source
            authority's state-as-of for mirror snapshots.

    Returns the signed Bundle.
    """
    object_entries: list[dict[str, str]] = []
    for obj in objects:
        phip_id = obj["phip_id"]
        events = history.get(phip_id) or []
        if not events:
            raise PhipError(
                f"bundle: object {phip_id} has no events in history",
                {"phip_id": phip_id},
            )
        object_entries.append(
            {"phip_id": phip_id, "history_head": hash_event(events[-1])}
        )

    manifest_unsigned: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "created_at": created_at,
        "created_by": created_by,
        "authority": authority,
        "objects": object_entries,
    }
    if snapshot_of is not None:
        manifest_unsigned["snapshot_of"] = snapshot_of

    sig_value = sign(private_key, canonical_bytes(manifest_unsigned))
    manifest = {
        **manifest_unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": sig_value,
        },
    }

    obj_map = {o["phip_id"]: o for o in objects}
    return Bundle(manifest=manifest, objects=obj_map, history=dict(history), keys=dict(keys))


def verify_bundle(
    bundle: Bundle,
    *,
    producer_public_key: Ed25519PublicKey | None = None,
) -> None:
    """Verify a bundle end-to-end per §4.3.4.

    If ``producer_public_key`` is None, the producer's key actor is
    looked up in ``bundle.keys`` and its embedded JWK is used.

    Raises:
        InvalidSignature: manifest signature or any event signature fails
        InvalidEvent: a chain breaks (previous_hash mismatch) or the
            manifest's `history_head` doesn't match the actual chain head
        KeyNotFound: an event references a key not in `bundle.keys`
            (and not equal to the producer's key)
        PhipError: structural problems (missing manifest fields, etc.)
    """
    manifest = bundle.manifest
    sig = manifest.get("signature")
    if not isinstance(sig, dict) or not isinstance(sig.get("value"), str):
        raise PhipError("bundle manifest is unsigned")

    # Step 1: manifest signature.
    producer_key = producer_public_key or _embedded_key(bundle, manifest["created_by"])
    if producer_key is None:
        raise KeyNotFound(
            f"bundle producer key not in embedded keys: {manifest['created_by']}",
            {"key_id": manifest["created_by"]},
        )
    unsigned_manifest = {k: v for k, v in manifest.items() if k != "signature"}
    from phip.crypto import verify  # local import to avoid cycle

    if not verify(producer_key, canonical_bytes(unsigned_manifest), sig["value"]):
        raise InvalidSignature("bundle manifest signature verification failed")

    # Step 2 + 3: walk each object's chain.
    for entry in manifest["objects"]:
        phip_id = entry["phip_id"]
        expected_head = entry["history_head"]
        events = bundle.history.get(phip_id)
        if not events:
            raise InvalidEvent(
                f"bundle missing history for {phip_id}",
                {"phip_id": phip_id},
            )
        for i, event in enumerate(events):
            expected_prev = "genesis" if i == 0 else hash_event(events[i - 1])
            if event.get("previous_hash") != expected_prev:
                raise InvalidEvent(
                    f"chain break in {phip_id} at event[{i}]",
                    {"phip_id": phip_id, "index": i},
                )
            ev_sig = event.get("signature")
            if not isinstance(ev_sig, dict) or not isinstance(ev_sig.get("key_id"), str):
                raise InvalidEvent(
                    f"event[{i}] in {phip_id} missing signature",
                    {"phip_id": phip_id, "index": i},
                )
            event_key = _resolve_event_key(bundle, ev_sig["key_id"], producer_key)
            if event_key is None:
                raise KeyNotFound(
                    f"event[{i}] in {phip_id} references unknown key {ev_sig['key_id']}",
                    {"phip_id": phip_id, "index": i, "key_id": ev_sig["key_id"]},
                )
            if not verify_event(event, event_key):
                raise InvalidSignature(
                    f"event[{i}] in {phip_id} signature verification failed",
                    {"phip_id": phip_id, "index": i},
                )
        actual_head = hash_event(events[-1])
        if actual_head != expected_head:
            raise InvalidEvent(
                f"manifest history_head mismatch for {phip_id}",
                {"phip_id": phip_id, "expected": expected_head, "actual": actual_head},
            )


def _embedded_key(bundle: Bundle, key_uri: str) -> Ed25519PublicKey | None:
    """Look up an embedded key actor by full PhIP URI."""
    actor = bundle.keys.get(key_uri)
    if not actor:
        return None
    attrs = actor.get("attributes") or {}
    jwk = attrs.get("phip:keys")
    if not isinstance(jwk, dict):
        return None
    try:
        return public_key_from_jwk(jwk)
    except ValueError:
        return None


def _resolve_event_key(
    bundle: Bundle,
    key_id: str,
    producer_key: Ed25519PublicKey,
) -> Ed25519PublicKey | None:
    """Resolve an event's `signature.key_id` to a public key.

    Lookup order:

    1. Full PhIP URI match in `bundle.keys`.
    2. Bare keypair id (no `phip://` prefix) matching the tail of
       any embedded key's URI — bundles produced by the canonical
       generator use bare ids in event signatures, deferring to the
       manifest's producer-signed integrity envelope.
    3. The producer's key as a final fallback. Bundles are an
       integrity unit anchored at the manifest signature; an event
       whose key_id doesn't resolve is treated as signed by the
       producer (the actor who attested the bundle).

    Returns None only if `key_id` looks like a URI but isn't in the
    embedded keys (real cross-actor reference that can't be resolved).
    """
    # 1. Full URI match.
    found = _embedded_key(bundle, key_id)
    if found is not None:
        return found
    # 2. Bare id — match by tail of any embedded URI.
    if "://" not in key_id:
        for uri in bundle.keys:
            if uri.endswith("/" + key_id):
                return _embedded_key(bundle, uri)
        # No tail match → fall through to producer key.
        return producer_key
    # 3. URI form but not in bundle: treat as unresolved.
    return None


# ── tar pack / unpack ──────────────────────────────────────────────


def pack_bundle(bundle: Bundle) -> bytes:
    """Serialize a Bundle to a tar archive (the on-disk form).

    Layout per §4.3.4:

        manifest.json
        objects/{urlencoded-phip-id}.json
        history/{urlencoded-phip-id}.jsonl
        keys/{urlencoded-key-phip-id}.json
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        _add_file(tar, "manifest.json", canonical_bytes(bundle.manifest))
        for phip_id, obj in bundle.objects.items():
            _add_file(
                tar,
                f"objects/{quote(phip_id, safe='')}.json",
                canonical_bytes(obj),
            )
        for phip_id, events in bundle.history.items():
            jsonl = b"\n".join(canonical_bytes(e) for e in events) + b"\n"
            _add_file(tar, f"history/{quote(phip_id, safe='')}.jsonl", jsonl)
        for key_uri, actor in bundle.keys.items():
            _add_file(
                tar,
                f"keys/{quote(key_uri, safe='')}.json",
                canonical_bytes(actor),
            )
    return buf.getvalue()


def unpack_bundle(tar_bytes: bytes) -> Bundle:
    """Deserialize a tar archive into a Bundle.

    Raises ``PhipError`` if the manifest is missing or the archive is
    structurally bad. Does NOT verify signatures — call ``verify_bundle``
    on the result.
    """
    buf = io.BytesIO(tar_bytes)
    manifest: dict[str, Any] | None = None
    objects: dict[str, dict[str, Any]] = {}
    history: dict[str, list[Event]] = {}
    keys: dict[str, dict[str, Any]] = {}

    with tarfile.open(fileobj=buf, mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name
            file_obj = tar.extractfile(member)
            if file_obj is None:
                continue
            data = file_obj.read()
            if name == "manifest.json":
                manifest = json.loads(data.decode("utf-8"))
            elif name.startswith("objects/") and name.endswith(".json"):
                phip_id = unquote(name[len("objects/"):-len(".json")])
                objects[phip_id] = json.loads(data.decode("utf-8"))
            elif name.startswith("history/") and name.endswith(".jsonl"):
                phip_id = unquote(name[len("history/"):-len(".jsonl")])
                events = []
                for line in data.splitlines():
                    line = line.strip()
                    if line:
                        events.append(json.loads(line.decode("utf-8")))
                history[phip_id] = events
            elif name.startswith("keys/") and name.endswith(".json"):
                key_uri = unquote(name[len("keys/"):-len(".json")])
                keys[key_uri] = json.loads(data.decode("utf-8"))

    if manifest is None:
        raise PhipError("bundle archive missing manifest.json")
    return Bundle(manifest=manifest, objects=objects, history=history, keys=keys)


def _add_file(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def bundle_from_dict(d: dict[str, Any]) -> Bundle:
    """Construct a Bundle from the inline test-vector form
    (``{manifest, objects, history, keys}``)."""
    return Bundle(
        manifest=d["manifest"],
        objects=dict(d.get("objects") or {}),
        history={k: list(v) for k, v in (d.get("history") or {}).items()},
        keys=dict(d.get("keys") or {}),
    )


def iter_object_phip_ids(bundle: Bundle) -> Iterable[str]:
    """Iterate over every phip_id declared in the manifest's `objects[]`."""
    for entry in bundle.manifest.get("objects", []):
        yield str(entry["phip_id"])

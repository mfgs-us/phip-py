"""Build a 2-event chain, pack into a portable bundle, verify it offline.

Run:
    python examples/04_bundle_roundtrip.py
"""

import uuid
from datetime import datetime, timezone

from phip import (
    generate_keypair,
    hash_event,
    make_bundle,
    pack_bundle,
    sign_event,
    unpack_bundle,
    verify_bundle,
)


def main() -> None:
    kp = generate_keypair()
    authority = "tutorial.local"
    key_id = f"phip://{authority}/keys/alice"
    obj_uri = f"phip://{authority}/parts/widget-001"

    def now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    e1 = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": obj_uri,
            "type": "created",
            "timestamp": now(),
            "actor": key_id,
            "previous_hash": "genesis",
            "payload": {"object_type": "component", "state": "concept"},
        },
        kp.private,
        key_id,
    )
    e2 = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": obj_uri,
            "type": "measurement",
            "timestamp": now(),
            "actor": key_id,
            "previous_hash": hash_event(e1),
            "payload": {"metric": "x", "value": 1.0, "unit": "Hz", "as_of": now()},
        },
        kp.private,
        key_id,
    )

    bundle = make_bundle(
        authority=authority,
        created_by=key_id,
        created_at=now(),
        objects=[
            {
                "phip_id": obj_uri,
                "object_type": "component",
                "state": "concept",
                "head_hash": hash_event(e2),
                "history_length": 2,
            }
        ],
        history={obj_uri: [e1, e2]},
        keys={
            key_id: {
                "phip_id": key_id,
                "object_type": "actor",
                "state": "active",
                "attributes": {"phip:keys": kp.jwk},
            }
        },
        private_key=kp.private,
        key_id=key_id,
    )
    blob = pack_bundle(bundle)
    print(f"packed bundle: {len(blob)} bytes")

    loaded = unpack_bundle(blob)
    verify_bundle(loaded)
    print(f"verified offline: {len(loaded.objects)} objects, "
          f"{sum(len(e) for e in loaded.history.values())} events")


if __name__ == "__main__":
    main()

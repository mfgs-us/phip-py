"""End-to-end against a running phip-server.

Prereq: spin up phip-server first
    cd path/to/phip-server
    PHIP_AUTHORITY=tutorial.local docker compose up -d

Run:
    python examples/03_full_client.py
"""

import uuid
from datetime import datetime, timezone

from phip import Client, generate_keypair, hash_event, sign_event


AUTHORITY = "tutorial.local"
SERVER = "http://127.0.0.1:8080"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    kp = generate_keypair()
    key_id = f"phip://{AUTHORITY}/keys/alice"
    client = Client(base_url=SERVER, authority=AUTHORITY)

    print(f"meta: {client.meta()['authority']!r}")

    # Bootstrap actor (self-signed `created`).
    bootstrap = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": key_id,
            "type": "created",
            "timestamp": now(),
            "actor": key_id,
            "previous_hash": "genesis",
            "payload": {
                "object_type": "actor",
                "state": "active",
                "attributes": {
                    "phip:keys": {
                        **kp.jwk,
                        "not_before": "2020-01-01T00:00:00Z",
                        "not_after": "2099-01-01T00:00:00Z",
                    }
                },
            },
        },
        kp.private,
        key_id,
    )
    client.create(bootstrap)
    print(f"actor registered: {key_id}")

    # Create a component.
    obj_uri = f"phip://{AUTHORITY}/parts/widget-{uuid.uuid4().hex[:6]}"
    created = sign_event(
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
    client.create(created)
    print(f"created: {obj_uri}")

    # Push a measurement.
    measurement = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": obj_uri,
            "type": "measurement",
            "timestamp": now(),
            "actor": key_id,
            "previous_hash": hash_event(created),
            "payload": {
                "metric": "freq_response",
                "value": 2.5e6,
                "unit": "Hz",
                "as_of": now(),
            },
        },
        kp.private,
        key_id,
    )
    client.push(obj_uri, measurement)
    print("measurement pushed")

    # Read back.
    obj = client.get(obj_uri)
    print(f"server says state={obj['state']!r}, history_length={obj['history_length']}")
    for ev in client.history(obj_uri)["events"]:
        print(f"  {ev['timestamp']}  {ev['type']}")


if __name__ == "__main__":
    main()

"""Local-only: sign a created event, verify, tamper, watch verify fail.

Run:
    python examples/01_sign_and_verify.py
"""

import uuid
from datetime import datetime, timezone

from phip import generate_keypair, sign_event, verify_event


def main() -> None:
    kp = generate_keypair()
    authority = "tutorial.local"
    key_id = f"phip://{authority}/keys/alice"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    event = {
        "event_id": str(uuid.uuid4()),
        "phip_id": f"phip://{authority}/parts/widget-001",
        "type": "created",
        "timestamp": now,
        "actor": key_id,
        "previous_hash": "genesis",
        "payload": {"object_type": "component", "state": "concept"},
    }
    signed = sign_event(event, kp.private, key_id)
    print("signed event:")
    print("  key_id:", signed["signature"]["key_id"])
    print("  verify:", verify_event(signed, kp.public))

    # Tamper with the payload.
    signed["payload"]["state"] = "qualified"
    print("after tamper, verify:", verify_event(signed, kp.public))


if __name__ == "__main__":
    main()

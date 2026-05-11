"""Build a 3-event chain, walk it, prove the previous_hash linkage holds.

Run:
    python examples/02_chain_walk.py
"""

import uuid
from datetime import datetime, timezone

from phip import generate_keypair, hash_event, sign_event, verify_event


def main() -> None:
    kp = generate_keypair()
    authority = "tutorial.local"
    key_id = f"phip://{authority}/keys/alice"
    phip_id = f"phip://{authority}/parts/widget-001"

    def now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def make(type_: str, prev: str, payload: dict) -> dict:
        return sign_event(
            {
                "event_id": str(uuid.uuid4()),
                "phip_id": phip_id,
                "type": type_,
                "timestamp": now(),
                "actor": key_id,
                "previous_hash": prev,
                "payload": payload,
            },
            kp.private,
            key_id,
        )

    e1 = make("created", "genesis", {"object_type": "component", "state": "concept"})
    e2 = make("measurement", hash_event(e1), {"metric": "freq_response", "value": 2.5e6, "unit": "Hz", "as_of": now()})
    e3 = make("transitioned", hash_event(e2), {"to": "qualified"})

    chain = [e1, e2, e3]
    expected = "genesis"
    for i, ev in enumerate(chain):
        ok_link = ev["previous_hash"] == expected
        ok_sig = verify_event(ev, kp.public)
        print(f"  event {i}  type={ev['type']:<12}  link={ok_link}  sig={ok_sig}")
        expected = hash_event(ev)
    print("chain verified end-to-end:", expected[:14] + "...")


if __name__ == "__main__":
    main()

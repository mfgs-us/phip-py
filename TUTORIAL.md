# phip-py — Tutorial

Hands-on walkthrough of the Python client library. By the end of this
you'll have signed events, walked a hash chain, verified signatures
end-to-end, and built+packed a portable PhIP bundle — all in Python,
nothing else required.

> **Audience:** anyone integrating PhIP into a Python codebase. If you
> want a command-line tool instead of a library, see
> [phip-cli](https://github.com/mfgs-us/phip-cli).

## Setup

```bash
pip install git+https://github.com/mfgs-us/phip-py
# (or `pip install phip` once it's on PyPI)
```

## 1. Sign and verify your first event

PhIP events are JSON objects with a few required fields, signed by
Ed25519. The library handles the canonicalization (RFC 8785 JCS) so
the same bytes get signed everywhere.

```python
import uuid
from datetime import datetime, timezone
from phip import generate_keypair, sign_event, verify_event

# Generate a one-off keypair (for production: store these somewhere safe).
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
print(signed["signature"])
# {'algorithm': 'Ed25519', 'key_id': 'phip://tutorial.local/keys/alice', 'value': '...'}

# Verify it.
assert verify_event(signed, kp.public)

# Tamper with the payload, watch verification fail.
signed["payload"]["state"] = "qualified"
assert not verify_event(signed, kp.public)
```

That's the whole protocol primitive in 20 lines.

## 2. Hash chains

Each subsequent event on the same object references the previous
event's hash. Walking the chain proves nothing has been silently
edited.

```python
from phip import hash_event

# Continuing from above — make a measurement event linked to the created event.
created_hash = hash_event(signed)

measurement = sign_event(
    {
        "event_id": str(uuid.uuid4()),
        "phip_id": f"phip://{authority}/parts/widget-001",
        "type": "measurement",
        "timestamp": now,
        "actor": key_id,
        "previous_hash": created_hash,
        "payload": {
            "metric": "freq_response",
            "value": 2.5e6,
            "unit": "Hz",
            "as_of": now,
        },
    },
    kp.private,
    key_id,
)
print(measurement["previous_hash"], "->", hash_event(measurement))
```

If you flip even one bit in any prior event, every downstream
`previous_hash` no longer matches and the chain breaks.

## 3. Use the synchronous `Client` against a phip-server

`phip-py` ships sync and async clients. Both speak the same wire
format. Assuming you have phip-server running locally on port 8080
(see [phip-server's tutorial](https://github.com/mfgs-us/phip-server/blob/main/TUTORIAL.md)
for that):

```python
from phip import Client

client = Client(base_url="http://127.0.0.1:8080", authority="tutorial.local")

# Bootstrap your actor first (one-time, self-signed `created` event for the
# key). This is what the server uses to verify your subsequent pushes.
bootstrap = sign_event(
    {
        "event_id": str(uuid.uuid4()),
        "phip_id": key_id,
        "type": "created",
        "timestamp": now,
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

# Now create a component and push a measurement to it.
client.create(signed)                                            # the `created` event from §1
client.push(measurement["phip_id"], measurement)                  # the `measurement` event from §2

# Read it back.
obj = client.get(f"phip://{authority}/parts/widget-001")
print(obj["state"], obj["history_length"])
# concept 2

for event in client.history(f"phip://{authority}/parts/widget-001")["events"]:
    print(event["type"], event["timestamp"])
```

## 4. Async client (same surface)

For async codebases:

```python
import asyncio
from phip import AsyncClient

async def main():
    async with AsyncClient(base_url="http://127.0.0.1:8080", authority="tutorial.local") as client:
        obj = await client.get(f"phip://{authority}/parts/widget-001")
        print(obj["state"])

asyncio.run(main())
```

## 5. Walk an existing chain and verify every signature

This is what `verify_chain` does — the protocol-level integrity check
phip-server runs on every push, and what `phip-cli verify` exposes to
end users:

```python
from phip import verify_chain

# verify_chain calls a resolver per event. The resolver returns the
# Ed25519 public key for a given key_id (or None if not found). It
# raises on any integrity failure; no exception means the chain is
# valid end-to-end.
def resolve(key_id_str):
    if key_id_str == key_id:
        return kp.public
    return None

events = client.history(f"phip://{authority}/parts/widget-001")["events"]
verify_chain(events, public_key_resolver=resolve)
print(f"chain OK ({len(events)} events)")
```

For multi-actor or federated chains, `resolve_key` becomes a fetch
against `phip-server`'s `/resolve/keys/<name>` endpoint — see
`FederationClient` for the full federation case.

## 6. Pack a portable, verifiable bundle

A bundle is a self-contained tar file with the manifest, all event
chains, and embedded key actor records. Anyone can `verify_bundle` it
without network access.

```python
from datetime import datetime, timezone
from phip import make_bundle, pack_bundle, unpack_bundle, verify_bundle, hash_event

events_in_chain = [signed, measurement]  # from §2

bundle = make_bundle(
    authority="tutorial.local",
    created_by=key_id,
    created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    objects=[
        {
            "phip_id": f"phip://tutorial.local/parts/widget-001",
            "object_type": "component",
            "state": "concept",
            "head_hash": hash_event(measurement),
            "history_length": 2,
        }
    ],
    history={f"phip://tutorial.local/parts/widget-001": events_in_chain},
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

tar_bytes = pack_bundle(bundle)
open("widget-001.phip-bundle", "wb").write(tar_bytes)
print("wrote", len(tar_bytes), "bytes")

# Round-trip: verify with no network.
loaded = unpack_bundle(tar_bytes)
verify_bundle(loaded)
print("bundle verified end-to-end")
```

## 7. Capability tokens

Tokens (§11.3) scope what an actor can do. Mint them with the
granting authority's key, verify them on the way in:

```python
from phip import mint_token, encode_token, parse_token, verify_token

token = mint_token(
    granted_by=key_id,
    granted_to=f"phip://{authority}/keys/bob",
    scope="push_events",
    object_filter=f"phip://{authority}/parts/*",
    not_before="2020-01-01T00:00:00Z",
    expires="2099-01-01T00:00:00Z",
    private_key=kp.private,
    key_id=key_id,
    token_id=str(uuid.uuid4()),
)

wire = encode_token(token)
# Pass `wire` in `Authorization: PhIP-Capability <wire>` headers.

decoded = parse_token(wire)
verify_token(
    decoded,
    kp.public,
    requesting_actor=f"phip://{authority}/keys/bob",
    requested_object=f"phip://{authority}/parts/widget-001",
    requested_scope="push_events",
)
print("token verified")
```

## Where to go next

- **`examples/`** — runnable Python scripts for each section above.
- **[phip-cli](https://github.com/mfgs-us/phip-cli)** — same workflow from the command line.
- **[phip-server](https://github.com/mfgs-us/phip-server)** — run your own authority.
- **[The spec](https://github.com/mfgs-us/phip)** — normative reference for everything above.

## Errors you'll see

| Exception | Meaning |
|---|---|
| `InvalidSignature` | Event/token/bundle signature didn't verify |
| `ChainConflict` | Push's `previous_hash` didn't match server's current head |
| `KeyNotFound` | Resolver couldn't produce a JWK for some `key_id` |
| `KeyExpired` | JWK's `not_before`/`not_after` window doesn't include `at` |
| `InvalidEvent` | Event missing required fields or malformed |
| `ObjectNotFound` / `ObjectExists` | What it says |
| `InvalidCapability` / `MissingCapability` | Token failed validation, or no token where one was required |
| `ForeignNamespace` | Pushed an event whose authority doesn't match the server's |

All inherit from `PhipError`. Error envelopes from phip-server come
back as Python exceptions of the matching subclass; you can dispatch
on type directly.

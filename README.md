# phip — PhIP client library for Python

[![spec](https://img.shields.io/badge/spec-v0.1.0--draft-blue)](https://github.com/mfgs-us/phip)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)]()

Python client library for the
[Physical Information Protocol](https://github.com/mfgs-us/phip) — a
federated protocol for addressing, querying, and exchanging information
about physical objects across organizational boundaries.

> **Status:** `0.1.0a3` (alpha). Implements PhIP spec `0.1.0-draft`,
> which itself is unstable until v1.0. Expect breaking changes.

## Install

```bash
pip install phip   # not yet on PyPI; install from source for now
```

From source:

```bash
pip install git+https://github.com/mfgs-us/phip-py
```

## 30-line first integration

```python
import uuid
from datetime import datetime, timezone
from phip import Client, generate_keypair, sign_event

AUTHORITY = "test.local"
client = Client(base_url=f"http://127.0.0.1:8080", authority=AUTHORITY)

# 1. Self-sign a bootstrap key actor (§11.2.4)
kp = generate_keypair()
key_id = f"phip://{AUTHORITY}/keys/bootstrap"
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

client.create(sign_event({
    "event_id": str(uuid.uuid4()),
    "phip_id": key_id, "type": "created", "timestamp": now,
    "actor": key_id, "previous_hash": "genesis",
    "payload": {"object_type": "actor", "state": "active",
                "attributes": {"phip:keys": {**kp.jwk,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z"}}},
}, kp.private, key_id))

# 2. Create a component object
phip_id = f"phip://{AUTHORITY}/units/widget-001"
client.create(sign_event({
    "event_id": str(uuid.uuid4()),
    "phip_id": phip_id, "type": "created", "timestamp": now,
    "actor": key_id, "previous_hash": "genesis",
    "payload": {"object_type": "component", "state": "concept"},
}, kp.private, key_id))

# 3. Read it back
print(client.get(phip_id)["state"])  # → 'concept'
```

Run a PhIP server locally (the [Node reference](https://github.com/mfgs-us/phip/tree/main/reference))
to make this script work end-to-end:

```bash
git clone https://github.com/mfgs-us/phip
cd phip/reference && npm install
PHIP_AUTHORITY=test.local PHIP_PORT=8080 npm start
```

## What's in the box

Both **sync** (`Client`) and **async** (`AsyncClient`) APIs are
first-class. The library covers:

- URI parsing (`parse_uri`, `format_uri`)
- JCS canonicalization (RFC 8785)
- Ed25519 sign / verify, JWK helpers
- Event signing + full hash-chain verification
- Capability tokens (mint, parse, encode, verify)
- HTTP operations: CREATE, GET, PUSH, QUERY, history, batch, /meta
- Typed error hierarchy (one exception per spec error code)
- Foreign-authority key resolution via `FederationClient` (HTTPS-only
  by default, DNS pre-resolution + private-IP block, 24h cache TTL
  ceiling, 1 MiB response cap)
- PhIP bundle pack / unpack / verify (`phip.bundle.make_bundle`,
  `pack_bundle`, `unpack_bundle`, `verify_bundle`)
- **Topology disclosure** (§11.5.6) via `phip.topology`:
  `Client.get_topology` / `AsyncClient.get_topology` issue
  `?disclosure=topology` requests; `build_topology_envelope` /
  `verify_topology_response` / `stitch_pages` cover the
  envelope-signed shape with per-entry `event_hash` chain-walk
  verification. `read_topology` scope and `GRANTED_TO_ANYONE = "*"`
  presenter-anonymous grants supported in `mint_token` /
  `verify_token`.

Coming later:

- Subscription / polling helpers
- Retry policy customization

## Conformance

phip-py passes:

- The language-agnostic [test vectors](https://github.com/mfgs-us/phip/tree/main/tests/vectors)
  byte-for-byte (JCS, Ed25519, hash chains, lifecycle, tokens, bundles)
- The [HTTP conformance suite](https://github.com/mfgs-us/phip/tree/main/tests/conformance)
  against the [reference resolver](https://github.com/mfgs-us/phip/tree/main/reference)

Run the test suite:

```bash
pip install -e ".[test]"
pytest
```

## Versioning

Pinned to PhIP spec MAJOR. v0.1.x of this library implements PhIP
`0.1.x` of the spec. See the protocol's
[VERSIONING.md](https://github.com/mfgs-us/phip/blob/main/VERSIONING.md)
for full rules.

`PROTOCOL_VERSION` is exported as a module constant:

```python
from phip import PROTOCOL_VERSION  # "0.1.0-draft"
```

## Out of scope

This library is client-only:

- It does **not** host PhIP authorities (that's `phip-server`)
- It does **not** integrate with HSMs or KMS (that's `phip-cli`)
- It does **not** terminate TLS or run mTLS (that's `phip-server`)
- It does **not** ship a CLI (that will be `phip-cli`, in Go)

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

## Repository

[github.com/mfgs-us/phip-py](https://github.com/mfgs-us/phip-py) ·
[spec](https://github.com/mfgs-us/phip)

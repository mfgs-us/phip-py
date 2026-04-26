# phip — PhIP client library for Python

[![spec](https://img.shields.io/badge/spec-v0.1.0--draft-blue)](https://github.com/mfgs-us/phip)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)]()

Python client library for the
[Physical Information Protocol](https://github.com/mfgs-us/phip) — a
federated protocol for addressing, querying, and exchanging information
about physical objects across organizational boundaries.

> **Status:** `0.1.0a1` (alpha). Implements PhIP spec `0.1.0-draft`,
> which itself is unstable until v1.0. Expect breaking changes.

## Install

```bash
pip install phip   # not yet on PyPI; install from source for now
```

From source:

```bash
pip install git+https://github.com/mfgs-us/phip-py
```

## What's in the box

```python
from phip import Client, sign_event, verify_event

client = Client(base_url="https://acme.example", signing_key=key)
obj = client.get("phip://acme.example/parts/widget-001")
client.push(phip_id, event)
```

Both **sync** (`Client`) and **async** (`AsyncClient`) APIs are
first-class. See `examples/` for end-to-end walkthroughs.

The library covers:

- URI parsing
- JCS canonicalization (RFC 8785)
- Ed25519 sign / verify
- Event signing + hash chain verification
- Capability tokens (mint, parse, verify)
- HTTP operations: CREATE, GET, PUSH, QUERY, history, batch, /meta
- Foreign-authority key resolution (with SSRF defense)
- PhIP bundle import / export

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

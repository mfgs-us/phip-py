# Changelog

All notable changes to phip-py will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this library follows [SemVer](https://semver.org/) and pins to spec
MAJOR per the PhIP [VERSIONING.md](https://github.com/mfgs-us/phip/blob/main/VERSIONING.md).

## [0.1.0a2] — Unreleased

Adds federation client + bundle support.

### Added

- **`FederationClient`**: async outbound HTTPS for foreign-authority
  `/meta` and key-actor resolution. Mirrors `reference/src/federation.js`
  in the spec repo:
  - HTTPS by default; `allow_http=True` for tests
  - DNS pre-resolution + private/loopback/link-local rejection
    (RFC 1918, CGNAT, IPv6 fe80::/10, fc00::/7, ff00::/8 etc.)
  - Cache TTL respects `Cache-Control: max-age` clamped at 24h
  - 1 MiB response cap, 10s request timeout
  - `url_builder` test hook for mapping authority names to localhost ports
- **Bundle module** (`phip.bundle`): pack / unpack / verify per §4.3.4:
  - `make_bundle(...)` — produce a signed bundle from objects + history
  - `verify_bundle(bundle)` — full integrity check (manifest signature
    + per-object chain + per-event signatures)
  - `pack_bundle(bundle) -> bytes` and `unpack_bundle(bytes) -> Bundle`
    for the on-disk tar transport
  - `bundle_from_dict(d)` for the inline test-vector form
- 35-case private-IP filter test (covers IPv4 + IPv6 + the Node
  reference's previously-discovered `fe81::`–`fe8f::` link-local hole)
- Bundle vector tests: one-object accept, multi-object accept,
  tampered-event reject; round-trip make → pack → unpack → verify;
  unknown-key rejection; `snapshot_of` round trip

### Tested

Total: 106 tests passing (was 60 in a1).

## [0.1.0a1] — Unreleased

Initial alpha. Implements PhIP spec `0.1.0-draft` for client-side
operations.

### Added

- **Primitives**: URI parsing, RFC 8785 (JCS) canonicalization,
  Ed25519 sign/verify, SHA-256, JWK helpers
- **Events**: `sign_event`, `verify_event`, `hash_event`,
  `verify_chain` (full hash-chain walk with key resolution)
- **Capability tokens**: `mint_token`, `parse_token`, `encode_token`,
  `verify_token` (full §11.3.4 verification: signature, validity
  window, granted_to, object_filter, scope coverage)
- **HTTP clients**: synchronous `Client` and asynchronous
  `AsyncClient`. Both cover CREATE, GET, PUSH, QUERY, history,
  batch_create, batch_push, /meta. Built on `httpx`; transport
  injectable for tests.
- **Errors**: typed exception hierarchy mirroring spec §12.6.1
  (one class per error code, base `PhipError`). Error envelopes
  parsed automatically; `ChainConflict.current_head` accessor.
- **Type hints**: throughout, `py.typed` marker shipped.

### Tested

- 33 unit tests against the language-agnostic vectors (JCS,
  Ed25519, hash chains, lifecycle tables, capability tokens)
- 21 client tests with mocked HTTP transport (sync + async, error
  mapping, header handling, batch, /meta fallback)
- 6 integration tests against the live Node reference resolver
  (auto-skipped if reference isn't available)

### Not yet in this alpha

- Federation: foreign-authority key resolution + SSRF defense
- PhIP bundle import / export
- Subscription / polling helpers
- Retry policy customization (`Client` does not auto-retry)

# Changelog

All notable changes to phip-py will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this library follows [SemVer](https://semver.org/) and pins to spec
MAJOR per the PhIP [VERSIONING.md](https://github.com/mfgs-us/phip/blob/main/VERSIONING.md).

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

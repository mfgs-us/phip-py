# Changelog

All notable changes to phip-py will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this library follows [SemVer](https://semver.org/) and pins to spec
MAJOR per the PhIP [VERSIONING.md](https://github.com/mfgs-us/phip/blob/main/VERSIONING.md).

## [0.1.0a3] — Unreleased

Implements PhIP spec topology disclosure (§11.5.6), which landed in the
spec repo via [mfgs-us/phip#10](https://github.com/mfgs-us/phip/pull/10).
Tracks the same `0.1.0-draft` spec version; library bump per VERSIONING.md
"library MINOR tracks spec MINOR additions".

### Added

- **`phip.topology` module** — full client-side support for §11.5.6:
  - `topology_entry_for(event)` — project a full event into its five
    topology fields (event_id, type, timestamp, previous_hash,
    event_hash)
  - `build_topology_envelope(...)` — assemble + sign a topology
    response envelope. Signature covers exactly the four canonical
    fields `{disclosure, page_length, phip_id, topology}` per §11.5.6.4
  - `verify_topology_response(response, public_key)` — end-to-end
    verification: signature, page_length consistency, disclosure
    marker, in-page chain walk
  - `verify_first_page(...)` — also asserts `entry[0].previous_hash ==
    "genesis"` (for first-page responses)
  - `walk_topology_chain(topology)` — returns the index of the first
    chain break or `None`
  - `stitch_pages(pages)` — concatenate paginated topology slices,
    asserting inter-page `previous_hash`/`event_hash` continuity
- **`Client.get_topology(...)`** and **`AsyncClient.get_topology(...)`**
  — high-level GET-history-with-`?disclosure=topology` helper.
- **`read_topology` scope** added to `_VALID_SCOPES` in
  `phip.tokens`. `mint_token` accepts it; `verify_token` correctly
  treats `read_history` as covering `read_topology` requests.
- **`GRANTED_TO_ANYONE = "*"`** sentinel exported from `phip.tokens`
  for presenter-anonymous grants. `mint_token` refuses `"*"` combined
  with `read_history`, `read_query`, `read_state`, or any `push_*`
  scope per the §11.3.1 SHOULD; `verify_token` skips the
  `requesting_actor` match when `granted_to == "*"`.

### Tightened (defensive verification)

`verify_topology_response` enforces structural invariants that the JSON
Schema declares but that a client without a schema validator would
otherwise let through:

- Each topology entry MUST contain EXACTLY the five canonical fields
  (`event_id`, `type`, `timestamp`, `previous_hash`, `event_hash`).
  Catches resolvers that leak `payload` / `actor` / `signature`
  per-entry even when the envelope signature happens to verify.
- `topology_signature.algorithm` MUST be `"Ed25519"`. Other algorithms
  raise `InvalidEvent` rather than failing opaquely inside the
  cryptographic verifier.
- `phip_id` MUST be a non-empty string — replaces a latent `KeyError`
  on malformed responses.

`mint_token` rejects empty `granted_to` (consistent with the existing
empty-`object_filter` rejection), and uses an allowlist
(`_STAR_SAFE_SCOPES = {"read_topology"}`) for `granted_to='*'`
issuance so future scopes added to `_VALID_SCOPES` must be explicitly
considered for `"*"` compatibility instead of silently bypassing a
denylist.

`stitch_pages(pages, public_key=...)` now optionally verifies each
non-empty page's full envelope before stitching — the recommended
single-call shortcut for callers that want a verified flat list.
Without `public_key`, behavior is unchanged: stitch only, caller is
responsible for prior verification.

### Tests

15 new topology tests + 5 new token tests + the round-2 defensive
checks; suite total **118 passing** (was 107), 7 unrelated skips
(reference resolver not present in CI).

The shared test vectors at
`tests/vectors/topology/cases.json` mirror the canonical set landed in
mfgs-us/phip; every fixture verifies identically here.

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
- 32-case private-IP filter test (covers IPv4 + IPv6 + the Node
  reference's previously-discovered `fe81::`–`fe8f::` link-local hole)
- Bundle vector tests: one-object accept, multi-object accept,
  tampered-event reject; round-trip make → pack → unpack → verify;
  unknown-key rejection; `snapshot_of` round trip

### Tested

Total: 117 tests passing (was 60 in a1).

### Hardened (post-review)

- **R1: streaming size cap.** `FederationClient` now reads the response
  body via `client.stream(...)` + `aiter_bytes`, rejecting once the
  1 MiB cap is reached. Previous code materialized the full body into
  `response.content` first, OOM-able by an adversarial multi-GB body.
- **R2: bundle producer-key fallback constrained.** The producer-key
  fallback in `_resolve_event_key` now requires `event.actor` to equal
  the producer's URI. Without this guard, a malicious bundle could
  mint events whose `actor` claimed a foreign actor URI but whose
  bare `signature.key_id` fell through to the producer's key, fooling
  downstream code that trusts `event.actor` after a successful chain
  verification.
- **R3: JWK validity-window enforcement.** `FederationClient.resolve_key`
  now accepts an optional `at: datetime` argument; when supplied, the
  resolver raises `KeyExpired` if the JWK's `not_before`/`not_after`
  window does not bracket `at`, or `ValueError` if the JWK lacks the
  validity-window fields. Naïve `datetime`s are assumed UTC. This
  closes the documented gap where callers had to enforce the window
  themselves and any miss silently accepted out-of-window keys.
- **Module docstring** for `phip.federation` updated to remove the
  inaccurate "pins resolved IP" claim and explicitly document the v0.1
  rebind window and the now-built-in JWK validity-window check.

### Infrastructure

- **GitHub Actions CI** (`.github/workflows/ci.yml`): pytest matrix
  across Python 3.10 / 3.11 / 3.12 / 3.13, plus ruff and mypy on
  3.12. Independent jobs; concurrency cancels superseded runs.
- **Cache integration tests** (4): cache-hit suppression of network
  fetch, miss-after-expiry refetch, 24h TTL clamp end-to-end, default
  TTL when no `Cache-Control` header is returned.

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

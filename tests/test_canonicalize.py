"""JCS canonicalization passes byte-for-byte against the language-agnostic vectors."""

from __future__ import annotations

from phip.canonicalize import canonical_bytes, canonicalize


def test_jcs_string_matches(jcs_cases) -> None:
    for case in jcs_cases:
        got = canonicalize(case["input"])
        assert got == case["canonical"], f"{case['name']}: string mismatch"


def test_jcs_byte_hex_matches(jcs_cases) -> None:
    for case in jcs_cases:
        got_hex = canonical_bytes(case["input"]).hex()
        assert got_hex == case["canonical_bytes_hex"], f"{case['name']}: bytes mismatch"


def test_jcs_byte_length_matches(jcs_cases) -> None:
    for case in jcs_cases:
        got_len = len(canonical_bytes(case["input"]))
        assert got_len == case["canonical_byte_length"], f"{case['name']}: length mismatch"

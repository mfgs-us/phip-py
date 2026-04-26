"""URI parsing matches the language-agnostic vectors."""

from __future__ import annotations

import pytest

from phip.uri import format_uri, parse_uri


def test_valid_uris_decompose_correctly(uri_cases) -> None:
    for case in uri_cases["valid"]:
        parsed = parse_uri(case["uri"])
        assert parsed.authority == case["authority"]
        assert parsed.namespace == case["namespace"]
        assert parsed.local_id == case["local_id"]
        assert list(parsed.sub_path) == case["sub_path"]


def test_valid_uris_round_trip(uri_cases) -> None:
    for case in uri_cases["valid"]:
        parsed = parse_uri(case["uri"])
        assert parsed.format() == case["uri"]


def test_invalid_uris_rejected(uri_cases) -> None:
    for case in uri_cases["invalid"]:
        with pytest.raises(ValueError):
            parse_uri(case["uri"])


def test_format_uri_builds_canonical_form() -> None:
    assert (
        format_uri("acme.example", "parts", "widget-001")
        == "phip://acme.example/parts/widget-001"
    )
    assert (
        format_uri("acme.example", "parts", "widget-001", ["sensors", "temp-1"])
        == "phip://acme.example/parts/widget-001/sensors/temp-1"
    )


def test_format_uri_validates_components() -> None:
    with pytest.raises(ValueError):
        format_uri("", "parts", "x")
    with pytest.raises(ValueError):
        format_uri("acme example", "parts", "x")  # space in authority
    with pytest.raises(ValueError):
        format_uri("acme.example", "", "x")
    with pytest.raises(ValueError):
        format_uri("acme.example", "parts", "")

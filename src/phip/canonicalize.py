"""RFC 8785 (JSON Canonicalization Scheme / JCS) wrapper.

The PhIP hash chain (§10.3) and event signatures (§11.1) are computed
over the JCS serialization of the event. This module wraps the
``rfc8785`` package and exposes both string and bytes accessors so
callers don't repeatedly UTF-8 encode the same value.
"""

from __future__ import annotations

from typing import Any

import rfc8785


def canonicalize(value: Any) -> str:
    """Return the JCS canonicalization of `value` as a UTF-8 string."""
    return rfc8785.dumps(value).decode("utf-8")


def canonical_bytes(value: Any) -> bytes:
    """Return the JCS canonicalization of `value` as UTF-8 bytes.

    This is what the hash chain and signature paths actually consume —
    skips a string-encode round trip.
    """
    return rfc8785.dumps(value)

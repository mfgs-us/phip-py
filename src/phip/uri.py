"""PhIP URI parsing and formatting (Section 4 of the spec).

A PhIP URI has the form:

    phip://{authority}/{namespace}/{local-id}[/{sub-path}...]

where:

* `authority` is a DNS-like name (letters, digits, dots, hyphens)
* `namespace` and `local-id` are pchar-set strings
* `sub-path` is zero or more additional segments (Section 4.4)

This module enforces the grammar at parse time. Path segments after
`local-id` are returned as a tuple in `sub_path`; per §4.4.3 they are
informational, not normative — `contained_in` relations are the source
of truth for hierarchy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Authority: ALPHA / DIGIT / "." / "-"
# Path segment: unreserved / pct-encoded — practically [A-Za-z0-9._~%-]
_URI_RE = re.compile(
    r"^phip://"
    r"(?P<authority>[A-Za-z0-9.\-]+)"
    r"/(?P<namespace>[A-Za-z0-9._~%\-]+)"
    r"/(?P<local_id>[A-Za-z0-9._~%\-]+)"
    r"(?P<rest>(?:/[A-Za-z0-9._~%\-]+)*)$"
)


@dataclass(frozen=True, slots=True)
class PhipUri:
    """Parsed PhIP URI components."""

    authority: str
    namespace: str
    local_id: str
    sub_path: tuple[str, ...] = ()

    def format(self) -> str:
        """Reassemble into the canonical string form."""
        base = f"phip://{self.authority}/{self.namespace}/{self.local_id}"
        if self.sub_path:
            return base + "/" + "/".join(self.sub_path)
        return base

    def __str__(self) -> str:
        return self.format()


def parse_uri(uri: str) -> PhipUri:
    """Parse a PhIP URI string into its components.

    Raises ``ValueError`` for malformed input (wrong scheme, missing
    authority, missing namespace or local-id, empty segments, illegal
    characters in authority).
    """
    if not isinstance(uri, str):
        raise ValueError(f"PhIP URI must be a string, got {type(uri).__name__}")
    m = _URI_RE.match(uri)
    if not m:
        raise ValueError(f"not a valid PhIP URI: {uri!r}")
    rest = m.group("rest")
    sub_path = tuple(p for p in rest.split("/") if p) if rest else ()
    return PhipUri(
        authority=m.group("authority"),
        namespace=m.group("namespace"),
        local_id=m.group("local_id"),
        sub_path=sub_path,
    )


def format_uri(
    authority: str,
    namespace: str,
    local_id: str,
    sub_path: tuple[str, ...] | list[str] | None = None,
) -> str:
    """Build a PhIP URI string from components.

    Validates that each part is non-empty and the authority is
    DNS-grammar-clean. Returns the canonical string form.
    """
    if not authority or not re.fullmatch(r"[A-Za-z0-9.\-]+", authority):
        raise ValueError(f"invalid authority: {authority!r}")
    if not namespace or not re.fullmatch(r"[A-Za-z0-9._~%\-]+", namespace):
        raise ValueError(f"invalid namespace: {namespace!r}")
    if not local_id or not re.fullmatch(r"[A-Za-z0-9._~%\-]+", local_id):
        raise ValueError(f"invalid local_id: {local_id!r}")
    base = f"phip://{authority}/{namespace}/{local_id}"
    if sub_path:
        for seg in sub_path:
            if not seg or not re.fullmatch(r"[A-Za-z0-9._~%\-]+", seg):
                raise ValueError(f"invalid sub-path segment: {seg!r}")
        return base + "/" + "/".join(sub_path)
    return base


def authority_of(uri: str) -> str:
    """Extract just the authority component from a PhIP URI."""
    return parse_uri(uri).authority

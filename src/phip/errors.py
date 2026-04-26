"""Exception hierarchy mirroring the spec's error code registry (§12.6.1).

Every error code in the spec maps to a typed exception that subclasses
``PhipError``. Catching the base catches anything PhIP-related; catching
a specific subclass dispatches on the protocol error code.

The constructor accepts the optional ``details`` dict from the spec
envelope (§12.6) so callers can pull structured fields like
``current_head`` (CHAIN_CONFLICT) or ``valid_transitions``
(INVALID_TRANSITION) without re-parsing.
"""

from __future__ import annotations

from typing import Any


class PhipError(Exception):
    """Base for all PhIP protocol errors.

    Attributes:
        code: The PhIP error code (e.g. ``"INVALID_SIGNATURE"``).
        status: The associated HTTP status from §12.6.1.
        details: Optional details object from the error envelope.
    """

    code: str = "PHIP_ERROR"
    status: int = 500

    def __init__(self, message: str = "", details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    @property
    def current_head(self) -> str | None:
        """Convenience accessor for `details.current_head` on CHAIN_CONFLICT."""
        v = self.details.get("current_head")
        return v if isinstance(v, str) else None

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.code!r}, {self.message!r})"


# ── 401 — authentication errors ────────────────────────────────────


class InvalidSignature(PhipError):
    code = "INVALID_SIGNATURE"
    status = 401


class KeyNotFound(PhipError):
    code = "KEY_NOT_FOUND"
    status = 401


class KeyExpired(PhipError):
    code = "KEY_EXPIRED"
    status = 401


# ── 403 — authorization errors ─────────────────────────────────────


class MissingCapability(PhipError):
    code = "MISSING_CAPABILITY"
    status = 403


class InvalidCapability(PhipError):
    code = "INVALID_CAPABILITY"
    status = 403


class AccessDenied(PhipError):
    code = "ACCESS_DENIED"
    status = 403


class ForeignNamespace(PhipError):
    code = "FOREIGN_NAMESPACE"
    status = 403


# ── 404 — not found ────────────────────────────────────────────────


class ObjectNotFound(PhipError):
    code = "OBJECT_NOT_FOUND"
    status = 404


# ── 405 — method not supported ─────────────────────────────────────


class OperationNotSupported(PhipError):
    code = "OPERATION_NOT_SUPPORTED"
    status = 405


# ── 409 — conflicts ────────────────────────────────────────────────


class ObjectExists(PhipError):
    code = "OBJECT_EXISTS"
    status = 409


class ChainConflict(PhipError):
    code = "CHAIN_CONFLICT"
    status = 409


class DuplicateEvent(PhipError):
    code = "DUPLICATE_EVENT"
    status = 409


class TerminalState(PhipError):
    code = "TERMINAL_STATE"
    status = 409


# ── 422 — invalid data ─────────────────────────────────────────────


class InvalidObject(PhipError):
    code = "INVALID_OBJECT"
    status = 422


class InvalidEvent(PhipError):
    code = "INVALID_EVENT"
    status = 422


class InvalidTransition(PhipError):
    code = "INVALID_TRANSITION"
    status = 422


class InvalidTrack(PhipError):
    code = "INVALID_TRACK"
    status = 422


class InvalidRelation(PhipError):
    code = "INVALID_RELATION"
    status = 422


class DanglingRelation(PhipError):
    code = "DANGLING_RELATION"
    status = 422


class InvalidQuery(PhipError):
    code = "INVALID_QUERY"
    status = 422


# ── Code → class registry ──────────────────────────────────────────

_BY_CODE: dict[str, type[PhipError]] = {
    cls.code: cls
    for cls in (
        InvalidSignature,
        KeyNotFound,
        KeyExpired,
        MissingCapability,
        InvalidCapability,
        AccessDenied,
        ForeignNamespace,
        ObjectNotFound,
        OperationNotSupported,
        ObjectExists,
        ChainConflict,
        DuplicateEvent,
        TerminalState,
        InvalidObject,
        InvalidEvent,
        InvalidTransition,
        InvalidTrack,
        InvalidRelation,
        DanglingRelation,
        InvalidQuery,
    )
}


def from_envelope(envelope: dict[str, Any], status: int | None = None) -> PhipError:
    """Construct the appropriate PhipError subclass from a §12.6 envelope.

    Falls back to the base ``PhipError`` for codes not in the registry
    (forward-compatible with future spec additions).
    """
    err = envelope.get("error", envelope) if isinstance(envelope, dict) else {}
    code = err.get("code", "PHIP_ERROR") if isinstance(err, dict) else "PHIP_ERROR"
    message = err.get("message", "") if isinstance(err, dict) else ""
    details = err.get("details") if isinstance(err, dict) else None
    cls = _BY_CODE.get(code, PhipError)
    instance = cls(message, details if isinstance(details, dict) else None)
    if status is not None:
        instance.status = status
    if cls is PhipError:
        instance.code = code
    return instance

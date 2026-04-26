"""Cryptographic primitives — Ed25519 + SHA-256.

PhIP uses Ed25519 (RFC 8032) for signatures over JCS-canonical bytes,
and SHA-256 for hash-chain links (§10.3). This module wraps
``cryptography`` with a thin, ergonomic API and a couple of conversion
helpers for the on-the-wire JWK + base64url representations.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def _b64url_no_pad(b: bytes) -> str:
    """Standard base64url WITHOUT padding — what the spec uses."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _from_b64url(s: str) -> bytes:
    """Decode base64url with optional padding stripped."""
    s = s.lstrip()
    if s.startswith("base64url:"):
        s = s[len("base64url:"):]
    # Re-pad for stdlib decoder.
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def sha256_hex(data: bytes) -> str:
    """SHA-256 of `data` as a 64-char lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class Keypair:
    """An Ed25519 keypair held as the primitive types from `cryptography`."""

    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def public_raw(self) -> bytes:
        """Raw 32-byte public key bytes (the X coordinate in JWK terms)."""
        return self.public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_b64url(self) -> str:
        """Base64url (unpadded) encoding of the raw public key."""
        return _b64url_no_pad(self.public_raw)

    @property
    def private_pkcs8_der(self) -> bytes:
        """PKCS#8 DER-encoded private key (the format used in test vectors)."""
        return self.private.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

    @property
    def jwk(self) -> dict[str, str]:
        """JWK form of the public key, ready to embed in `phip:keys`."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": self.public_b64url,
        }


def generate_keypair() -> Keypair:
    """Generate a fresh Ed25519 keypair."""
    private = Ed25519PrivateKey.generate()
    return Keypair(private=private, public=private.public_key())


def keypair_from_pkcs8(private_pkcs8_der: bytes) -> Keypair:
    """Load a keypair from a PKCS#8 DER-encoded private key.

    Tests and ceremony tooling produce keys in this format. The public
    key is derived from the private key.
    """
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    private = load_der_private_key(private_pkcs8_der, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("loaded key is not Ed25519")
    return Keypair(private=private, public=private.public_key())


def public_key_from_b64url(b64url: str) -> Ed25519PublicKey:
    """Build an Ed25519 public key from its raw 32-byte base64url form.

    This is the form used in the `phip:keys` JWK `x` field.
    """
    raw = _from_b64url(b64url)
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_from_jwk(jwk: dict[str, str]) -> Ed25519PublicKey:
    """Extract an Ed25519 public key from a `phip:keys`-shaped JWK."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"not an Ed25519 OKP JWK: kty={jwk.get('kty')!r}, crv={jwk.get('crv')!r}")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ValueError("JWK is missing `x`")
    return public_key_from_b64url(x)


def sign(private: Ed25519PrivateKey, message: bytes) -> str:
    """Sign `message` and return a base64url (unpadded) signature.

    The PhIP wire format for `signature.value` is exactly this string.
    """
    return _b64url_no_pad(private.sign(message))


def verify(public: Ed25519PublicKey, message: bytes, signature_b64url: str) -> bool:
    """Verify a base64url-encoded signature against `message`.

    Returns True on success, False on cryptographic failure. Other
    errors (bad encoding, wrong length) propagate as ValueError so
    callers can distinguish "verification said no" from "input was
    malformed."
    """
    sig = _from_b64url(signature_b64url)
    if len(sig) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(sig)}")
    try:
        public.verify(sig, message)
        return True
    except InvalidSignature:
        return False

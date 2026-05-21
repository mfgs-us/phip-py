"""phip — Python client library for the Physical Information Protocol.

PhIP is a federated protocol for formatting, addressing, querying, and
exchanging information about physical objects across organizational and
system boundaries. See https://github.com/mfgs-us/phip for the spec.

Public surface (built incrementally):

    from phip import (
        # Version
        __version__, PROTOCOL_VERSION,

        # Primitives
        canonicalize, sha256_hex,
        parse_uri, format_uri,

        # Crypto
        generate_keypair, sign, verify,

        # Events
        sign_event, verify_event, hash_event, verify_chain,

        # Tokens
        sign_token, verify_token,

        # Clients
        Client, AsyncClient,

        # Errors
        PhipError, InvalidSignature, ChainConflict, AccessDenied,
        # ... one per spec error code
    )
"""

from phip._version import PROTOCOL_VERSION, __version__
from phip.async_client import AsyncClient
from phip.bundle import (
    BUNDLE_VERSION,
    Bundle,
    bundle_from_dict,
    make_bundle,
    pack_bundle,
    unpack_bundle,
    verify_bundle,
)
from phip.canonicalize import canonical_bytes, canonicalize
from phip.client import Client
from phip.crypto import (
    Keypair,
    generate_keypair,
    keypair_from_pkcs8,
    public_key_from_b64url,
    public_key_from_jwk,
    sha256_hex,
    sign,
    verify,
)
from phip.errors import (
    AccessDenied,
    ChainConflict,
    DanglingRelation,
    DuplicateEvent,
    ForeignNamespace,
    InvalidCapability,
    InvalidEvent,
    InvalidObject,
    InvalidQuery,
    InvalidRelation,
    InvalidSignature,
    InvalidTrack,
    InvalidTransition,
    KeyExpired,
    KeyNotFound,
    MissingCapability,
    ObjectExists,
    ObjectNotFound,
    OperationNotSupported,
    PhipError,
    TerminalState,
)
from phip.events import Event, hash_event, sign_event, verify_chain, verify_event
from phip.federation import FederationClient
from phip.tokens import (
    GRANTED_TO_ANYONE,
    Token,
    encode_token,
    mint_token,
    parse_token,
    verify_token,
)
from phip.topology import (
    DISCLOSURE_TOPOLOGY,
    TOPOLOGY_FIELDS_SIGNED,
    TopologyEntry,
    TopologyResponse,
    build_topology_envelope,
    stitch_pages,
    topology_entry_for,
    verify_first_page,
    verify_topology_response,
    walk_topology_chain,
)
from phip.uri import PhipUri, authority_of, format_uri, parse_uri

__all__ = [
    # Version
    "PROTOCOL_VERSION",
    "__version__",
    # Canonicalize
    "canonical_bytes",
    "canonicalize",
    # Crypto
    "Keypair",
    "generate_keypair",
    "keypair_from_pkcs8",
    "public_key_from_b64url",
    "public_key_from_jwk",
    "sha256_hex",
    "sign",
    "verify",
    # Errors
    "AccessDenied",
    "ChainConflict",
    "DanglingRelation",
    "DuplicateEvent",
    "ForeignNamespace",
    "InvalidCapability",
    "InvalidEvent",
    "InvalidObject",
    "InvalidQuery",
    "InvalidRelation",
    "InvalidSignature",
    "InvalidTrack",
    "InvalidTransition",
    "KeyExpired",
    "KeyNotFound",
    "MissingCapability",
    "ObjectExists",
    "ObjectNotFound",
    "OperationNotSupported",
    "PhipError",
    "TerminalState",
    # Events
    "Event",
    "hash_event",
    "sign_event",
    "verify_chain",
    "verify_event",
    # Tokens
    "GRANTED_TO_ANYONE",
    "Token",
    "encode_token",
    "mint_token",
    "parse_token",
    "verify_token",
    # Topology disclosure (§11.5.6)
    "DISCLOSURE_TOPOLOGY",
    "TOPOLOGY_FIELDS_SIGNED",
    "TopologyEntry",
    "TopologyResponse",
    "build_topology_envelope",
    "stitch_pages",
    "topology_entry_for",
    "verify_first_page",
    "verify_topology_response",
    "walk_topology_chain",
    # Clients
    "AsyncClient",
    "Client",
    # Federation
    "FederationClient",
    # Bundles
    "BUNDLE_VERSION",
    "Bundle",
    "bundle_from_dict",
    "make_bundle",
    "pack_bundle",
    "unpack_bundle",
    "verify_bundle",
    # URI
    "PhipUri",
    "authority_of",
    "format_uri",
    "parse_uri",
]

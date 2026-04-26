"""Test fixtures shared across the suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).parent / "vectors"


def _load_json(rel_path: str) -> dict:
    return json.loads((VECTORS_DIR / rel_path).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def jcs_cases() -> list[dict]:
    return _load_json("jcs/cases.json")["cases"]


@pytest.fixture(scope="session")
def hash_cases() -> list[dict]:
    return _load_json("hash/cases.json")["cases"]


@pytest.fixture(scope="session")
def uri_cases() -> dict:
    return _load_json("uri/cases.json")


@pytest.fixture(scope="session")
def keypair_data() -> list[dict]:
    """Fixed test keypairs in PKCS#8 / raw form."""
    return _load_json("ed25519/keypair.json")["keys"]


@pytest.fixture(scope="session")
def ed25519_cases() -> dict:
    """Raw signing cases plus event-signing cases."""
    return _load_json("ed25519/cases.json")


@pytest.fixture(scope="session")
def hashchain_data() -> dict:
    return _load_json("hashchain/sequence.json")


@pytest.fixture(scope="session")
def lifecycle_mfg() -> dict:
    return _load_json("lifecycle/manufacturing.json")


@pytest.fixture(scope="session")
def lifecycle_op() -> dict:
    return _load_json("lifecycle/operational.json")


@pytest.fixture(scope="session")
def bootstrap_example() -> dict:
    return _load_json("bootstrap/example.json")


@pytest.fixture(scope="session")
def token_cases() -> list[dict]:
    return _load_json("token/cases.json")["cases"]


@pytest.fixture(scope="session")
def bundle_cases() -> list[dict]:
    return _load_json("bundle/cases.json")["bundles"]

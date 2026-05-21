"""End-to-end integration test against the Node reference resolver.

Auto-skips when:
  - The reference resolver isn't available on disk (looks for the
    sibling clone at ``../phip/reference``, override via the
    ``PHIP_REFERENCE_PATH`` environment variable)
  - Node.js isn't installed or fails to start the resolver
  - The resolver port can't be reached within a few seconds

What this proves: phip-py's URI handling, JCS, Ed25519 signing, hash
chain math, error-envelope mapping, and HTTP transport all line up
with a real PhIP server end-to-end. The mocked tests cover correctness
of each unit; this test covers wire-level integration.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from phip import (
    ChainConflict,
    Client,
    ObjectExists,
    ObjectNotFound,
    generate_keypair,
    sign_event,
)

REFERENCE_PATH = Path(
    os.environ.get(
        "PHIP_REFERENCE_PATH",
        Path(__file__).resolve().parents[2] / "phip" / "reference",
    )
).resolve()

AUTHORITY = "test.local"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def reference_server() -> Iterator[Client]:
    if not REFERENCE_PATH.exists():
        pytest.skip(
            f"reference resolver not at {REFERENCE_PATH}. "
            "Set PHIP_REFERENCE_PATH or clone github.com/mfgs-us/phip alongside this repo."
        )
    if not (REFERENCE_PATH / "node_modules").exists():
        pytest.skip(
            f"reference resolver dependencies not installed; run "
            f"`npm install` in {REFERENCE_PATH}"
        )

    port = _free_port()
    env = {
        **os.environ,
        "PHIP_AUTHORITY": AUTHORITY,
        "PHIP_PORT": str(port),
    }
    # On Windows, npx/node lookups need shell=True or a full path.
    proc = subprocess.Popen(
        ["node", str(REFERENCE_PATH / "src" / "index.js")],
        env=env,
        cwd=REFERENCE_PATH,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        if not _wait_for_port(port):
            stdout, stderr = proc.communicate(timeout=2)
            pytest.skip(
                f"reference resolver didn't open port {port}\n"
                f"stdout: {stdout.decode(errors='replace')[:500]}\n"
                f"stderr: {stderr.decode(errors='replace')[:500]}"
            )
        client = Client(base_url=f"http://127.0.0.1:{port}", authority=AUTHORITY)
        try:
            yield client
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bootstrap_key(client: Client) -> tuple[str, object]:
    """Self-signed bootstrap actor (§11.2.4). Returns (key_phip_id, keypair)."""
    kp = generate_keypair()
    run_id = uuid.uuid4().hex[:8]
    key_phip_id = f"phip://{AUTHORITY}/keys/bootstrap-{run_id}"
    event = {
        "event_id": str(uuid.uuid4()),
        "phip_id": key_phip_id,
        "type": "created",
        "timestamp": _now_iso(),
        "actor": key_phip_id,
        "previous_hash": "genesis",
        "payload": {
            "object_type": "actor",
            "state": "active",
            "attributes": {
                "phip:keys": {
                    **kp.jwk,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                },
            },
        },
    }
    signed = sign_event(event, kp.private, key_phip_id)
    client.create(signed)
    return key_phip_id, kp


def test_meta_round_trip(reference_server: Client) -> None:
    meta = reference_server.meta()
    assert meta["protocol_version"] == "0.1.0-draft"
    assert meta["authority"] == AUTHORITY


def test_create_get_push_history_chain(reference_server: Client) -> None:
    key_phip_id, kp = _bootstrap_key(reference_server)
    run_id = uuid.uuid4().hex[:8]

    # CREATE.
    obj_phip_id = f"phip://{AUTHORITY}/units/widget-{run_id}"
    create = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": obj_phip_id,
            "type": "created",
            "timestamp": _now_iso(),
            "actor": key_phip_id,
            "previous_hash": "genesis",
            "payload": {
                "object_type": "component",
                "state": "concept",
                "identity": {"serial": f"WGT-{run_id}"},
            },
        },
        kp.private,
        key_phip_id,
    )
    obj = reference_server.create(create)
    assert obj["state"] == "concept"
    assert obj["history_length"] == 1
    head = obj["history_head"]

    # PUSH a state_transition.
    trans = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": obj_phip_id,
            "type": "state_transition",
            "timestamp": _now_iso(),
            "actor": key_phip_id,
            "previous_hash": head,
            "payload": {"from": "concept", "to": "design"},
        },
        kp.private,
        key_phip_id,
    )
    appended = reference_server.push(obj_phip_id, trans)
    assert appended["event_id"] == trans["event_id"]

    # GET reflects new state.
    obj2 = reference_server.get(obj_phip_id)
    assert obj2["state"] == "design"
    assert obj2["history_length"] == 2

    # History sub-resource returns both events.
    page = reference_server.history(obj_phip_id, limit=10)
    assert page["history_length"] == 2
    assert len(page["events"]) == 2


def test_chain_conflict_carries_current_head(reference_server: Client) -> None:
    key_phip_id, kp = _bootstrap_key(reference_server)
    run_id = uuid.uuid4().hex[:8]
    obj_phip_id = f"phip://{AUTHORITY}/units/conflict-{run_id}"

    create = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": obj_phip_id,
            "type": "created",
            "timestamp": _now_iso(),
            "actor": key_phip_id,
            "previous_hash": "genesis",
            "payload": {"object_type": "component", "state": "concept"},
        },
        kp.private,
        key_phip_id,
    )
    reference_server.create(create)

    # Push with a stale previous_hash.
    stale = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": obj_phip_id,
            "type": "state_transition",
            "timestamp": _now_iso(),
            "actor": key_phip_id,
            "previous_hash": "sha256:" + "0" * 64,
            "payload": {"from": "concept", "to": "design"},
        },
        kp.private,
        key_phip_id,
    )
    with pytest.raises(ChainConflict) as exc:
        reference_server.push(obj_phip_id, stale)
    assert exc.value.current_head, "current_head MUST be present per §12.3.1"


def test_object_exists_on_duplicate_create(reference_server: Client) -> None:
    key_phip_id, kp = _bootstrap_key(reference_server)
    run_id = uuid.uuid4().hex[:8]
    phip_id = f"phip://{AUTHORITY}/units/dup-{run_id}"
    event = sign_event(
        {
            "event_id": str(uuid.uuid4()),
            "phip_id": phip_id,
            "type": "created",
            "timestamp": _now_iso(),
            "actor": key_phip_id,
            "previous_hash": "genesis",
            "payload": {"object_type": "component", "state": "concept"},
        },
        kp.private,
        key_phip_id,
    )
    reference_server.create(event)
    with pytest.raises(ObjectExists):
        reference_server.create(event)


def test_object_not_found(reference_server: Client) -> None:
    with pytest.raises(ObjectNotFound):
        reference_server.get(f"phip://{AUTHORITY}/parts/never-existed-{uuid.uuid4().hex}")


def test_query_by_filters(reference_server: Client) -> None:
    key_phip_id, kp = _bootstrap_key(reference_server)
    run_id = uuid.uuid4().hex[:8]
    phip_id = f"phip://{AUTHORITY}/units/queryable-{run_id}"
    reference_server.create(
        sign_event(
            {
                "event_id": str(uuid.uuid4()),
                "phip_id": phip_id,
                "type": "created",
                "timestamp": _now_iso(),
                "actor": key_phip_id,
                "previous_hash": "genesis",
                "payload": {"object_type": "component", "state": "concept"},
            },
            kp.private,
            key_phip_id,
        )
    )
    result = reference_server.query("units", {"filters": {"object_type": "component"}})
    assert phip_id in result["matches"]

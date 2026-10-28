from __future__ import annotations
from app.models.verifkv import GENESIS_HASH
import sqlite3

from app.models.verifkv import (
    VerifKVEvent,
    VerifKVEventType,
)

from verifkv_service.store import VerifKVStore


def make_event(
    *,
    event_type: VerifKVEventType,
    tenant_id: str = "tenant-001",
    request_id: str = "request-001",
) -> VerifKVEvent:

    return VerifKVEvent(
        event_type=event_type,
        source="unit-test",
        tenant_id=tenant_id,
        request_id=request_id,
        payload={
            "backend_id": "backend-a",
            "status": "ok",
        },
    )


def test_empty_verifkv_chain_is_valid(
    tmp_path,
) -> None:

    db_path = tmp_path / "verifkv.db"

    store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    result = store.verify_chain()

    assert result == {
        "valid": True,
        "verified_events": 0,
    }


def test_event_is_persisted_and_chain_verifies(
    tmp_path,
) -> None:

    db_path = tmp_path / "verifkv.db"

    store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    event = make_event(event_type=(VerifKVEventType.ROUTE_ASSIGNED))

    sequence_number = store.append(event)

    assert sequence_number == 1

    result = store.verify_chain()

    assert result["valid"] is True

    assert result["verified_events"] == 1


def test_multiple_events_form_valid_hash_chain(
    tmp_path,
) -> None:

    db_path = tmp_path / "verifkv.db"

    store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    events = [
        make_event(
            event_type=(VerifKVEventType.AUTHZ_DECISION),
            request_id="request-001",
        ),
        make_event(
            event_type=(VerifKVEventType.ROUTE_ASSIGNED),
            request_id="request-001",
        ),
        make_event(
            event_type=(VerifKVEventType.KV_POLICY_APPLIED),
            request_id="request-001",
        ),
        make_event(
            event_type=(VerifKVEventType.REQUEST_COMPLETED),
            request_id="request-001",
        ),
    ]

    for event in events:
        store.append(event)

    result = store.verify_chain()

    assert result["valid"] is True

    assert result["verified_events"] == 4


def test_stored_event_contains_hash_and_hmac(
    tmp_path,
) -> None:

    db_path = tmp_path / "verifkv.db"

    store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    event = make_event(event_type=(VerifKVEventType.AUTHZ_DECISION))

    store.append(event)

    connection = sqlite3.connect(db_path)

    row = connection.execute(
        """
        SELECT
            previous_hash,
            event_hash,
            hmac_tag,
            payload_json
        FROM verifkv_events
        WHERE event_id = ?
        """,
        (str(event.event_id),),
    ).fetchone()

    connection.close()

    assert row is not None

    previous_hash = row[0]
    event_hash = row[1]
    hmac_tag = row[2]
    payload_json = row[3]

    assert previous_hash == GENESIS_HASH

    assert len(event_hash) == 64

    assert len(hmac_tag) == 64

    assert payload_json.startswith("{")

    assert payload_json.endswith("}")


def test_verifkv_database_is_created(
    tmp_path,
) -> None:

    db_path = tmp_path / "nested" / "verifkv.db"

    store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    assert db_path.exists()

    event = make_event(event_type=(VerifKVEventType.BACKEND_OBSERVED))

    store.append(event)

    assert store.verify_chain()["valid"] is True

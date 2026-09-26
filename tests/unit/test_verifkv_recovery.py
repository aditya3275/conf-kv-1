from __future__ import annotations

import sqlite3

from app.models.verifkv import (
    VerifKVEvent,
    VerifKVEventType,
)

from verifkv_service.store import VerifKVStore


def create_store(
    tmp_path,
) -> tuple[VerifKVStore, str]:

    db_path = tmp_path / "verifkv.db"

    store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    return store, str(db_path)


def create_event(
    event_type: VerifKVEventType,
    request_id: str,
) -> VerifKVEvent:

    return VerifKVEvent(
        event_type=event_type,
        source="recovery-test",
        tenant_id="tenant-001",
        request_id=request_id,
        payload={
            "backend_id": "backend-a",
            "value": request_id,
        },
    )


def test_tampered_payload_is_detected(
    tmp_path,
) -> None:

    store, db_path = create_store(tmp_path)

    event = create_event(
        VerifKVEventType.ROUTE_ASSIGNED,
        "request-001",
    )

    store.append(event)

    connection = sqlite3.connect(db_path)

    connection.execute(
        """
        UPDATE verifkv_events
        SET payload_json = ?
        WHERE event_id = ?
        """,
        (
            '{"tampered":true}',
            str(event.event_id),
        ),
    )

    connection.commit()
    connection.close()

    result = store.verify_chain()

    assert result["valid"] is False

    assert result["failed_sequence"] == 1

    assert result["reason"] == "event_hash_mismatch"


def test_tampered_event_hash_is_detected(
    tmp_path,
) -> None:

    store, db_path = create_store(tmp_path)

    event = create_event(
        VerifKVEventType.AUTHZ_DECISION,
        "request-001",
    )

    store.append(event)

    connection = sqlite3.connect(db_path)

    connection.execute(
        """
        UPDATE verifkv_events
        SET event_hash = ?
        WHERE event_id = ?
        """,
        (
            "0" * 64,
            str(event.event_id),
        ),
    )

    connection.commit()
    connection.close()

    result = store.verify_chain()

    assert result["valid"] is False

    assert result["failed_sequence"] == 1

    assert result["reason"] == "event_hash_mismatch"


def test_tampered_hmac_is_detected(
    tmp_path,
) -> None:

    store, db_path = create_store(tmp_path)

    event = create_event(
        VerifKVEventType.KV_POLICY_APPLIED,
        "request-001",
    )

    store.append(event)

    connection = sqlite3.connect(db_path)

    connection.execute(
        """
        UPDATE verifkv_events
        SET hmac_tag = ?
        WHERE event_id = ?
        """,
        (
            "1" * 64,
            str(event.event_id),
        ),
    )

    connection.commit()
    connection.close()

    result = store.verify_chain()

    assert result["valid"] is False

    assert result["failed_sequence"] == 1

    assert result["reason"] == "hmac_mismatch"


def test_broken_chain_link_is_detected(
    tmp_path,
) -> None:

    store, db_path = create_store(tmp_path)

    first_event = create_event(
        VerifKVEventType.AUTHZ_DECISION,
        "request-001",
    )

    second_event = create_event(
        VerifKVEventType.ROUTE_ASSIGNED,
        "request-002",
    )

    store.append(first_event)

    store.append(second_event)

    connection = sqlite3.connect(db_path)

    connection.execute(
        """
        UPDATE verifkv_events
        SET previous_hash = ?
        WHERE event_id = ?
        """,
        (
            "BROKEN-PREVIOUS-HASH",
            str(second_event.event_id),
        ),
    )

    connection.commit()
    connection.close()

    result = store.verify_chain()

    assert result["valid"] is False

    assert result["failed_sequence"] == 2

    assert result["reason"] == "chain_link_mismatch"


def test_valid_chain_remains_valid_after_reopening_store(
    tmp_path,
) -> None:

    db_path = tmp_path / "verifkv.db"

    first_store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    first_store.append(
        create_event(
            VerifKVEventType.AUTHZ_DECISION,
            "request-001",
        )
    )

    first_store.append(
        create_event(
            VerifKVEventType.ROUTE_ASSIGNED,
            "request-001",
        )
    )

    first_result = first_store.verify_chain()

    assert first_result["valid"] is True

    # Simulate restarting the VerifKV service.
    second_store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-secret",
    )

    second_result = second_store.verify_chain()

    assert second_result["valid"] is True

    assert second_result["verified_events"] == 2

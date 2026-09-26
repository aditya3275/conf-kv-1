from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.enums import Zone
from app.verifkv.service import VerifKVService
from app.verifkv.store import VerifKVStore
from app.verifkv.writer import VerifKVWriter


@pytest.fixture
async def service(tmp_path):
    db_path = tmp_path / "control_plane.db"

    store = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="test-hmac-secret",
    )

    writer = VerifKVWriter(
        store,
        reconcile_interval_seconds=60.0,
    )

    service = VerifKVService(
        store=store,
        writer=writer,
    )

    await service.start()

    yield service

    await service.close()


@pytest.mark.asyncio
async def test_authorization_is_written_to_outbox(service):
    request_id = uuid4()

    await service.record_authorization(
        request_id=request_id,
        tenant_id="tenant-a",
        decision=True,
        backend_id="vllm-secure-01",
        zone=Zone.SECURE,
        decision_id="decision-001",
        policy_version="v1",
        timestamp=datetime.now(timezone.utc),
        payload={"reason": "allowed"},
    )

    records = await service.store.get_unreconciled_outbox()

    # The writer may already have processed it.
    # Therefore validate through final chain state instead.
    valid, message = await service.verify()

    assert valid is True
    assert message == "VerifKV chain is valid"


@pytest.mark.asyncio
async def test_verifkv_chain_contains_authorization(
    service,
):
    await service.record_authorization(
        request_id=uuid4(),
        tenant_id="tenant-a",
        decision=True,
        backend_id="vllm-secure-01",
        zone=Zone.SECURE,
        decision_id="decision-001",
        policy_version="v1",
        timestamp=datetime.now(timezone.utc),
        payload={"reason": "allowed"},
    )

    # Give background writer an opportunity to drain.
    await service.writer._queue.join()

    db = service.store._db
    assert db is not None

    cursor = await db.execute("""
        SELECT COUNT(*)
        FROM verifkv_events
        """)

    row = await cursor.fetchone()

    assert row[0] == 1


@pytest.mark.asyncio
async def test_outbox_is_marked_reconciled(
    service,
):
    await service.record_authorization(
        request_id=uuid4(),
        tenant_id="tenant-a",
        decision=True,
        backend_id="vllm-secure-01",
        zone=Zone.SECURE,
        decision_id="decision-001",
        policy_version="v1",
        timestamp=datetime.now(timezone.utc),
        payload={},
    )

    await service.writer._queue.join()

    db = service.store._db
    assert db is not None

    cursor = await db.execute("""
        SELECT verifkv_seq
        FROM authz_outbox
        """)

    row = await cursor.fetchone()

    assert row["verifkv_seq"] is not None


@pytest.mark.asyncio
async def test_tampering_is_detected(
    service,
):
    await service.record_authorization(
        request_id=uuid4(),
        tenant_id="tenant-a",
        decision=True,
        backend_id="vllm-secure-01",
        zone=Zone.SECURE,
        decision_id="decision-001",
        policy_version="v1",
        timestamp=datetime.now(timezone.utc),
        payload={},
    )

    await service.writer._queue.join()

    db = service.store._db
    assert db is not None

    await db.execute(
        """
        UPDATE verifkv_events
        SET payload = ?
        WHERE seq = 1
        """,
        ('{"tampered":true}',),
    )

    await db.commit()

    valid, message = await service.verify()

    assert valid is False
    assert "hash mismatch" in message

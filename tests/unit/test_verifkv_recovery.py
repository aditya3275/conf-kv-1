from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.enums import Zone
from app.verifkv.service import VerifKVService
from app.verifkv.store import VerifKVStore
from app.verifkv.writer import VerifKVWriter


@pytest.mark.asyncio
async def test_unreconciled_outbox_is_recovered_after_restart(
    tmp_path,
):
    db_path = tmp_path / "control_plane.db"

    # --------------------------------------------
    # Process 1
    # --------------------------------------------

    store1 = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="secret",
    )

    await store1.initialize()

    request_id = uuid4()

    outbox_seq = await store1.append_authorization_outbox(
        request_id=request_id,
        tenant_id="tenant-a",
        decision=True,
        backend_id="vllm-secure-01",
        zone=Zone.SECURE,
        decision_id="decision-001",
        policy_version="v1",
        timestamp=datetime.now(timezone.utc),
        payload={},
    )

    assert outbox_seq == 1

    # Simulate crash before the asynchronous writer processes it.
    await store1.close()

    # --------------------------------------------
    # Process 2 / restart
    # --------------------------------------------

    store2 = VerifKVStore(
        db_path=str(db_path),
        hmac_secret="secret",
    )

    writer2 = VerifKVWriter(
        store2,
        reconcile_interval_seconds=60.0,
    )

    service2 = VerifKVService(
        store=store2,
        writer=writer2,
    )

    await service2.start()

    try:
        db = service2.store._db
        assert db is not None

        cursor = await db.execute(
            """
            SELECT verifkv_seq
            FROM authz_outbox
            WHERE outbox_seq = ?
            """,
            (outbox_seq,),
        )

        row = await cursor.fetchone()

        assert row is not None
        assert row["verifkv_seq"] is not None

        valid, message = await service2.verify()

        assert valid is True
        assert message == "VerifKV chain is valid"

    finally:
        await service2.close()

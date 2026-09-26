from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from app.enforcement.authorization import (
    AuthorizationRecorder,
)
from app.models.enums import Zone
from app.verifkv.store import VerifKVStore
from app.verifkv.writer import VerifKVWriter


class VerifKVService(AuthorizationRecorder):
    """
    Complete VerifKV service.

    Synchronous boundary:
        durable authorization outbox commit

    Asynchronous:
        hash-chain construction
    """

    def __init__(
        self,
        store: VerifKVStore,
        writer: VerifKVWriter,
    ):
        self.store = store
        self.writer = writer

    async def start(self) -> None:
        await self.store.initialize()

        await self.writer.start()

    async def close(self) -> None:
        await self.writer.stop()

        await self.store.close()

    async def record_authorization(
        self,
        *,
        request_id: UUID,
        tenant_id: str,
        decision: bool,
        backend_id: str,
        zone: Zone,
        decision_id: str,
        policy_version: str,
        timestamp: datetime,
        payload: dict[str, Any],
    ) -> None:
        """
        Synchronous durable authorization boundary.

        The method returns ONLY after the outbox row is committed.
        It then schedules asynchronous chain processing.
        """

        outbox_seq = await self.store.append_authorization_outbox(
            request_id=request_id,
            tenant_id=tenant_id,
            decision=decision,
            backend_id=backend_id,
            zone=zone,
            decision_id=decision_id,
            policy_version=policy_version,
            timestamp=timestamp,
            payload=payload,
        )

        # Non-blocking.
        self.writer.notify(outbox_seq)

    async def verify(self) -> tuple[bool, str]:
        return await self.store.verify_chain()

from __future__ import annotations

import asyncio
import logging

from app.verifkv.store import VerifKVStore

logger = logging.getLogger(__name__)


class VerifKVWriter:
    """
    Single-consumer ordered writer.

    Producers:
        request handlers -> asyncio.Queue

    Consumer:
        exactly one background task

    Ordering guarantee:
        durable outbox_seq order

    Recovery guarantee:
        startup and periodic reconciliation process all
        outbox records with verifkv_seq IS NULL.
    """

    def __init__(
        self,
        store: VerifKVStore,
        reconcile_interval_seconds: float = 30.0,
    ):
        self.store = store
        self.reconcile_interval_seconds = reconcile_interval_seconds

        self._queue: asyncio.Queue[int | None] = asyncio.Queue()

        self._worker_task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return

        # Critical recovery step:
        # do this before accepting new requests.
        await self.reconcile()

        self._running = True

        self._worker_task = asyncio.create_task(
            self._run(),
            name="verifkv-writer",
        )

    async def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        # Allow the worker to process queued items.
        await self._queue.join()

        if self._worker_task is not None:
            self._worker_task.cancel()

            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

            self._worker_task = None

        # Final reconciliation before shutdown.
        await self.reconcile()

    def notify(
        self,
        outbox_seq: int,
    ) -> None:
        """
        Non-blocking producer operation.

        The request path does NOT wait for the VerifKV writer.

        The durable outbox remains the source of truth if the process
        crashes before this queue item is consumed.
        """
        self._queue.put_nowait(outbox_seq)

    async def reconcile(self) -> None:
        """
        Process every unreconciled durable outbox record in database
        sequence order.
        """

        while True:
            records = await self.store.get_unreconciled_outbox()

            if not records:
                return

            for record in records:
                try:
                    await self.store.fold_outbox_record(record)
                except Exception:
                    logger.exception(
                        "Failed to fold VerifKV outbox_seq=%s",
                        record.outbox_seq,
                    )
                    raise

    async def _run(self) -> None:
        periodic_task = asyncio.create_task(
            self._periodic_reconciliation(),
            name="verifkv-periodic-reconciliation",
        )

        try:
            while self._running:
                outbox_seq = await self._queue.get()

                try:
                    if outbox_seq is None:
                        return

                    # We intentionally reconcile from the durable
                    # outbox rather than assuming queue order is safe.
                    await self.reconcile()

                except Exception:
                    logger.exception("VerifKV writer failed")

                finally:
                    self._queue.task_done()

        finally:
            periodic_task.cancel()

            try:
                await periodic_task
            except asyncio.CancelledError:
                pass

    async def _periodic_reconciliation(
        self,
    ) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.reconcile_interval_seconds)

                await self.reconcile()

            except asyncio.CancelledError:
                return

            except Exception:
                logger.exception("Periodic VerifKV reconciliation failed")

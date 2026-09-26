from __future__ import annotations

import asyncio
import logging

from app.models.verifkv import VerifKVEvent

from verifkv_service.store import VerifKVStore

logger = logging.getLogger(__name__)


class VerifKVWriter:
    """
    Single asynchronous consumer responsible for serializing
    provenance writes.
    """

    def __init__(
        self,
        store: VerifKVStore,
        queue_maxsize: int = 10_000,
    ) -> None:

        self.store = store

        self.queue: asyncio.Queue[VerifKVEvent] = asyncio.Queue(maxsize=queue_maxsize)

        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:

        if self._running:
            return

        self._running = True

        self._task = asyncio.create_task(
            self._run(),
            name="verifkv-writer",
        )

        logger.info("VerifKV writer started")

    async def stop(self) -> None:

        if not self._running:
            return

        self._running = False

        if self._task is not None:

            self._task.cancel()

            try:
                await self._task

            except asyncio.CancelledError:
                pass

            self._task = None

        logger.info("VerifKV writer stopped")

    def enqueue_nowait(
        self,
        event: VerifKVEvent,
    ) -> bool:

        try:

            self.queue.put_nowait(event)

            return True

        except asyncio.QueueFull:

            logger.error(
                "VerifKV writer queue full; " "dropping event=%s",
                event.event_id,
            )

            return False

    async def _run(self) -> None:

        while self._running:

            event = await self.queue.get()

            try:

                sequence_number = await asyncio.to_thread(
                    self.store.append,
                    event,
                )

                logger.debug(
                    "Stored VerifKV event=%s sequence=%s",
                    event.event_id,
                    sequence_number,
                )

            except asyncio.CancelledError:

                raise

            except Exception:

                logger.exception(
                    "Failed to persist VerifKV event=%s",
                    event.event_id,
                )

            finally:

                self.queue.task_done()

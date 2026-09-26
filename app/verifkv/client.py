from __future__ import annotations

import asyncio
import logging

import httpx

from app.models.verifkv import VerifKVEvent

logger = logging.getLogger(__name__)


class VerifKVEventClient:
    """
    Asynchronous client for the external VerifKV provenance service.

    Request-path behavior:
        emit_nowait() -> queue.put_nowait() -> return

    Background behavior:
        queue -> HTTP POST -> VerifKV service
    """

    def __init__(
        self,
        base_url: str,
        queue_maxsize: int = 10_000,
    ) -> None:
        self.base_url = base_url.rstrip("/")

        self.queue: asyncio.Queue[VerifKVEvent] = asyncio.Queue(maxsize=queue_maxsize)

        self._client: httpx.AsyncClient | None = None
        self._worker_task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(
                connect=1.5,
                read=3.0,
                write=3.0,
                pool=3.0,
            ),
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
            ),
        )

        self._running = True

        self._worker_task = asyncio.create_task(
            self._worker(),
            name="verifkv-event-worker",
        )

        logger.info(
            "VerifKV client started: base_url=%s",
            self.base_url,
        )

    async def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        if self._worker_task is not None:
            self._worker_task.cancel()

            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

            self._worker_task = None

        if self._client is not None:
            await self._client.aclose()
            self._client = None

        logger.info("VerifKV client stopped")

    def emit_nowait(self, event: VerifKVEvent) -> bool:
        """
        Non-blocking event submission.

        Returns False when the bounded queue is full.
        """

        if not self._running:
            logger.warning(
                "VerifKV client is not running; dropping event=%s",
                event.event_id,
            )
            return False

        try:
            self.queue.put_nowait(event)

            return True

        except asyncio.QueueFull:
            logger.error(
                "VerifKV queue full; dropping event=%s type=%s",
                event.event_id,
                event.event_type,
            )

            return False

    async def _worker(self) -> None:
        while self._running:

            event = await self.queue.get()

            try:
                await self._send_event(event)

            except asyncio.CancelledError:
                raise

            except Exception:
                logger.exception(
                    "Failed to send VerifKV event=%s",
                    event.event_id,
                )

            finally:
                self.queue.task_done()

    async def _send_event(
        self,
        event: VerifKVEvent,
    ) -> None:

        if self._client is None:
            logger.warning(
                "HTTP client unavailable; dropping event=%s",
                event.event_id,
            )
            return

        response = await self._client.post(
            "/v1/events",
            json=event.model_dump(mode="json"),
        )

        response.raise_for_status()

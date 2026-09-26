from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum

import httpx

from app.models.verifkv import (
    VerifKVEvent,
    VerifKVEventType,
)

from verifkv_service.writer import VerifKVWriter

logger = logging.getLogger(__name__)


class BackendObservation(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


@dataclass(slots=True)
class WatchTarget:
    backend_id: str
    endpoint: str


class BackendWatchdog:
    """
    Independent observer of inference backends.

    It records:
        BACKEND_OBSERVED
        BACKEND_FAILURE_DETECTED
        BACKEND_RECOVERED
        METRIC_SCRAPE_FAILURE

    It does NOT claim that a process "crashed" unless
    there is an explicit infrastructure-level signal proving it.
    """

    def __init__(
        self,
        writer: VerifKVWriter,
        interval_seconds: float = 5.0,
        timeout_seconds: float = 1.5,
    ) -> None:

        self.writer = writer

        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds

        self.targets: list[WatchTarget] = []

        self._states: dict[
            str,
            BackendObservation,
        ] = {}

        self._client: httpx.AsyncClient | None = None
        self._task: asyncio.Task | None = None

        self._running = False

    def set_targets(
        self,
        targets: list[WatchTarget],
    ) -> None:

        self.targets = targets

        for target in targets:

            self._states.setdefault(
                target.backend_id,
                BackendObservation.UNKNOWN,
            )

    async def start(self) -> None:

        if self._running:
            return

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
            ),
        )

        self._running = True

        self._task = asyncio.create_task(
            self._run(),
            name="verifkv-backend-watchdog",
        )

        logger.info("Backend watchdog started")

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

        if self._client is not None:

            await self._client.aclose()

            self._client = None

        logger.info("Backend watchdog stopped")

    async def _run(self) -> None:

        while self._running:

            for target in self.targets:

                try:

                    await self._check_target(target)

                except asyncio.CancelledError:

                    raise

                except Exception:

                    logger.exception(
                        "Unexpected watchdog failure " "for backend=%s",
                        target.backend_id,
                    )

            await asyncio.sleep(self.interval_seconds)

    async def _check_target(
        self,
        target: WatchTarget,
    ) -> None:

        if self._client is None:
            return

        base_url = target.endpoint.rstrip("/")

        health_ok = False
        metrics_ok = False

        try:

            response = await self._client.get(f"{base_url}/health")

            health_ok = response.status_code == 200

        except Exception as exc:

            logger.debug(
                "Health check failed backend=%s error=%s",
                target.backend_id,
                exc,
            )

        try:

            response = await self._client.get(f"{base_url}/metrics")

            metrics_ok = response.status_code == 200

        except Exception as exc:

            logger.debug(
                "Metrics check failed backend=%s error=%s",
                target.backend_id,
                exc,
            )

        current_state = (
            BackendObservation.HEALTHY if health_ok else BackendObservation.UNHEALTHY
        )

        previous_state = self._states.get(
            target.backend_id,
            BackendObservation.UNKNOWN,
        )

        self._states[target.backend_id] = current_state

        if previous_state == BackendObservation.UNKNOWN:

            self.writer.enqueue_nowait(
                VerifKVEvent(
                    event_type=VerifKVEventType.BACKEND_OBSERVED,
                    source="verifkv-watchdog",
                    payload={
                        "backend_id": target.backend_id,
                        "health_ok": health_ok,
                        "metrics_ok": metrics_ok,
                    },
                )
            )

        elif (
            previous_state == BackendObservation.HEALTHY
            and current_state == BackendObservation.UNHEALTHY
        ):

            self.writer.enqueue_nowait(
                VerifKVEvent(
                    event_type=(VerifKVEventType.BACKEND_FAILURE_DETECTED),
                    source="verifkv-watchdog",
                    payload={
                        "backend_id": target.backend_id,
                        "health_ok": health_ok,
                        "metrics_ok": metrics_ok,
                    },
                )
            )

        elif (
            previous_state == BackendObservation.UNHEALTHY
            and current_state == BackendObservation.HEALTHY
        ):

            self.writer.enqueue_nowait(
                VerifKVEvent(
                    event_type=(VerifKVEventType.BACKEND_RECOVERED),
                    source="verifkv-watchdog",
                    payload={
                        "backend_id": target.backend_id,
                        "health_ok": health_ok,
                        "metrics_ok": metrics_ok,
                    },
                )
            )

        if not metrics_ok:

            self.writer.enqueue_nowait(
                VerifKVEvent(
                    event_type=(VerifKVEventType.METRIC_SCRAPE_FAILURE),
                    source="verifkv-watchdog",
                    payload={
                        "backend_id": target.backend_id,
                    },
                )
            )

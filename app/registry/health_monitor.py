from __future__ import annotations

import asyncio
import logging

import httpx

from app.models.enums import (
    BackendStatus,
    HealthStatus,
)
from app.registry.backend_registry import BackendRegistry

logger = logging.getLogger(__name__)


class BackendHealthMonitor:
    """
    Periodically checks backend health and stores the result in memory.

    The request path never performs a health request.

    A failed request may later trigger a reactive check.
    """

    def __init__(
        self,
        registry: BackendRegistry,
        interval_seconds: float = 5.0,
        timeout_seconds: float = 1.5,
    ):
        self.registry = registry
        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds

        self._client: httpx.AsyncClient | None = None
        self._task: asyncio.Task | None = None

        self._running = False

    async def start(self) -> None:
        if self._running:
            return

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
        )

        self._running = True

        self._task = asyncio.create_task(
            self._run(),
            name="backend-health-monitor",
        )

    async def stop(self) -> None:
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

    async def _run(self) -> None:
        while self._running:
            try:
                await self.check_all()
            except Exception:
                logger.exception("Backend health monitoring cycle failed")

            try:
                await asyncio.sleep(self.interval_seconds)
            except asyncio.CancelledError:
                break

    async def check_all(self) -> None:
        client = self._client

        if client is None:
            return

        backends = self.registry.list_available_backends()

        await asyncio.gather(
            *(
                self._check_backend(
                    backend.backend_id,
                )
                for backend in backends
            ),
            return_exceptions=True,
        )

    async def _check_backend(
        self,
        backend_id: str,
    ) -> HealthStatus:
        backend = self.registry.get_backend(backend_id)

        if backend is None:
            return HealthStatus.UNKNOWN

        if backend.endpoint is None:
            await self.registry.update_health(
                backend_id,
                HealthStatus.UNKNOWN,
            )
            return HealthStatus.UNKNOWN

        client = self._client

        if client is None:
            return HealthStatus.UNKNOWN

        health_url = f"{str(backend.endpoint).rstrip('/')}/health"

        try:
            response = await client.get(health_url)

            if response.is_success:
                health = HealthStatus.HEALTHY
            else:
                health = HealthStatus.DEGRADED

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
        ):
            health = HealthStatus.UNHEALTHY

        except Exception:
            health = HealthStatus.UNKNOWN

        await self.registry.update_health(
            backend_id,
            health,
        )

        return health

    async def force_check(
        self,
        backend_id: str,
    ) -> HealthStatus:
        """
        Reactive health check.

        This is NOT called for every request.
        It is intended for recovery after an upstream failure.
        """
        return await self._check_backend(backend_id)

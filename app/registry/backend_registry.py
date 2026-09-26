from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from app.models.backend import Backend
from app.models.enums import (
    BackendStatus,
    HealthStatus,
    Zone,
)

BACKEND_SCHEMA = """
CREATE TABLE IF NOT EXISTS backends (
    backend_id TEXT PRIMARY KEY,

    endpoint TEXT,

    zone TEXT NOT NULL,

    gpu_ids TEXT NOT NULL DEFAULT '[]',

    configured_status TEXT NOT NULL DEFAULT 'unavailable',

    capacity_available INTEGER NOT NULL DEFAULT 0,

    load_percent REAL,

    created_at TEXT NOT NULL,

    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_backends_zone
ON backends(zone);

CREATE INDEX IF NOT EXISTS idx_backends_status
ON backends(configured_status);
"""


class BackendRegistry:
    """
    Durable backend registry with an in-memory hot-path cache.

    Persistent state:
        SQLite

    Request-path reads:
        memory only

    Runtime health:
        maintained in memory by HealthMonitor
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

        self._db: aiosqlite.Connection | None = None

        self._backends: dict[str, Backend] = {}

        self._locks: dict[str, asyncio.Lock] = {}

    async def initialize(self) -> None:
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row

        await self._db.execute("PRAGMA journal_mode = WAL")

        await self._db.execute("PRAGMA synchronous = NORMAL")

        await self._db.execute("PRAGMA busy_timeout = 5000")

        await self._db.executescript(BACKEND_SCHEMA)
        await self._db.commit()

        await self._reload_cache()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _require_db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("BackendRegistry is not initialized")

        return self._db

    def _lock_for(self, backend_id: str) -> asyncio.Lock:
        lock = self._locks.get(backend_id)

        if lock is None:
            lock = asyncio.Lock()
            self._locks[backend_id] = lock

        return lock

    async def _reload_cache(self) -> None:
        db = self._require_db()

        cursor = await db.execute("""
            SELECT
                backend_id,
                endpoint,
                zone,
                gpu_ids,
                configured_status,
                capacity_available,
                load_percent
            FROM backends
            """)

        rows = await cursor.fetchall()

        new_cache: dict[str, Backend] = {}

        for row in rows:
            import json

            endpoint = row["endpoint"]

            backend = Backend(
                backend_id=row["backend_id"],
                endpoint=endpoint,
                zone=Zone(row["zone"]),
                gpu_ids=json.loads(row["gpu_ids"]),
                configured_status=BackendStatus(row["configured_status"]),
                capacity_available=bool(row["capacity_available"]),
                load_percent=row["load_percent"],
                # Runtime health is not persisted as authoritative state.
                health_status=HealthStatus.UNKNOWN,
            )

            new_cache[backend.backend_id] = backend

        self._backends = new_cache

    async def register_backend(
        self,
        backend: Backend,
    ) -> None:
        """
        Administrative operation.

        Registers or replaces a logical serving backend.
        """
        db = self._require_db()

        import json

        now = datetime.now(timezone.utc).isoformat()

        async with self._lock_for(backend.backend_id):
            await db.execute(
                """
                INSERT INTO backends (
                    backend_id,
                    endpoint,
                    zone,
                    gpu_ids,
                    configured_status,
                    capacity_available,
                    load_percent,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(backend_id)
                DO UPDATE SET
                    endpoint = excluded.endpoint,
                    zone = excluded.zone,
                    gpu_ids = excluded.gpu_ids,
                    configured_status = excluded.configured_status,
                    capacity_available = excluded.capacity_available,
                    load_percent = excluded.load_percent,
                    updated_at = excluded.updated_at
                """,
                (
                    backend.backend_id,
                    (str(backend.endpoint) if backend.endpoint is not None else None),
                    backend.zone.value,
                    json.dumps(backend.gpu_ids),
                    backend.configured_status.value,
                    int(backend.capacity_available),
                    backend.load_percent,
                    now,
                    now,
                ),
            )

            await db.commit()

            # Preserve runtime health if this backend already exists.
            previous = self._backends.get(backend.backend_id)

            if previous is not None:
                backend.health_status = previous.health_status

            self._backends[backend.backend_id] = backend

    async def remove_backend(
        self,
        backend_id: str,
    ) -> bool:
        db = self._require_db()

        async with self._lock_for(backend_id):
            result = await db.execute(
                """
                DELETE FROM backends
                WHERE backend_id = ?
                """,
                (backend_id,),
            )

            await db.commit()

            deleted = result.rowcount > 0

            self._backends.pop(
                backend_id,
                None,
            )

            return deleted

    def get_backend(
        self,
        backend_id: str,
    ) -> Backend | None:
        """
        Hot-path memory lookup.
        """
        return self._backends.get(backend_id)

    def list_backends(self) -> list[Backend]:
        """
        Hot-path memory read.
        """
        return list(self._backends.values())

    def list_available_backends(self) -> list[Backend]:
        return [
            backend
            for backend in self._backends.values()
            if (backend.configured_status == BackendStatus.AVAILABLE)
        ]

    async def update_health(
        self,
        backend_id: str,
        health: HealthStatus,
    ) -> None:
        """
        Runtime health is intentionally kept in memory.

        We do not write every health probe to SQLite because health
        is runtime state, not durable configuration.
        """
        backend = self._backends.get(backend_id)

        if backend is not None:
            backend.health_status = health

    async def update_capacity(
        self,
        backend_id: str,
        capacity_available: bool,
        load_percent: float | None = None,
    ) -> None:
        """
        Runtime scheduling metadata.

        Kept in memory on the request path. Persistence can be added
        later if experimental requirements justify it.
        """
        backend = self._backends.get(backend_id)

        if backend is not None:
            backend.capacity_available = capacity_available
            backend.load_percent = load_percent

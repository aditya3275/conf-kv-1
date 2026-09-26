from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from app.models.enums import SecurityLevel, Zone
from app.models.tenant import Tenant

TENANT_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    security_level TEXT NOT NULL,
    allowed_zones TEXT NOT NULL,
    quota_limit INTEGER NOT NULL CHECK (quota_limit > 0),
    quota_used INTEGER NOT NULL DEFAULT 0 CHECK (quota_used >= 0),
    kv_isolation_required INTEGER NOT NULL DEFAULT 1,
    cache_salt TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_credentials_key_hash
ON credentials(key_hash);

CREATE INDEX IF NOT EXISTS idx_credentials_tenant_id
ON credentials(tenant_id);
"""


def hash_api_key(api_key: str) -> str:
    """
    API keys are generated with high entropy, so a fast cryptographic
    hash is appropriate for lookup without adding password-KDF latency
    to every authenticated request.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    """
    Generates a high-entropy bearer credential.

    The raw credential is returned only once.
    """
    return "cks_" + secrets.token_urlsafe(32)


def generate_cache_salt() -> str:
    """
    Generates an unpredictable tenant-specific cache salt.
    """
    return secrets.token_hex(32)


class TenantRegistry:
    """
    Cache-first tenant registry.

    Hot path:
        memory only

    Durable state:
        SQLite via aiosqlite

    SQLite is not used for normal tenant reads during request handling.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path

        self._db: aiosqlite.Connection | None = None

        self._tenants: dict[str, Tenant] = {}

        # Only active credentials are kept in this lookup cache.
        self._credential_hash_to_tenant: dict[str, str] = {}

        # Serializes state-changing operations for an individual tenant.
        self._tenant_locks: dict[str, asyncio.Lock] = {}

    async def initialize(self) -> None:
        """
        Open SQLite, create Phase-2 schema, and warm the in-memory cache.
        """
        db_path = Path(self.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row

        await self._db.execute("PRAGMA foreign_keys = ON")
        await self._db.execute("PRAGMA journal_mode = WAL")
        await self._db.execute("PRAGMA synchronous = NORMAL")
        await self._db.execute("PRAGMA busy_timeout = 5000")

        await self._db.executescript(TENANT_SCHEMA)
        await self._db.commit()

        await self._reload_cache()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _require_db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("TenantRegistry is not initialized")

        return self._db

    def _lock_for(self, tenant_id: str) -> asyncio.Lock:
        lock = self._tenant_locks.get(tenant_id)

        if lock is None:
            lock = asyncio.Lock()
            self._tenant_locks[tenant_id] = lock

        return lock

    async def _reload_cache(self) -> None:
        db = self._require_db()

        tenants_cursor = await db.execute("""
            SELECT
                tenant_id,
                security_level,
                allowed_zones,
                quota_limit,
                quota_used,
                kv_isolation_required,
                cache_salt,
                active
            FROM tenants
            """)

        tenant_rows = await tenants_cursor.fetchall()

        credentials_cursor = await db.execute("""
            SELECT key_hash, tenant_id
            FROM credentials
            WHERE active = 1
            """)

        credential_rows = await credentials_cursor.fetchall()

        tenants: dict[str, Tenant] = {}

        for row in tenant_rows:
            tenant = Tenant(
                tenant_id=row["tenant_id"],
                security_level=SecurityLevel(row["security_level"]),
                allowed_zones=[Zone(zone) for zone in json.loads(row["allowed_zones"])],
                quota_limit=row["quota_limit"],
                quota_used=row["quota_used"],
                kv_isolation_required=bool(row["kv_isolation_required"]),
                cache_salt=row["cache_salt"],
                active=bool(row["active"]),
            )

            tenants[tenant.tenant_id] = tenant

        credential_map: dict[str, str] = {}

        for row in credential_rows:
            credential_map[row["key_hash"]] = row["tenant_id"]

        self._tenants = tenants
        self._credential_hash_to_tenant = credential_map

    async def create_tenant(
        self,
        tenant_id: str,
        security_level: SecurityLevel,
        allowed_zones: list[Zone],
        quota_limit: int = 1000,
        kv_isolation_required: bool = True,
    ) -> tuple[Tenant, str]:
        """
        Creates a tenant and its initial API credential.

        Returns:
            (Tenant, raw_api_key)

        The raw API key is returned once and is never persisted.
        """
        if not allowed_zones:
            raise ValueError("At least one allowed zone is required")

        db = self._require_db()

        cache_salt = generate_cache_salt()
        raw_api_key = generate_api_key()
        key_hash = hash_api_key(raw_api_key)

        credential_id = secrets.token_hex(16)

        now = datetime.now(timezone.utc).isoformat()

        async with self._lock_for(tenant_id):
            await db.execute(
                """
                INSERT INTO tenants (
                    tenant_id,
                    security_level,
                    allowed_zones,
                    quota_limit,
                    quota_used,
                    kv_isolation_required,
                    cache_salt,
                    active,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, 0, ?, ?, 1, ?, ?)
                """,
                (
                    tenant_id,
                    security_level.value,
                    json.dumps([zone.value for zone in allowed_zones]),
                    quota_limit,
                    int(kv_isolation_required),
                    cache_salt,
                    now,
                    now,
                ),
            )

            await db.execute(
                """
                INSERT INTO credentials (
                    credential_id,
                    tenant_id,
                    key_hash,
                    active,
                    created_at
                )
                VALUES (?, ?, ?, 1, ?)
                """,
                (
                    credential_id,
                    tenant_id,
                    key_hash,
                    now,
                ),
            )

            await db.commit()

            tenant = Tenant(
                tenant_id=tenant_id,
                security_level=security_level,
                allowed_zones=allowed_zones,
                quota_limit=quota_limit,
                quota_used=0,
                kv_isolation_required=kv_isolation_required,
                cache_salt=cache_salt,
                active=True,
            )

            # Update hot-path caches only after durable commit succeeds.
            self._tenants[tenant_id] = tenant
            self._credential_hash_to_tenant[key_hash] = tenant_id

        return tenant, raw_api_key

    async def create_credential(
        self,
        tenant_id: str,
    ) -> str:
        """
        Creates an additional credential for an existing tenant.
        """
        db = self._require_db()

        async with self._lock_for(tenant_id):
            tenant = self._tenants.get(tenant_id)

            if tenant is None:
                raise KeyError(f"Unknown tenant: {tenant_id}")

            raw_api_key = generate_api_key()
            key_hash = hash_api_key(raw_api_key)
            credential_id = secrets.token_hex(16)

            await db.execute(
                """
                INSERT INTO credentials (
                    credential_id,
                    tenant_id,
                    key_hash,
                    active,
                    created_at
                )
                VALUES (?, ?, ?, 1, ?)
                """,
                (
                    credential_id,
                    tenant_id,
                    key_hash,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

            await db.commit()

            self._credential_hash_to_tenant[key_hash] = tenant_id

            return raw_api_key

    async def revoke_credential(
        self,
        api_key: str,
    ) -> None:
        """
        Revokes an API credential.

        The credential is removed from the in-memory authentication
        cache only after SQLite confirms the revocation.
        """
        db = self._require_db()

        key_hash = hash_api_key(api_key)
        tenant_id = self._credential_hash_to_tenant.get(key_hash)

        if tenant_id is None:
            return

        async with self._lock_for(tenant_id):
            now = datetime.now(timezone.utc).isoformat()

            await db.execute(
                """
                UPDATE credentials
                SET active = 0,
                    revoked_at = ?
                WHERE key_hash = ?
                """,
                (now, key_hash),
            )

            await db.commit()

            self._credential_hash_to_tenant.pop(
                key_hash,
                None,
            )

    def get_tenant(
        self,
        tenant_id: str,
    ) -> Tenant | None:
        """
        Hot-path memory lookup.
        """
        return self._tenants.get(tenant_id)

    def resolve_by_api_key(
        self,
        api_key: str,
    ) -> Tenant | None:
        """
        Hot-path authentication lookup.

        No database I/O occurs here.
        """
        key_hash = hash_api_key(api_key)

        tenant_id = self._credential_hash_to_tenant.get(key_hash)

        if tenant_id is None:
            return None

        tenant = self._tenants.get(tenant_id)

        if tenant is None or not tenant.active:
            return None

        return tenant

    async def set_active(
        self,
        tenant_id: str,
        active: bool,
    ) -> None:
        """
        Administrative tenant activation/deactivation.
        """
        db = self._require_db()

        async with self._lock_for(tenant_id):
            tenant = self._tenants.get(tenant_id)

            if tenant is None:
                raise KeyError(f"Unknown tenant: {tenant_id}")

            await db.execute(
                """
                UPDATE tenants
                SET active = ?,
                    updated_at = ?
                WHERE tenant_id = ?
                """,
                (
                    int(active),
                    datetime.now(timezone.utc).isoformat(),
                    tenant_id,
                ),
            )

            await db.commit()

            tenant.active = active

    async def rotate_cache_salt(
        self,
        tenant_id: str,
    ) -> str:
        """
        Administrative cache-salt rotation.
        """
        db = self._require_db()

        async with self._lock_for(tenant_id):
            tenant = self._tenants.get(tenant_id)

            if tenant is None:
                raise KeyError(f"Unknown tenant: {tenant_id}")

            new_salt = generate_cache_salt()

            await db.execute(
                """
                UPDATE tenants
                SET cache_salt = ?,
                    updated_at = ?
                WHERE tenant_id = ?
                """,
                (
                    new_salt,
                    datetime.now(timezone.utc).isoformat(),
                    tenant_id,
                ),
            )

            await db.commit()

            tenant.cache_salt = new_salt

            return new_salt

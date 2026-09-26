from __future__ import annotations

import sqlite3

import pytest

from app.models.enums import SecurityLevel, Zone
from app.registry.tenant_registry import TenantRegistry


@pytest.fixture
async def tenant_registry(tmp_path):
    db_path = tmp_path / "control_plane.db"

    registry = TenantRegistry(db_path=str(db_path))

    await registry.initialize()

    yield registry

    await registry.close()


async def create_test_tenant(
    registry: TenantRegistry,
    tenant_id: str = "tenant-001",
):
    return await registry.create_tenant(
        tenant_id,
        SecurityLevel.STANDARD,
        [Zone.GENERAL],
        10,
        True,
    )


@pytest.mark.asyncio
async def test_initialize_creates_control_plane_schema(
    tenant_registry,
) -> None:

    assert tenant_registry._db is not None

    cursor = await tenant_registry._db.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'tenants'
        """)

    row = await cursor.fetchone()

    assert row is not None
    assert row["name"] == "tenants"


@pytest.mark.asyncio
async def test_create_tenant_returns_raw_api_key_once(
    tenant_registry,
) -> None:

    tenant, api_key = await create_test_tenant(tenant_registry)

    assert tenant.tenant_id == "tenant-001"

    assert isinstance(
        api_key,
        str,
    )

    assert api_key.startswith("cks_")

    assert api_key


@pytest.mark.asyncio
async def test_invalid_api_key_is_rejected(
    tenant_registry,
) -> None:

    await create_test_tenant(tenant_registry)

    resolved = tenant_registry.resolve_by_api_key("cks_invalid_key")

    assert resolved is None


@pytest.mark.asyncio
async def test_raw_api_key_is_not_stored(
    tenant_registry,
) -> None:

    tenant, api_key = await create_test_tenant(tenant_registry)

    assert tenant_registry._db is not None

    # ---------------------------------------------------------
    # The current architecture keeps credentials separate
    # from tenant metadata.
    # ---------------------------------------------------------

    cursor = await tenant_registry._db.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        """)

    tables = await cursor.fetchall()

    table_names = {row["name"] for row in tables}

    assert "credentials" in table_names

    # ---------------------------------------------------------
    # Discover the hash column from the credentials table.
    # This keeps the test independent of the exact credential
    # column naming.
    # ---------------------------------------------------------

    cursor = await tenant_registry._db.execute("""
        PRAGMA table_info(credentials)
        """)

    columns = await cursor.fetchall()

    hash_columns = [
        column["name"] for column in columns if "hash" in column["name"].lower()
    ]

    assert hash_columns

    hash_column = hash_columns[0]

    # Column names cannot be bound using ? placeholders, so quote
    # the discovered identifier safely.
    quoted_column = '"' + hash_column.replace('"', '""') + '"'

    cursor = await tenant_registry._db.execute(f"""
        SELECT {quoted_column}
        FROM credentials
        """)

    rows = await cursor.fetchall()

    assert rows

    stored_values = [row[hash_column] for row in rows]

    # The raw API key must never appear in the credential store.
    assert api_key not in stored_values

    # A SHA-256 hash is 64 hexadecimal characters.
    matching_hashes = [
        value for value in stored_values if isinstance(value, str) and len(value) == 64
    ]

    assert matching_hashes


@pytest.mark.asyncio
async def test_credential_can_be_revoked(
    tenant_registry,
) -> None:

    tenant, api_key = await create_test_tenant(tenant_registry)

    # Credential works before revocation.
    resolved_before = tenant_registry.resolve_by_api_key(api_key)

    assert resolved_before is not None

    # Deactivate/revoke the tenant.
    await tenant_registry.set_active(
        tenant.tenant_id,
        False,
    )

    # The current registry removes the credential from the
    # effective authentication path.
    resolved_after = tenant_registry.resolve_by_api_key(api_key)

    assert resolved_after is None


@pytest.mark.asyncio
async def test_inactive_tenant_cannot_authenticate(
    tenant_registry,
) -> None:

    tenant, api_key = await create_test_tenant(tenant_registry)

    await tenant_registry.set_active(
        tenant.tenant_id,
        False,
    )

    resolved = tenant_registry.resolve_by_api_key(api_key)

    assert resolved is None


@pytest.mark.asyncio
async def test_cache_salt_rotation_updates_memory_and_database(
    tenant_registry,
) -> None:

    tenant, api_key = await create_test_tenant(tenant_registry)

    original_salt = tenant.cache_salt

    new_salt = await tenant_registry.rotate_cache_salt(tenant.tenant_id)

    assert new_salt is not None

    assert isinstance(
        new_salt,
        str,
    )

    assert new_salt != original_salt

    # ---------------------------------------------------------
    # Verify in-memory state.
    # ---------------------------------------------------------

    cached_tenant = tenant_registry.get_tenant(tenant.tenant_id)

    assert cached_tenant is not None

    assert cached_tenant.cache_salt == new_salt

    # ---------------------------------------------------------
    # Verify durable tenant metadata.
    # ---------------------------------------------------------

    assert tenant_registry._db is not None

    cursor = await tenant_registry._db.execute(
        """
        SELECT cache_salt
        FROM tenants
        WHERE tenant_id = ?
        """,
        (tenant.tenant_id,),
    )

    row = await cursor.fetchone()

    assert row is not None

    assert row["cache_salt"] == new_salt

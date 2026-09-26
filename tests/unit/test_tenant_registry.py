import aiosqlite
import pytest

from app.models.enums import SecurityLevel, Zone
from app.registry.tenant_registry import (
    TenantRegistry,
    hash_api_key,
)


@pytest.fixture
async def registry(tmp_path):
    db_path = tmp_path / "control_plane.db"

    registry = TenantRegistry(str(db_path))

    await registry.initialize()

    yield registry

    await registry.close()


@pytest.mark.asyncio
async def test_initialize_creates_control_plane_schema(
    registry,
):
    db = registry._db
    assert db is not None

    cursor = await db.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
        """)

    tables = {row[0] for row in await cursor.fetchall()}

    assert "tenants" in tables
    assert "credentials" in tables


@pytest.mark.asyncio
async def test_create_tenant_returns_raw_api_key_once(
    registry,
):
    tenant, api_key = await registry.create_tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.HIGH,
        allowed_zones=[Zone.SECURE],
        quota_limit=100,
    )

    assert tenant.tenant_id == "tenant-a"
    assert api_key.startswith("cks_")

    resolved = registry.resolve_by_api_key(api_key)

    assert resolved is not None
    assert resolved.tenant_id == "tenant-a"


@pytest.mark.asyncio
async def test_invalid_api_key_is_rejected(
    registry,
):
    await registry.create_tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.HIGH,
        allowed_zones=[Zone.SECURE],
    )

    assert registry.resolve_by_api_key("cks_invalid") is None


@pytest.mark.asyncio
async def test_raw_api_key_is_not_stored(
    registry,
):
    _, api_key = await registry.create_tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.STANDARD,
        allowed_zones=[Zone.GENERAL],
    )

    db = registry._db
    assert db is not None

    cursor = await db.execute("SELECT key_hash FROM credentials")

    rows = await cursor.fetchall()

    assert len(rows) == 1
    assert rows[0]["key_hash"] == hash_api_key(api_key)
    assert rows[0]["key_hash"] != api_key


@pytest.mark.asyncio
async def test_credential_can_be_revoked(
    registry,
):
    _, api_key = await registry.create_tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.STANDARD,
        allowed_zones=[Zone.GENERAL],
    )

    assert registry.resolve_by_api_key(api_key) is not None

    await registry.revoke_credential(api_key)

    assert registry.resolve_by_api_key(api_key) is None


@pytest.mark.asyncio
async def test_inactive_tenant_cannot_authenticate(
    registry,
):
    _, api_key = await registry.create_tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.HIGH,
        allowed_zones=[Zone.SECURE],
    )

    await registry.set_active(
        "tenant-a",
        False,
    )

    assert registry.resolve_by_api_key(api_key) is None


@pytest.mark.asyncio
async def test_cache_salt_rotation_updates_memory_and_database(
    registry,
):
    tenant, _ = await registry.create_tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.HIGH,
        allowed_zones=[Zone.SECURE],
    )

    old_salt = tenant.cache_salt.get_secret_value()

    new_salt = await registry.rotate_cache_salt("tenant-a")

    assert new_salt != old_salt

    updated = registry.get_tenant("tenant-a")

    assert updated is not None

    assert updated.cache_salt.get_secret_value() == new_salt

    db = registry._db
    assert db is not None

    cursor = await db.execute(
        """
        SELECT cache_salt
        FROM tenants
        WHERE tenant_id = ?
        """,
        ("tenant-a",),
    )

    row = await cursor.fetchone()

    assert row["cache_salt"] == new_salt

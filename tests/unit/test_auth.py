import pytest
from fastapi import Header

from app.gateway.auth import (
    AuthenticationError,
    extract_bearer_token,
    make_authenticator,
)
from app.models.enums import SecurityLevel, Zone
from app.registry.tenant_registry import TenantRegistry


def test_extract_bearer_token() -> None:
    assert extract_bearer_token("Bearer cks_test123") == "cks_test123"


def test_extract_bearer_token_is_case_insensitive() -> None:
    assert extract_bearer_token("bearer cks_test123") == "cks_test123"


def test_extract_bearer_token_rejects_invalid_scheme() -> None:
    with pytest.raises(AuthenticationError):
        extract_bearer_token("Basic cks_test123")


@pytest.mark.asyncio
async def test_authenticator_resolves_tenant(
    tmp_path,
):
    registry = TenantRegistry(str(tmp_path / "control_plane.db"))

    await registry.initialize()

    try:
        tenant, api_key = await registry.create_tenant(
            tenant_id="tenant-a",
            security_level=SecurityLevel.HIGH,
            allowed_zones=[Zone.SECURE],
        )

        authenticate = make_authenticator(registry)

        result = await authenticate(authorization=f"Bearer {api_key}")

        assert result.tenant_id == tenant.tenant_id

    finally:
        await registry.close()


@pytest.mark.asyncio
async def test_authenticator_rejects_invalid_credentials(
    tmp_path,
):
    registry = TenantRegistry(str(tmp_path / "control_plane.db"))

    await registry.initialize()

    try:
        authenticate = make_authenticator(registry)

        with pytest.raises(AuthenticationError):
            await authenticate(authorization="Bearer cks_invalid")

    finally:
        await registry.close()


@pytest.mark.asyncio
async def test_authenticator_rejects_missing_header(
    tmp_path,
):
    registry = TenantRegistry(str(tmp_path / "control_plane.db"))

    await registry.initialize()

    try:
        authenticate = make_authenticator(registry)

        with pytest.raises(AuthenticationError):
            await authenticate(authorization="")

    finally:
        await registry.close()

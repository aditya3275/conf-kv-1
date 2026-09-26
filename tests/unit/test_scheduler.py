import pytest

from app.models.backend import Backend
from app.models.enums import (
    BackendStatus,
    HealthStatus,
    SecurityLevel,
    Zone,
)
from app.models.tenant import Tenant
from app.registry.backend_registry import BackendRegistry
from app.scheduler.scheduler import (
    NoBackendAvailableError,
    SecurityAwareScheduler,
)


@pytest.fixture
async def registry(tmp_path):
    registry = BackendRegistry(str(tmp_path / "control_plane.db"))

    await registry.initialize()

    yield registry

    await registry.close()


def make_tenant(
    security_level=SecurityLevel.HIGH,
    zones=None,
) -> Tenant:
    return Tenant(
        tenant_id="tenant-a",
        security_level=security_level,
        allowed_zones=zones or [Zone.SECURE],
        quota_limit=100,
        quota_used=0,
        kv_isolation_required=True,
        cache_salt="test-secret",
        active=True,
    )


async def add_backend(
    registry,
    backend_id,
    zone,
    load,
):
    backend = Backend(
        backend_id=backend_id,
        endpoint=f"http://127.0.0.1:800{load}",
        zone=zone,
        gpu_ids=[load],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.HEALTHY,
        capacity_available=True,
        load_percent=float(load),
    )

    await registry.register_backend(backend)

    await registry.update_health(
        backend_id,
        HealthStatus.HEALTHY,
    )


@pytest.mark.asyncio
async def test_high_security_tenant_prefers_secure_backend(
    registry,
):
    secure = Backend(
        backend_id="secure",
        endpoint="http://127.0.0.1:8001",
        zone=Zone.SECURE,
        gpu_ids=[0],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.HEALTHY,
        capacity_available=True,
        load_percent=80,
    )

    general = Backend(
        backend_id="general",
        endpoint="http://127.0.0.1:8002",
        zone=Zone.GENERAL,
        gpu_ids=[1],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.HEALTHY,
        capacity_available=True,
        load_percent=10,
    )

    await registry.register_backend(secure)
    await registry.register_backend(general)

    # Both zones are allowed for this test.
    tenant = make_tenant(
        security_level=SecurityLevel.HIGH,
        zones=[Zone.SECURE, Zone.GENERAL],
    )

    scheduler = SecurityAwareScheduler(registry)

    recommendation = scheduler.recommend(tenant)

    assert recommendation.backend_id == "secure"
    assert recommendation.zone == Zone.SECURE


@pytest.mark.asyncio
async def test_standard_tenant_prefers_lower_load(
    registry,
):
    first = Backend(
        backend_id="backend-a",
        endpoint="http://127.0.0.1:8001",
        zone=Zone.GENERAL,
        gpu_ids=[0],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.HEALTHY,
        capacity_available=True,
        load_percent=20,
    )

    second = Backend(
        backend_id="backend-b",
        endpoint="http://127.0.0.1:8002",
        zone=Zone.GENERAL,
        gpu_ids=[1],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.HEALTHY,
        capacity_available=True,
        load_percent=70,
    )

    await registry.register_backend(first)
    await registry.register_backend(second)

    tenant = make_tenant(
        security_level=SecurityLevel.STANDARD,
        zones=[Zone.GENERAL],
    )

    scheduler = SecurityAwareScheduler(registry)

    recommendation = scheduler.recommend(tenant)

    assert recommendation.backend_id == "backend-a"


@pytest.mark.asyncio
async def test_unhealthy_backend_is_not_recommended(
    registry,
):
    backend = Backend(
        backend_id="unhealthy",
        endpoint="http://127.0.0.1:8001",
        zone=Zone.SECURE,
        gpu_ids=[0],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.UNHEALTHY,
        capacity_available=True,
    )

    await registry.register_backend(backend)

    scheduler = SecurityAwareScheduler(registry)

    tenant = make_tenant()

    with pytest.raises(NoBackendAvailableError):
        scheduler.recommend(tenant)


@pytest.mark.asyncio
async def test_backend_outside_allowed_zone_is_not_recommended(
    registry,
):
    backend = Backend(
        backend_id="general",
        endpoint="http://127.0.0.1:8001",
        zone=Zone.GENERAL,
        gpu_ids=[0],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.HEALTHY,
        capacity_available=True,
    )

    await registry.register_backend(backend)

    scheduler = SecurityAwareScheduler(registry)

    tenant = make_tenant(
        security_level=SecurityLevel.HIGH,
        zones=[Zone.SECURE],
    )

    with pytest.raises(NoBackendAvailableError):
        scheduler.recommend(tenant)

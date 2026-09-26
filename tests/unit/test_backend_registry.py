import pytest

from app.models.backend import Backend
from app.models.enums import (
    BackendStatus,
    HealthStatus,
    Zone,
)
from app.registry.backend_registry import (
    BackendRegistry,
)


@pytest.fixture
async def registry(tmp_path):
    registry = BackendRegistry(str(tmp_path / "control_plane.db"))

    await registry.initialize()

    yield registry

    await registry.close()


@pytest.mark.asyncio
async def test_register_backend(
    registry,
):
    backend = Backend(
        backend_id="vllm-secure-01",
        endpoint="http://127.0.0.1:8001",
        zone=Zone.SECURE,
        gpu_ids=[0],
        configured_status=BackendStatus.AVAILABLE,
        capacity_available=True,
    )

    await registry.register_backend(backend)

    result = registry.get_backend("vllm-secure-01")

    assert result is not None
    assert result.zone == Zone.SECURE
    assert result.gpu_ids == [0]
    assert result.health_status == HealthStatus.UNKNOWN


@pytest.mark.asyncio
async def test_backend_registry_hot_path_is_memory_only(
    registry,
):
    backend = Backend(
        backend_id="vllm-general-01",
        endpoint="http://127.0.0.1:8002",
        zone=Zone.GENERAL,
        gpu_ids=[1],
        configured_status=BackendStatus.AVAILABLE,
        capacity_available=True,
    )

    await registry.register_backend(backend)

    result = registry.get_backend("vllm-general-01")

    assert result is backend


@pytest.mark.asyncio
async def test_health_is_runtime_state(
    registry,
):
    backend = Backend(
        backend_id="vllm-secure-01",
        endpoint="http://127.0.0.1:8001",
        zone=Zone.SECURE,
        gpu_ids=[0],
        configured_status=BackendStatus.AVAILABLE,
        capacity_available=True,
    )

    await registry.register_backend(backend)

    assert backend.health_status == HealthStatus.UNKNOWN

    await registry.update_health(
        backend.backend_id,
        HealthStatus.HEALTHY,
    )

    assert (
        registry.get_backend(backend.backend_id).health_status == HealthStatus.HEALTHY
    )


@pytest.mark.asyncio
async def test_remove_backend(
    registry,
):
    backend = Backend(
        backend_id="vllm-general-01",
        zone=Zone.GENERAL,
    )

    await registry.register_backend(backend)

    removed = await registry.remove_backend(backend.backend_id)

    assert removed is True
    assert registry.get_backend(backend.backend_id) is None

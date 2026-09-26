from uuid import uuid4

import pytest

from app.enforcement.cache_policy import (
    build_cache_policy,
)
from app.enforcement.router import (
    EnforcementRouter,
    RoutingError,
)
from app.models.backend import Backend
from app.models.enums import (
    BackendStatus,
    HealthStatus,
    SecurityLevel,
    Zone,
)
from app.models.opa import (
    OPAResponse,
    OPAResult,
)
from app.models.tenant import Tenant


def make_tenant() -> Tenant:
    return Tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.HIGH,
        allowed_zones=[Zone.SECURE],
        quota_limit=100,
        quota_used=0,
        kv_isolation_required=True,
        cache_salt="secret-value",
        active=True,
    )


def make_backend() -> Backend:
    return Backend(
        backend_id="vllm-secure-01",
        endpoint="http://127.0.0.1:8001",
        zone=Zone.SECURE,
        gpu_ids=[0],
        configured_status=BackendStatus.AVAILABLE,
        health_status=HealthStatus.HEALTHY,
        capacity_available=True,
    )


def test_build_authorized_route():
    tenant = make_tenant()
    backend = make_backend()

    response = OPAResponse(
        result=OPAResult(
            allow=True,
            decision_id="decision-001",
            policy_version="v1",
            reason="allowed",
        )
    )

    cache_policy = build_cache_policy(tenant)

    route = EnforcementRouter.build_route(
        request_id=uuid4(),
        backend=backend,
        opa_response=response,
        cache_policy=cache_policy,
    )

    assert route.backend_id == "vllm-secure-01"

    assert route.zone == Zone.SECURE

    assert route.decision_id == "decision-001"

    assert route.cache_policy.namespace == "tenant:tenant-a"


def test_denied_decision_cannot_create_route():
    tenant = make_tenant()
    backend = make_backend()

    response = OPAResponse(
        result=OPAResult(
            allow=False,
            decision_id="decision-002",
            policy_version="v1",
            reason="denied",
        )
    )

    cache_policy = build_cache_policy(tenant)

    with pytest.raises(RoutingError):
        EnforcementRouter.build_route(
            request_id=uuid4(),
            backend=backend,
            opa_response=response,
            cache_policy=cache_policy,
        )


def test_missing_backend_endpoint_cannot_create_route():
    tenant = make_tenant()

    backend = Backend(
        backend_id="vllm-secure-01",
        endpoint=None,
        zone=Zone.SECURE,
    )

    response = OPAResponse(
        result=OPAResult(
            allow=True,
            decision_id="decision-003",
            policy_version="v1",
            reason="allowed",
        )
    )

    cache_policy = build_cache_policy(tenant)

    with pytest.raises(RoutingError):
        EnforcementRouter.build_route(
            request_id=uuid4(),
            backend=backend,
            opa_response=response,
            cache_policy=cache_policy,
        )

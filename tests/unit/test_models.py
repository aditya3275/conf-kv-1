from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models.backend import Backend
from app.models.cache import CachePolicy
from app.models.enums import (
    BackendStatus,
    HealthStatus,
    SecurityLevel,
    Zone,
)
from app.models.inference import (
    ClientInferenceRequest,
    InferenceRequest,
)
from app.models.opa import (
    OPARequest,
    OPAResponse,
    OPAResult,
    PolicyInput,
)
from app.models.outbox import OutboxRecord
from app.models.routing import ApprovedRoute
from app.models.scheduling import SchedulingRecommendation
from app.models.tenant import Tenant


def test_client_request_does_not_contain_trusted_tenant_identity() -> None:
    request = ClientInferenceRequest(
        model="test-model",
        messages=[
            {"role": "user", "content": "hello"},
        ],
    )

    assert not hasattr(request, "tenant_id")


def test_inference_request_generates_request_id() -> None:
    request = InferenceRequest(
        tenant_id="tenant-a",
        model="test-model",
        messages=[
            {"role": "user", "content": "hello"},
        ],
    )

    assert request.request_id is not None


def test_invalid_tenant_quota_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Tenant(
            tenant_id="tenant-a",
            security_level=SecurityLevel.HIGH,
            allowed_zones=[Zone.SECURE],
            quota_limit=0,
            quota_used=0,
            kv_isolation_required=True,
            cache_salt="secret",
        )


def test_tenant_quota_remaining() -> None:
    tenant = Tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.HIGH,
        allowed_zones=[Zone.SECURE],
        quota_limit=10,
        quota_used=3,
        kv_isolation_required=True,
        cache_salt="secret",
    )

    assert tenant.quota_remaining == 7


def test_backend_defaults_to_unknown_health_and_unavailable_status() -> None:
    backend = Backend(
        backend_id="vllm-secure-01",
        zone=Zone.SECURE,
    )

    assert backend.configured_status == BackendStatus.UNAVAILABLE
    assert backend.health_status == HealthStatus.UNKNOWN
    assert backend.endpoint is None
    assert backend.gpu_ids == []


def test_backend_gpu_ids_are_not_shared_between_instances() -> None:
    backend_a = Backend(
        backend_id="a",
        zone=Zone.GENERAL,
    )

    backend_b = Backend(
        backend_id="b",
        zone=Zone.GENERAL,
    )

    backend_a.gpu_ids.append(0)

    assert backend_b.gpu_ids == []


def test_scheduler_recommendation() -> None:
    recommendation = SchedulingRecommendation(
        backend_id="vllm-secure-01",
        zone=Zone.SECURE,
        reason="high-security tenant requires secure zone",
    )

    assert recommendation.backend_id == "vllm-secure-01"


def test_opa_contract() -> None:
    payload = PolicyInput(
        tenant={
            "id": "tenant-a",
            "security_level": SecurityLevel.HIGH,
            "allowed_zones": [Zone.SECURE],
            "active": True,
            "quota_remaining": 5,
            "kv_isolation_required": True,
        },
        recommendation={
            "backend_id": "vllm-secure-01",
            "zone": Zone.SECURE,
        },
        resource={
            "backend_id": "vllm-secure-01",
            "configured_status": BackendStatus.AVAILABLE,
            "health_status": HealthStatus.HEALTHY,
            "capacity_available": True,
        },
    )

    request = OPARequest(input=payload)

    assert request.input.tenant.id == "tenant-a"
    assert request.input.recommendation.backend_id == "vllm-secure-01"


def test_opa_response_contract() -> None:
    response = OPAResponse(
        result=OPAResult(
            allow=True,
            decision_id="decision-001",
            policy_version="v1",
            reason="allowed",
        )
    )

    assert response.result.allow is True
    assert response.result.decision_id == "decision-001"


def test_cache_salt_is_secret() -> None:
    policy = CachePolicy(
        isolation_required=True,
        namespace="tenant-a",
        cache_salt="super-secret",
    )

    serialized = policy.model_dump()

    assert serialized["cache_salt"] != "super-secret"


def test_outbox_record_supports_unprocessed_state() -> None:
    record = OutboxRecord(
        authorization_event_id="authz-event-001",
        request_id=str(uuid4()),
        tenant_id="tenant-a",
        decision=True,
        backend_id="vllm-secure-01",
        zone=Zone.SECURE.value,
        decision_id="decision-001",
        policy_version="v1",
        timestamp=datetime.now(timezone.utc),
    )

    assert record.outbox_seq is None
    assert record.verifkv_seq is None


def test_outbox_record_supports_reconciliation_state() -> None:
    record = OutboxRecord(
        outbox_seq=10,
        authorization_event_id="authz-event-001",
        request_id=str(uuid4()),
        tenant_id="tenant-a",
        decision=True,
        backend_id="vllm-secure-01",
        zone=Zone.SECURE.value,
        decision_id="decision-001",
        policy_version="v1",
        timestamp=datetime.now(timezone.utc),
        verifkv_seq=42,
    )

    assert record.outbox_seq == 10
    assert record.verifkv_seq == 42

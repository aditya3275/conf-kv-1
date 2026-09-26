from app.models.enums import (
    BackendStatus,
    HealthStatus,
    SecurityLevel,
    Zone,
)
from app.models.opa import (
    OPARequest,
    OPAResponse,
    OPAResult,
    PolicyInput,
)


def test_opa_request_does_not_include_request_id():
    request = OPARequest(
        input=PolicyInput(
            tenant={
                "id": "tenant-a",
                "security_level": SecurityLevel.HIGH,
                "allowed_zones": [Zone.SECURE],
                "active": True,
                "quota_remaining": 100,
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
    )

    payload = request.model_dump()

    assert "request_id" not in payload
    assert "request_id" not in payload["input"]


def test_opa_response_contract():
    response = OPAResponse(
        result=OPAResult(
            allow=True,
            decision_id="decision-fingerprint",
            policy_version="v1",
            reason="allowed",
        )
    )

    assert response.result.allow is True
    assert response.result.policy_version == "v1"
    assert response.result.reason == "allowed"

from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.enums import (
    BackendStatus,
    HealthStatus,
    SecurityLevel,
    Zone,
)
from app.models.scheduling import SchedulingRecommendation
from app.models.tenant import Tenant


class OPATenantInput(BaseModel):
    id: str = Field(min_length=1)

    security_level: SecurityLevel

    allowed_zones: list[Zone] = Field(min_length=1)

    active: bool

    quota_remaining: int = Field(ge=0)

    kv_isolation_required: bool


class OPARecommendationInput(BaseModel):
    backend_id: str = Field(min_length=1)

    zone: Zone


class OPAResourceInput(BaseModel):
    backend_id: str = Field(min_length=1)

    configured_status: BackendStatus

    health_status: HealthStatus

    capacity_available: bool


class PolicyInput(BaseModel):
    """
    Canonical semantic input to OPA.

    request_id is intentionally excluded.
    """

    tenant: OPATenantInput

    recommendation: OPARecommendationInput

    resource: OPAResourceInput


class OPARequest(BaseModel):
    input: PolicyInput


class OPAResult(BaseModel):
    allow: bool = False

    decision_id: str = Field(min_length=1)

    policy_version: str = Field(min_length=1)

    reason: str = Field(min_length=1)


class OPAResponse(BaseModel):
    result: OPAResult


def build_opa_request(
    tenant: Tenant,
    recommendation: SchedulingRecommendation,
    resource: OPAResourceInput,
) -> OPARequest:
    return OPARequest(
        input=PolicyInput(
            tenant=OPATenantInput(
                id=tenant.tenant_id,
                security_level=tenant.security_level,
                allowed_zones=tenant.allowed_zones,
                active=tenant.active,
                quota_remaining=tenant.quota_remaining,
                kv_isolation_required=tenant.kv_isolation_required,
            ),
            recommendation=OPARecommendationInput(
                backend_id=recommendation.backend_id,
                zone=recommendation.zone,
            ),
            resource=resource,
        )
    )

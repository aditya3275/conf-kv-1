package confidentialkv

import rego.v1


default allow := false


# ---------------------------------------------------------
# Main authorization decision
# ---------------------------------------------------------

allow if {
    input.tenant.active
    input.tenant.quota_remaining > 0

    input.recommendation.backend_id == input.resource.backend_id

    input.recommendation.zone in input.tenant.allowed_zones

    input.resource.configured_status == "available"
    input.resource.health_status == "healthy"
    input.resource.capacity_available

    high_security_requirement_satisfied
}


high_security_requirement_satisfied if {
    input.tenant.security_level == "standard"
}


high_security_requirement_satisfied if {
    input.tenant.security_level == "high"
    input.recommendation.zone == "secure"
}


# ---------------------------------------------------------
# Human-readable reason
# ---------------------------------------------------------

reason := "tenant_inactive" if {
    not input.tenant.active
}

reason := "quota_exhausted" if {
    input.tenant.active
    input.tenant.quota_remaining <= 0
}

reason := "backend_mismatch" if {
    input.tenant.active
    input.tenant.quota_remaining > 0
    input.recommendation.backend_id != input.resource.backend_id
}

reason := "zone_not_allowed" if {
    input.recommendation.backend_id == input.resource.backend_id
    input.recommendation.zone not in input.tenant.allowed_zones
}

reason := "backend_not_available" if {
    input.recommendation.backend_id == input.resource.backend_id
    input.recommendation.zone in input.tenant.allowed_zones
    input.resource.configured_status != "available"
}

reason := "backend_unhealthy" if {
    input.resource.configured_status == "available"
    input.resource.health_status != "healthy"
}

reason := "backend_capacity_unavailable" if {
    input.resource.configured_status == "available"
    input.resource.health_status == "healthy"
    not input.resource.capacity_available
}

reason := "high_security_requires_secure_zone" if {
    input.tenant.security_level == "high"
    input.recommendation.zone != "secure"
}

reason := "allowed" if {
    allow
}


# ---------------------------------------------------------
# Policy version
# ---------------------------------------------------------

policy_version := "v1"


# ---------------------------------------------------------
# Decision fingerprint
#
# This is deliberately NOT request_id based.
# It identifies the policy/input decision fingerprint.
# request_id remains correlation-only outside policy semantics.
# ---------------------------------------------------------

decision_id := crypto.sha256(
    sprintf(
        "%s|%s|%s|%s",
        [
            input.tenant.id,
            input.recommendation.backend_id,
            input.recommendation.zone,
            policy_version,
        ],
    ),
)


# ---------------------------------------------------------
# Public OPA result
# ---------------------------------------------------------

authz := {
    "allow": allow,
    "decision_id": decision_id,
    "policy_version": policy_version,
    "reason": reason,
}
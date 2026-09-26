package confidentialkv

import rego.v1


test_high_security_secure_backend_allowed if {
    result := authz with input as {
        "tenant": {
            "id": "tenant-a",
            "security_level": "high",
            "allowed_zones": ["secure"],
            "active": true,
            "quota_remaining": 100,
            "kv_isolation_required": true,
        },
        "recommendation": {
            "backend_id": "vllm-secure-01",
            "zone": "secure",
        },
        "resource": {
            "backend_id": "vllm-secure-01",
            "configured_status": "available",
            "health_status": "healthy",
            "capacity_available": true,
        },
    }

    result.allow == true
    result.policy_version == "v1"
}


test_high_security_general_backend_denied if {
    result := authz with input as {
        "tenant": {
            "id": "tenant-a",
            "security_level": "high",
            "allowed_zones": ["secure", "general"],
            "active": true,
            "quota_remaining": 100,
            "kv_isolation_required": true,
        },
        "recommendation": {
            "backend_id": "vllm-general-01",
            "zone": "general",
        },
        "resource": {
            "backend_id": "vllm-general-01",
            "configured_status": "available",
            "health_status": "healthy",
            "capacity_available": true,
        },
    }

    result.allow == false
    result.reason == "high_security_requires_secure_zone"
}


test_inactive_tenant_denied if {
    result := authz with input as {
        "tenant": {
            "id": "tenant-a",
            "security_level": "standard",
            "allowed_zones": ["general"],
            "active": false,
            "quota_remaining": 100,
            "kv_isolation_required": true,
        },
        "recommendation": {
            "backend_id": "vllm-general-01",
            "zone": "general",
        },
        "resource": {
            "backend_id": "vllm-general-01",
            "configured_status": "available",
            "health_status": "healthy",
            "capacity_available": true,
        },
    }

    result.allow == false
    result.reason == "tenant_inactive"
}


test_exhausted_quota_denied if {
    result := authz with input as {
        "tenant": {
            "id": "tenant-a",
            "security_level": "standard",
            "allowed_zones": ["general"],
            "active": true,
            "quota_remaining": 0,
            "kv_isolation_required": true,
        },
        "recommendation": {
            "backend_id": "vllm-general-01",
            "zone": "general",
        },
        "resource": {
            "backend_id": "vllm-general-01",
            "configured_status": "available",
            "health_status": "healthy",
            "capacity_available": true,
        },
    }

    result.allow == false
    result.reason == "quota_exhausted"
}


test_unhealthy_backend_denied if {
    result := authz with input as {
        "tenant": {
            "id": "tenant-a",
            "security_level": "standard",
            "allowed_zones": ["general"],
            "active": true,
            "quota_remaining": 100,
            "kv_isolation_required": false,
        },
        "recommendation": {
            "backend_id": "vllm-general-01",
            "zone": "general",
        },
        "resource": {
            "backend_id": "vllm-general-01",
            "configured_status": "available",
            "health_status": "unhealthy",
            "capacity_available": true,
        },
    }

    result.allow == false
    result.reason == "backend_unhealthy"
}


test_capacity_unavailable_denied if {
    result := authz with input as {
        "tenant": {
            "id": "tenant-a",
            "security_level": "standard",
            "allowed_zones": ["general"],
            "active": true,
            "quota_remaining": 100,
            "kv_isolation_required": false,
        },
        "recommendation": {
            "backend_id": "vllm-general-01",
            "zone": "general",
        },
        "resource": {
            "backend_id": "vllm-general-01",
            "configured_status": "available",
            "health_status": "healthy",
            "capacity_available": false,
        },
    }

    result.allow == false
    result.reason == "backend_capacity_unavailable"
}


test_backend_mismatch_denied if {
    result := authz with input as {
        "tenant": {
            "id": "tenant-a",
            "security_level": "standard",
            "allowed_zones": ["general"],
            "active": true,
            "quota_remaining": 100,
            "kv_isolation_required": false,
        },
        "recommendation": {
            "backend_id": "vllm-a",
            "zone": "general",
        },
        "resource": {
            "backend_id": "vllm-b",
            "configured_status": "available",
            "health_status": "healthy",
            "capacity_available": true,
        },
    }

    result.allow == false
    result.reason == "backend_mismatch"
}
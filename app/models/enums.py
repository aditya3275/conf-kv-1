from __future__ import annotations

from enum import Enum


class SecurityLevel(str, Enum):
    HIGH = "high"
    STANDARD = "standard"


class Zone(str, Enum):
    SECURE = "secure"
    GENERAL = "general"


class BackendStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class RequestLifecycleState(str, Enum):
    RECEIVED = "received"
    AUTHENTICATED = "authenticated"
    METADATA_ENRICHED = "metadata_enriched"
    SCHEDULED = "scheduled"
    POLICY_EVALUATED = "policy_evaluated"
    ADMITTED = "admitted"
    REJECTED = "rejected"
    ROUTED = "routed"
    COMPLETED = "completed"
    FAILED = "failed"


class VerifKVEventType(str, Enum):
    AUTHZ_DECISION = "authz_decision"
    ROUTE_ASSIGNED = "route_assigned"

    REQUEST_COMPLETED = "request_completed"
    REQUEST_FAILED = "request_failed"

    KV_LIFECYCLE = "kv_lifecycle"
    KV_MIGRATION = "kv_migration"

    BACKEND_OBSERVED = "backend_observed"
    BACKEND_FAILURE_DETECTED = "backend_failure_detected"
    BACKEND_RECOVERED = "backend_recovered"
    METRIC_SCRAPE_FAILURE = "metric_scrape_failure"

    UPSTREAM_ERROR = "upstream_error"

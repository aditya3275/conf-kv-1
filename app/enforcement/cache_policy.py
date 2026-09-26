from __future__ import annotations

from app.models.cache import CachePolicy
from app.models.tenant import Tenant


def build_cache_policy(
    tenant: Tenant,
) -> CachePolicy:
    """
    Converts the tenant's security configuration into the
    cache policy that the enforcement layer will apply.

    The namespace is our control-plane concept.

    The cache_salt is the value eventually injected into
    the vLLM request.

    The secret itself must never be logged.
    """

    return CachePolicy(
        isolation_required=tenant.kv_isolation_required,
        namespace=f"tenant:{tenant.tenant_id}",
        cache_salt=tenant.cache_salt,
    )

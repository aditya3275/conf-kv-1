from app.enforcement.cache_policy import (
    build_cache_policy,
)
from app.models.enums import SecurityLevel, Zone
from app.models.tenant import Tenant


def test_cache_policy_uses_tenant_salt():
    tenant = Tenant(
        tenant_id="tenant-a",
        security_level=SecurityLevel.HIGH,
        allowed_zones=[Zone.SECURE],
        quota_limit=100,
        quota_used=0,
        kv_isolation_required=True,
        cache_salt="tenant-a-secret",
        active=True,
    )

    policy = build_cache_policy(tenant)

    assert policy.isolation_required is True

    assert policy.namespace == "tenant:tenant-a"

    assert policy.cache_salt.get_secret_value() == "tenant-a-secret"

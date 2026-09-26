from __future__ import annotations

from typing import Any
from pydantic import SecretStr

from app.models.cache import CachePolicy


def _normalize_secret(
    value: SecretStr | str | None,
) -> SecretStr | None:
    if value is None:
        return None

    if isinstance(value, SecretStr):
        return value

    return SecretStr(value)


def build_cache_policy(
    tenant: Any | None = None,
    *,
    tenant_id: str | None = None,
    kv_isolation: bool | None = None,
    cache_salt: SecretStr | str | None = None,
) -> CachePolicy:
    """
    Build the authoritative tenant cache policy.

    Supports both:
        build_cache_policy(tenant)

    and:
        build_cache_policy(
            tenant_id="tenant-a",
            kv_isolation=True,
            cache_salt="..."
        )

    The CachePolicy model itself lives in app.models.cache.
    """

    if tenant is not None:
        if tenant_id is None:
            tenant_id = getattr(tenant, "tenant_id", None)

        if kv_isolation is None:
            if hasattr(tenant, "kv_isolation"):
                kv_isolation = bool(tenant.kv_isolation)
            elif hasattr(tenant, "kv_isolation_required"):
                kv_isolation = bool(tenant.kv_isolation_required)
            else:
                raise ValueError("Tenant has no KV isolation field")

        if cache_salt is None:
            cache_salt = getattr(tenant, "cache_salt", None)

    if not tenant_id:
        raise ValueError("tenant_id must not be empty")

    if kv_isolation is None:
        raise ValueError("kv_isolation must be specified")

    normalized_salt = _normalize_secret(cache_salt)

    if kv_isolation:
        namespace = f"tenant:{tenant_id}"

        if normalized_salt is None:
            raise ValueError("KV isolation requires a cache salt")

        return CachePolicy(
            enabled=True,
            isolation_enabled=True,
            namespace=namespace,
            cache_salt=normalized_salt,
        )

    return CachePolicy(
        enabled=True,
        isolation_enabled=False,
        namespace="shared",
        cache_salt=None,
    )


def build_vllm_cache_payload(
    policy: CachePolicy,
) -> dict[str, str]:
    """
    Convert the authoritative cache policy into the request fields
    understood by the serving layer.
    """

    if not policy.enabled:
        return {}

    if not policy.isolation_enabled:
        return {}

    if policy.cache_salt is None:
        raise ValueError("Isolated cache policy has no cache salt")

    return {"cache_salt": policy.cache_salt.get_secret_value()}

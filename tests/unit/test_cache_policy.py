from pydantic import SecretStr
import pytest

from app.enforcement.cache_policy import (
    build_cache_policy,
    build_vllm_cache_payload,
)


def test_isolated_tenant_gets_tenant_namespace() -> None:

    salt = SecretStr("test-salt-tenant-a")

    policy = build_cache_policy(
        tenant_id="tenant-a",
        kv_isolation=True,
        cache_salt=salt,
    )

    assert policy.enabled is True

    assert policy.isolation_enabled is True

    assert policy.namespace == "tenant:tenant-a"

    assert policy.cache_salt is not None

    assert policy.cache_salt.get_secret_value() == "test-salt-tenant-a"


def test_isolated_tenant_generates_vllm_payload() -> None:

    salt = SecretStr("test-salt-tenant-a")

    policy = build_cache_policy(
        tenant_id="tenant-a",
        kv_isolation=True,
        cache_salt=salt,
    )

    payload = build_vllm_cache_payload(policy)

    assert payload == {"cache_salt": "test-salt-tenant-a"}


def test_non_isolated_tenant_has_no_cache_salt() -> None:

    policy = build_cache_policy(
        tenant_id="tenant-a",
        kv_isolation=False,
        cache_salt=None,
    )

    assert policy.enabled is True

    assert policy.isolation_enabled is False

    assert policy.namespace == "shared"

    assert policy.cache_salt is None

    assert build_vllm_cache_payload(policy) == {}


def test_isolation_requires_cache_salt() -> None:

    with pytest.raises(
        ValueError,
        match="requires a cache salt",
    ):

        build_cache_policy(
            tenant_id="tenant-a",
            kv_isolation=True,
            cache_salt=None,
        )


def test_empty_tenant_id_is_rejected() -> None:

    with pytest.raises(
        ValueError,
        match="tenant_id must not be empty",
    ):

        build_cache_policy(
            tenant_id="",
            kv_isolation=True,
            cache_salt=SecretStr("test-salt"),
        )


def test_cache_payload_does_not_contain_namespace() -> None:

    policy = build_cache_policy(
        tenant_id="tenant-a",
        kv_isolation=True,
        cache_salt=SecretStr("test-salt"),
    )

    payload = build_vllm_cache_payload(policy)

    assert "namespace" not in payload

    assert "tenant_id" not in payload

    assert "request_id" not in payload

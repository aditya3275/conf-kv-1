from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from app.enforcement.proxy import EnforcementProxy


class FakeVerifKV:
    def __init__(self) -> None:
        self.events = []

    def emit_nowait(self, event) -> bool:
        self.events.append(event)
        return True


def extract_json_payload(
    request: httpx.Request,
) -> dict:
    """
    Extract the JSON body from an httpx.Request.

    httpx.Request does not provide request.json(), so we
    decode the raw request content explicitly.
    """

    return json.loads(request.content.decode("utf-8"))


@pytest.mark.asyncio
async def test_client_cache_salt_is_overridden() -> None:

    captured_payload: dict = {}

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        nonlocal captured_payload

        captured_payload = extract_json_payload(request)

        return httpx.Response(
            status_code=200,
            json={"id": "test-response"},
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:

        sink = FakeVerifKV()

        proxy = EnforcementProxy(
            http_client=client,
            verifkv_sink=sink,
        )

        response = await proxy.forward(
            backend_id="backend-a",
            backend_endpoint="http://backend-a",
            tenant_id="tenant-a",
            tenant_kv_isolation=True,
            tenant_cache_salt=SecretStr("CONTROL-PLANE-SALT"),
            request_id="request-001",
            request_payload={
                "model": "test-model",
                "messages": [
                    {
                        "role": "user",
                        "content": "hello",
                    }
                ],
                # Attacker-controlled value.
                "cache_salt": ("ATTACKER-CONTROLLED-SALT"),
                # These must also be stripped.
                "tenant_id": "attacker-tenant",
                "request_id": "attacker-request",
            },
            decision_id="decision-001",
            policy_version="v1",
        )

    assert response.status_code == 200

    # Control-plane salt must override
    # the attacker-controlled value.
    assert captured_payload["cache_salt"] == "CONTROL-PLANE-SALT"

    assert captured_payload["cache_salt"] != "ATTACKER-CONTROLLED-SALT"

    # Internal control-plane fields must
    # never reach the backend.
    assert "tenant_id" not in captured_payload

    assert "request_id" not in captured_payload


@pytest.mark.asyncio
async def test_isolated_request_contains_control_plane_salt() -> None:

    captured_payload: dict = {}

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        nonlocal captured_payload

        captured_payload = extract_json_payload(request)

        return httpx.Response(
            status_code=200,
            json={"id": "test-response"},
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:

        sink = FakeVerifKV()

        proxy = EnforcementProxy(
            http_client=client,
            verifkv_sink=sink,
        )

        await proxy.forward(
            backend_id="backend-a",
            backend_endpoint="http://backend-a",
            tenant_id="tenant-a",
            tenant_kv_isolation=True,
            tenant_cache_salt=SecretStr("TENANT-A-SALT"),
            request_id="request-001",
            request_payload={
                "model": "test-model",
                "messages": [
                    {
                        "role": "user",
                        "content": "hello",
                    }
                ],
            },
            decision_id="decision-001",
            policy_version="v1",
        )

    assert captured_payload["cache_salt"] == "TENANT-A-SALT"


@pytest.mark.asyncio
async def test_non_isolated_request_has_no_cache_salt() -> None:

    captured_payload: dict = {}

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:

        nonlocal captured_payload

        captured_payload = extract_json_payload(request)

        return httpx.Response(
            status_code=200,
            json={"id": "test-response"},
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:

        sink = FakeVerifKV()

        proxy = EnforcementProxy(
            http_client=client,
            verifkv_sink=sink,
        )

        await proxy.forward(
            backend_id="backend-a",
            backend_endpoint="http://backend-a",
            tenant_id="tenant-a",
            tenant_kv_isolation=False,
            tenant_cache_salt=None,
            request_id="request-001",
            request_payload={
                "model": "test-model",
                "messages": [
                    {
                        "role": "user",
                        "content": "hello",
                    }
                ],
            },
            decision_id="decision-001",
            policy_version="v1",
        )

    assert "cache_salt" not in captured_payload

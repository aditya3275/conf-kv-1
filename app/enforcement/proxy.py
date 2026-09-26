from __future__ import annotations

import logging
from typing import Any

import httpx

from app.enforcement.authorization import VerifKVEventSink
from app.models.verifkv import (
    VerifKVEvent,
    VerifKVEventType,
)

logger = logging.getLogger(__name__)


class EnforcementProxy:
    """
    Enforcement bridge between the control plane and
    pre-pinned inference backends.

    Responsibilities:
        1. Receive an approved routing decision.
        2. Build the final backend request.
        3. Inject control-plane cache policy.
        4. Forward to the selected backend.
        5. Emit provenance asynchronously.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        verifkv_sink: VerifKVEventSink,
    ) -> None:

        self.http_client = http_client
        self.verifkv_sink = verifkv_sink

    async def forward(
        self,
        *,
        backend_id: str,
        backend_endpoint: str,
        tenant_id: str,
        request_id: str,
        request_payload: dict[str, Any],
        decision_id: str,
        policy_version: str,
        cache_payload: dict[str, Any],
    ) -> httpx.Response:

        self.verifkv_sink.emit_nowait(
            VerifKVEvent(
                event_type=(VerifKVEventType.AUTHZ_DECISION),
                source="control-plane",
                tenant_id=tenant_id,
                request_id=request_id,
                payload={
                    "allow": True,
                    "decision_id": decision_id,
                    "policy_version": policy_version,
                    "backend_id": backend_id,
                },
            )
        )

        self.verifkv_sink.emit_nowait(
            VerifKVEvent(
                event_type=(VerifKVEventType.ROUTE_ASSIGNED),
                source="control-plane",
                tenant_id=tenant_id,
                request_id=request_id,
                payload={
                    "backend_id": backend_id,
                    "backend_endpoint": backend_endpoint,
                },
            )
        )

        payload = dict(request_payload)

        # Client-controlled cache_salt must never override
        # the control-plane policy.
        payload.pop("cache_salt", None)

        # The control plane injects the approved cache policy.
        payload.update(cache_payload)

        # Internal control-plane correlation fields must not
        # be forwarded to the model server as user fields.
        payload.pop("tenant_id", None)
        payload.pop("request_id", None)

        try:

            response = await self.http_client.post(
                f"{backend_endpoint.rstrip('/')}/v1/chat/completions",
                json=payload,
            )

            if response.is_error:

                self.verifkv_sink.emit_nowait(
                    VerifKVEvent(
                        event_type=(VerifKVEventType.UPSTREAM_ERROR),
                        source="control-plane",
                        tenant_id=tenant_id,
                        request_id=request_id,
                        payload={
                            "backend_id": backend_id,
                            "status_code": response.status_code,
                        },
                    )
                )

            return response

        except Exception as exc:

            self.verifkv_sink.emit_nowait(
                VerifKVEvent(
                    event_type=(VerifKVEventType.REQUEST_FAILED),
                    source="control-plane",
                    tenant_id=tenant_id,
                    request_id=request_id,
                    payload={
                        "backend_id": backend_id,
                        "error": str(exc),
                    },
                )
            )

            raise

from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import SecretStr

from app.enforcement.authorization import (
    VerifKVEventSink,
)
from app.enforcement.cache_policy import (
    build_cache_policy,
    build_vllm_cache_payload,
)
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

        1. Receive an already-authorized route.
        2. Build the authoritative KV-cache policy.
        3. Remove client-controlled cache policy fields.
        4. Inject the control-plane cache_salt.
        5. Forward the request to the selected backend.
        6. Emit asynchronous provenance events.

    GPU placement is NOT performed here.
    The backend endpoint is already associated with a
    pre-pinned serving instance.
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
        tenant_kv_isolation: bool,
        tenant_cache_salt: SecretStr | None,
        request_id: str,
        request_payload: dict[str, Any],
        decision_id: str,
        policy_version: str,
    ) -> httpx.Response:
        """
        Forward an authorized request to the selected backend.

        tenant_kv_isolation and tenant_cache_salt must come from
        the authoritative tenant registry, never from the client.
        """

        # -----------------------------------------------------
        # 1. Record successful authorization asynchronously
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # 2. Record route assignment asynchronously
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # 3. Build authoritative cache policy
        # -----------------------------------------------------

        cache_policy = build_cache_policy(
            tenant_id=tenant_id,
            kv_isolation=tenant_kv_isolation,
            cache_salt=tenant_cache_salt,
        )

        cache_payload = build_vllm_cache_payload(cache_policy)

        # -----------------------------------------------------
        # 4. Copy client payload
        # -----------------------------------------------------

        payload = dict(request_payload)

        # -----------------------------------------------------
        # 5. Remove client-controlled security fields
        # -----------------------------------------------------

        payload.pop(
            "cache_salt",
            None,
        )

        payload.pop(
            "tenant_id",
            None,
        )

        payload.pop(
            "request_id",
            None,
        )

        # -----------------------------------------------------
        # 6. Inject authoritative cache policy
        # -----------------------------------------------------

        payload.update(cache_payload)

        logger.debug(
            "Prepared backend request " "tenant=%s backend=%s " "cache_isolation=%s",
            tenant_id,
            backend_id,
            cache_policy.isolation_enabled,
        )

        # -----------------------------------------------------
        # 7. Forward to the pre-pinned backend
        # -----------------------------------------------------

        try:

            response = await self.http_client.post(
                (f"{backend_endpoint.rstrip('/')}" "/v1/chat/completions"),
                json=payload,
            )

            # -------------------------------------------------
            # 8. Record upstream failures asynchronously
            # -------------------------------------------------

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

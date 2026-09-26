from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from app.common.logging import configure_logging
from app.common.request_context import (
    get_request_id,
    new_request_id,
    reset_request_id,
    set_request_id,
)
from app.config.settings import settings
from app.enforcement.cache_policy import build_cache_policy
from app.enforcement.proxy import EnforcementProxy
from app.enforcement.router import EnforcementRouter, RoutingError
from app.gateway.auth import AuthenticationError, make_authenticator
from app.models.inference import ClientInferenceRequest
from app.models.opa import OPARequest
from app.opa.client import (
    OPAClient,
    OPADecisionError,
    OPAUnavailableError,
)
from app.registry.backend_registry import BackendRegistry
from app.registry.health_monitor import BackendHealthMonitor
from app.registry.tenant_registry import TenantRegistry
from app.scheduler.scheduler import NoBackendAvailableError, SecurityAwareScheduler
from app.verifkv.client import VerifKVEventClient

logger = logging.getLogger(__name__)


class Metrics:
    """
    Minimal in-process control-plane metrics.

    This is intentionally lightweight for Phase 8.
    A Prometheus exporter can be added after the request path is stable.
    """

    def __init__(self) -> None:
        self.request_count = 0
        self.policy_allow_count = 0
        self.policy_deny_count = 0
        self.request_error_count = 0
        self.backend_error_count = 0

        self.total_scheduler_latency_ms = 0.0
        self.total_opa_latency_ms = 0.0
        self.total_routing_latency_ms = 0.0

    def observe_scheduler(self, milliseconds: float) -> None:
        self.total_scheduler_latency_ms += milliseconds

    def observe_opa(self, milliseconds: float) -> None:
        self.total_opa_latency_ms += milliseconds

    def observe_routing(self, milliseconds: float) -> None:
        self.total_routing_latency_ms += milliseconds

    def render(self) -> str:
        return "\n".join(
            [
                "# TYPE confidentialkv_requests_total counter",
                f"confidentialkv_requests_total {self.request_count}",
                "",
                "# TYPE confidentialkv_policy_allow_total counter",
                f"confidentialkv_policy_allow_total {self.policy_allow_count}",
                "",
                "# TYPE confidentialkv_policy_deny_total counter",
                f"confidentialkv_policy_deny_total {self.policy_deny_count}",
                "",
                "# TYPE confidentialkv_request_errors_total counter",
                f"confidentialkv_request_errors_total {self.request_error_count}",
                "",
                "# TYPE confidentialkv_backend_errors_total counter",
                f"confidentialkv_backend_errors_total {self.backend_error_count}",
                "",
                "# TYPE confidentialkv_scheduler_latency_ms_total counter",
                (
                    "confidentialkv_scheduler_latency_ms_total "
                    f"{self.total_scheduler_latency_ms:.3f}"
                ),
                "",
                "# TYPE confidentialkv_opa_latency_ms_total counter",
                f"confidentialkv_opa_latency_ms_total {self.total_opa_latency_ms:.3f}",
                "",
                "# TYPE confidentialkv_routing_latency_ms_total counter",
                (
                    "confidentialkv_routing_latency_ms_total "
                    f"{self.total_routing_latency_ms:.3f}"
                ),
                "",
            ]
        )


configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initialize all control-plane dependencies before accepting traffic.
    """

    tenant_registry = TenantRegistry(settings.tenant_db_path)
    backend_registry = BackendRegistry(settings.control_plane_db_path)

    opa_client = OPAClient(
        base_url=settings.opa_url,
        timeout_seconds=settings.opa_timeout_seconds,
    )

    verifkv_client = VerifKVEventClient(
        base_url=settings.verifkv_url,
    )

    health_monitor = BackendHealthMonitor(
        registry=backend_registry,
        interval_seconds=settings.health_cache_ttl_seconds,
        timeout_seconds=settings.health_check_timeout_seconds,
    )

    upstream_client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.upstream_timeout_seconds),
        limits=httpx.Limits(
            max_connections=100,
            max_keepalive_connections=20,
        ),
    )

    metrics = Metrics()

    try:
        logger.info("Initializing ConfidentialKV-Scheduler control plane")

        # --------------------------------------------------------------
        # Durable registries -> in-memory caches
        # --------------------------------------------------------------

        await tenant_registry.initialize()
        await backend_registry.initialize()

        # --------------------------------------------------------------
        # External clients / workers
        # --------------------------------------------------------------

        await opa_client.start()
        await verifkv_client.start()

        # --------------------------------------------------------------
        # Backend health monitoring
        # --------------------------------------------------------------

        await health_monitor.start()

        # Perform an initial health pass before requests are accepted.
        await health_monitor.check_all()

        # --------------------------------------------------------------
        # Enforcement proxy
        # --------------------------------------------------------------

        enforcement_proxy = EnforcementProxy(
            http_client=upstream_client,
            verifkv_sink=verifkv_client,
        )

        # --------------------------------------------------------------
        # Scheduler
        # --------------------------------------------------------------

        scheduler = SecurityAwareScheduler(
            backend_registry=backend_registry,
        )

        # --------------------------------------------------------------
        # Authentication dependency
        # --------------------------------------------------------------

        authenticate = make_authenticator(
            tenant_registry,
        )

        # --------------------------------------------------------------
        # Expose runtime state to request handlers
        # --------------------------------------------------------------

        app.state.tenant_registry = tenant_registry
        app.state.backend_registry = backend_registry
        app.state.opa_client = opa_client
        app.state.verifkv_client = verifkv_client
        app.state.health_monitor = health_monitor
        app.state.upstream_client = upstream_client
        app.state.scheduler = scheduler
        app.state.enforcement_proxy = enforcement_proxy
        app.state.authenticate = authenticate
        app.state.metrics = metrics

        logger.info("ConfidentialKV-Scheduler control plane initialized")

        yield

    finally:
        logger.info("Shutting down ConfidentialKV-Scheduler control plane")

        await health_monitor.stop()
        await verifkv_client.stop()
        await opa_client.close()
        await upstream_client.aclose()

        await tenant_registry.close()
        await backend_registry.close()

        logger.info("Control plane shutdown complete")


app = FastAPI(
    title=settings.app_name,
    lifespan=lifespan,
)


@app.middleware("http")
async def request_id_middleware(
    request: Request,
    call_next,
):
    """
    Generate a gateway request ID and propagate it through the
    ContextVar-backed request context.
    """

    request_id = new_request_id()
    token = set_request_id(request_id)

    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    finally:
        reset_request_id(token)


async def authenticated_tenant(
    request: Request,
    authorization: str = Header(default=""),
):
    """
    Resolve the authenticated tenant through the initialized
    registry-bound authenticator.
    """

    authenticator = request.app.state.authenticate

    return await authenticator(
        authorization=authorization,
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": settings.app_name,
    }


@app.get("/ready")
async def readiness(request: Request):
    backend_registry = request.app.state.backend_registry

    backends = backend_registry.list_backends()

    return {
        "status": "ready",
        "backends_registered": len(backends),
    }


@app.get("/metrics")
async def metrics(request: Request):
    metrics_registry: Metrics = request.app.state.metrics

    return Response(
        content=metrics_registry.render(),
        media_type="text/plain; version=0.0.4",
    )


@app.post("/v1/chat/completions")
async def chat_completions(
    payload: ClientInferenceRequest,
    request: Request,
    tenant=Depends(authenticated_tenant),
):
    """
    Main inference entry point.

    Request lifecycle:

        client
          -> authentication
          -> trusted tenant metadata
          -> scheduler recommendation
          -> OPA authorization
          -> enforcement route
          -> enforcement proxy
          -> serving backend
    """

    metrics_registry: Metrics = request.app.state.metrics
    scheduler: SecurityAwareScheduler = request.app.state.scheduler
    backend_registry: BackendRegistry = request.app.state.backend_registry
    opa_client: OPAClient = request.app.state.opa_client
    enforcement_proxy: EnforcementProxy = request.app.state.enforcement_proxy

    metrics_registry.request_count += 1

    request_id = get_request_id()

    if request_id == "-":
        request_id = str(uuid4())

    logger.info(
        "Inference request received tenant=%s request_id=%s",
        tenant.tenant_id,
        request_id,
    )

    # ==============================================================
    # 1. Scheduler recommendation
    # ==============================================================

    scheduler_start = time.perf_counter()

    try:
        recommendation = scheduler.recommend(tenant)

    except NoBackendAvailableError as exc:
        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    finally:
        scheduler_elapsed = (time.perf_counter() - scheduler_start) * 1000.0

        metrics_registry.observe_scheduler(
            scheduler_elapsed,
        )

    logger.info(
        "Scheduler recommendation tenant=%s backend=%s zone=%s",
        tenant.tenant_id,
        recommendation.backend_id,
        recommendation.zone,
    )

    # ==============================================================
    # 2. Resolve backend from in-memory registry
    # ==============================================================

    backend = backend_registry.get_backend(
        recommendation.backend_id,
    )

    if backend is None:
        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=503,
            detail="Recommended backend is no longer registered",
        )

    if backend.endpoint is None:
        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=503,
            detail="Recommended backend has no endpoint",
        )

    # ==============================================================
    # 3. Construct OPA request
    #
    # request_id is deliberately not included in the OPA contract.
    # ==============================================================

    tenant_data = {
        "id": tenant.tenant_id,
        "active": tenant.active,
        "quota_remaining": tenant.quota_remaining,
    }

    # Current project code historically used `tier`, while the
    # scheduling layer now exposes security-level semantics.
    # Prefer the field expected by the actual OPA contract.
    opa_tenant_fields = getattr(
        OPARequest.model_fields["input"].annotation,
        "model_fields",
        None,
    )

    # The robust path is model validation below; the tenant object
    # itself remains authoritative.
    if hasattr(tenant, "tier"):
        tenant_data["tier"] = tenant.tier

    if hasattr(tenant, "security_level"):
        tenant_data["security_level"] = tenant.security_level

    opa_payload = {
        "input": {
            "tenant": tenant_data,
            "recommendation": {
                "backend_id": recommendation.backend_id,
                "zone": recommendation.zone,
            },
        }
    }

    try:
        opa_request = OPARequest.model_validate(
            opa_payload,
        )

    except Exception as exc:
        logger.exception(
            "Failed to build OPA request tenant=%s request_id=%s",
            tenant.tenant_id,
            request_id,
        )

        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=500,
            detail="Invalid internal OPA request contract",
        ) from exc

    # ==============================================================
    # 4. OPA authorization
    # ==============================================================

    opa_start = time.perf_counter()

    try:
        opa_response = await opa_client.evaluate(
            opa_request,
        )

    except OPAUnavailableError as exc:
        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=503,
            detail="Policy authorization service unavailable",
        ) from exc

    except OPADecisionError as exc:
        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=502,
            detail="Policy authorization returned an invalid decision",
        ) from exc

    finally:
        opa_elapsed = (time.perf_counter() - opa_start) * 1000.0

        metrics_registry.observe_opa(
            opa_elapsed,
        )

    # ==============================================================
    # 5. OPA DENY = request stops here
    # ==============================================================

    if not opa_response.result.allow:
        metrics_registry.policy_deny_count += 1

        logger.warning(
            "OPA denied request tenant=%s backend=%s reason=%s",
            tenant.tenant_id,
            recommendation.backend_id,
            opa_response.result.reason,
        )

        raise HTTPException(
            status_code=403,
            detail=opa_response.result.reason,
        )

    metrics_registry.policy_allow_count += 1

    # ==============================================================
    # 6. Build authoritative cache policy
    # ==============================================================

    try:
        cache_policy = build_cache_policy(
            tenant,
        )

    except ValueError as exc:
        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=500,
            detail="Unable to construct authoritative cache policy",
        ) from exc

    # ==============================================================
    # 7. Build approved route
    # ==============================================================

    routing_start = time.perf_counter()

    try:
        approved_route = EnforcementRouter.build_route(
            request_id=request_id,
            backend=backend,
            opa_response=opa_response,
            cache_policy=cache_policy,
        )

    except RoutingError as exc:
        metrics_registry.request_error_count += 1

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    finally:
        routing_elapsed = (time.perf_counter() - routing_start) * 1000.0

        metrics_registry.observe_routing(
            routing_elapsed,
        )

    # ==============================================================
    # 8. Enforcement proxy
    #
    # Client payload -> proxy strips client-controlled security fields
    # -> proxy injects authoritative cache policy
    # -> backend request
    # ==============================================================

    backend_payload = payload.model_dump(
        mode="json",
    )

    try:
        upstream_response = await enforcement_proxy.forward(
            backend_id=approved_route.backend_id,
            backend_endpoint=str(approved_route.endpoint),
            tenant_id=tenant.tenant_id,
            tenant_kv_isolation=approved_route.cache_policy.isolation_enabled,
            tenant_cache_salt=approved_route.cache_policy.cache_salt,
            request_id=request_id,
            request_payload=backend_payload,
            decision_id=approved_route.decision_id,
            policy_version=approved_route.policy_version,
        )

    except httpx.HTTPError as exc:
        metrics_registry.backend_error_count += 1
        metrics_registry.request_error_count += 1

        logger.exception(
            "Backend forwarding failed tenant=%s backend=%s",
            tenant.tenant_id,
            approved_route.backend_id,
        )

        raise HTTPException(
            status_code=502,
            detail="Inference backend unavailable",
        ) from exc

    except Exception as exc:
        metrics_registry.backend_error_count += 1
        metrics_registry.request_error_count += 1

        logger.exception(
            "Unexpected enforcement failure tenant=%s backend=%s",
            tenant.tenant_id,
            approved_route.backend_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Inference request failed",
        ) from exc

    # ==============================================================
    # 9. Return backend response
    # ==============================================================

    content_type = upstream_response.headers.get(
        "content-type",
        "application/json",
    )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        media_type=content_type,
        headers={
            "X-Backend-ID": approved_route.backend_id,
            "X-Request-ID": request_id,
        },
    )

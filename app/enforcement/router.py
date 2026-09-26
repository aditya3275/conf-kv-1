from __future__ import annotations

from uuid import UUID

from app.models.backend import Backend
from app.models.cache import CachePolicy
from app.models.opa import OPAResponse
from app.models.routing import ApprovedRoute


class RoutingError(RuntimeError):
    pass


class EnforcementRouter:
    """
    Converts an authorized policy decision into a concrete
    serving-backend route.

    The router does not:
        - allocate GPUs
        - start vLLM
        - move vLLM
        - make policy decisions

    It only translates an already-authorized decision into
    the endpoint that should receive the request.
    """

    @staticmethod
    def build_route(
        *,
        request_id: UUID,
        backend: Backend,
        opa_response: OPAResponse,
        cache_policy: CachePolicy,
    ) -> ApprovedRoute:
        result = opa_response.result

        if not result.allow:
            raise RoutingError("Cannot build route from a denied OPA decision")

        if backend.endpoint is None:
            raise RoutingError(f"Backend '{backend.backend_id}' has no endpoint")

        return ApprovedRoute(
            request_id=request_id,
            backend_id=backend.backend_id,
            endpoint=backend.endpoint,
            zone=backend.zone,
            decision_id=result.decision_id,
            policy_version=result.policy_version,
            cache_policy=cache_policy,
        )

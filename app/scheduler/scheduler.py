from __future__ import annotations

from app.models.enums import (
    BackendStatus,
    HealthStatus,
    SecurityLevel,
    Zone,
)
from app.models.scheduling import SchedulingRecommendation
from app.models.tenant import Tenant
from app.registry.backend_registry import BackendRegistry


class NoBackendAvailableError(RuntimeError):
    pass


class SecurityAwareScheduler:
    """
    Security-aware placement recommender.

    Responsibilities:
        - inspect tenant requirements
        - inspect currently available backends
        - recommend a logical serving backend

    NOT responsible for:
        - OPA authorization
        - GPU allocation
        - starting vLLM
        - moving live requests
    """

    def __init__(
        self,
        backend_registry: BackendRegistry,
    ):
        self.backend_registry = backend_registry

    def recommend(
        self,
        tenant: Tenant,
    ) -> SchedulingRecommendation:
        backends = self.backend_registry.list_available_backends()

        candidates = [
            backend
            for backend in backends
            if self._eligible(
                backend,
                tenant,
            )
        ]

        if not candidates:
            raise NoBackendAvailableError("No eligible backend is currently available")

        ranked = sorted(
            candidates,
            key=lambda backend: self._score(
                backend,
                tenant,
            ),
        )

        selected = ranked[0]

        return SchedulingRecommendation(
            backend_id=selected.backend_id,
            zone=selected.zone,
            reason=self._reason(
                selected,
                tenant,
            ),
        )

    @staticmethod
    def _eligible(
        backend,
        tenant: Tenant,
    ) -> bool:
        if backend.configured_status != BackendStatus.AVAILABLE:
            return False

        if backend.health_status != HealthStatus.HEALTHY:
            return False

        if not backend.capacity_available:
            return False

        if backend.zone not in tenant.allowed_zones:
            return False

        return True

    @staticmethod
    def _score(
        backend,
        tenant: Tenant,
    ) -> tuple:
        """
        Lower score = preferred.

        High-security tenants prefer secure zones.
        Among equally suitable zones, lower load wins.

        This is a recommendation heuristic, NOT the policy decision.
        """

        if tenant.security_level == SecurityLevel.HIGH:
            zone_penalty = 0 if backend.zone == Zone.SECURE else 100
        else:
            zone_penalty = 0

        load = backend.load_percent if backend.load_percent is not None else 100.0

        return (
            zone_penalty,
            load,
            backend.backend_id,
        )

    @staticmethod
    def _reason(
        backend,
        tenant: Tenant,
    ) -> str:
        if tenant.security_level == SecurityLevel.HIGH and backend.zone == Zone.SECURE:
            return "secure-zone backend preferred for " "high-security tenant"

        return "eligible backend selected using " "zone compatibility and load"

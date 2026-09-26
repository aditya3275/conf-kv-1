from __future__ import annotations

from pydantic import AnyHttpUrl, BaseModel, Field

from app.models.enums import BackendStatus, HealthStatus, Zone


class Backend(BaseModel):
    """
    Logical identity of an already-running LLM serving instance.

    This model does NOT allocate GPUs.
    GPU IDs are infrastructure metadata only.
    """

    backend_id: str = Field(min_length=1)

    # None before real GPU/vLLM deployment is configured.
    endpoint: AnyHttpUrl | None = None

    zone: Zone

    gpu_ids: list[int] = Field(default_factory=list)

    configured_status: BackendStatus = BackendStatus.UNAVAILABLE
    health_status: HealthStatus = HealthStatus.UNKNOWN

    capacity_available: bool = False

    # Optional normalized load information for future scheduling.
    load_percent: float | None = Field(
        default=None,
        ge=0,
        le=100,
    )

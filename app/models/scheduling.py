from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.enums import Zone


class SchedulingRecommendation(BaseModel):
    """
    Scheduler output.

    The scheduler recommends a backend.
    It never allocates or moves a GPU.
    """

    backend_id: str = Field(min_length=1)

    zone: Zone

    reason: str = Field(min_length=1)

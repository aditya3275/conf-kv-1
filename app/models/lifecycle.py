from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.enums import RequestLifecycleState


class LifecycleEvent(BaseModel):
    request_id: str

    tenant_id: str

    state: RequestLifecycleState

    details: dict[str, str] = Field(default_factory=dict)

from __future__ import annotations

from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, UUID4

from app.models.cache import CachePolicy
from app.models.enums import Zone


class ApprovedRoute(BaseModel):
    """
    Result of the authorized routing decision.

    The enforcement proxy converts this into an actual upstream request.
    """

    request_id: UUID4

    backend_id: str = Field(min_length=1)

    endpoint: AnyHttpUrl

    zone: Zone

    decision_id: str = Field(min_length=1)

    policy_version: str = Field(min_length=1)

    cache_policy: CachePolicy

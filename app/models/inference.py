from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, UUID4


class ClientInferenceRequest(BaseModel):
    """
    Trusted boundary model for the client payload.

    tenant_id is intentionally absent.
    Tenant identity comes from authentication, not the request body.
    """

    model: str = Field(min_length=1)

    messages: list[dict[str, Any]] = Field(min_length=1)

    stream: bool = True

    parameters: dict[str, Any] = Field(default_factory=dict)


class InferenceRequest(BaseModel):
    """
    Internal request representation after authentication.
    """

    request_id: UUID4 = Field(default_factory=uuid4)

    tenant_id: str = Field(min_length=1)

    model: str = Field(min_length=1)

    messages: list[dict[str, Any]] = Field(min_length=1)

    stream: bool = True

    parameters: dict[str, Any] = Field(default_factory=dict)


class RequestMetadata(BaseModel):
    request_id: UUID4

    tenant_id: str

    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

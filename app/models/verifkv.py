from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class VerifKVEventType(str, Enum):
    AUTHZ_DECISION = "AUTHZ_DECISION"
    ROUTE_ASSIGNED = "ROUTE_ASSIGNED"

    REQUEST_COMPLETED = "REQUEST_COMPLETED"
    REQUEST_FAILED = "REQUEST_FAILED"

    KV_LIFECYCLE = "KV_LIFECYCLE"
    KV_MIGRATION = "KV_MIGRATION"

    BACKEND_OBSERVED = "BACKEND_OBSERVED"
    BACKEND_FAILURE_DETECTED = "BACKEND_FAILURE_DETECTED"
    BACKEND_RECOVERED = "BACKEND_RECOVERED"

    METRIC_SCRAPE_FAILURE = "METRIC_SCRAPE_FAILURE"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"


class VerifKVEvent(BaseModel):
    """
    Event emitted by the control plane or serving infrastructure.

    These events are asynchronous provenance records.
    """

    event_id: UUID = Field(default_factory=uuid4)

    event_type: VerifKVEventType

    source: str

    tenant_id: str | None = None

    request_id: str | None = None

    payload: dict[str, Any] = Field(default_factory=dict)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

from __future__ import annotations

from pydantic import BaseModel, Field, SecretStr

from app.models.enums import SecurityLevel, Zone


class Tenant(BaseModel):
    tenant_id: str = Field(min_length=1)
    security_level: SecurityLevel
    allowed_zones: list[Zone] = Field(min_length=1)

    quota_limit: int = Field(gt=0)
    quota_used: int = Field(ge=0)

    kv_isolation_required: bool = True

    # Secret material must not be accidentally exposed in logs/serialization.
    cache_salt: SecretStr

    active: bool = True

    @property
    def quota_remaining(self) -> int:
        return max(0, self.quota_limit - self.quota_used)

from __future__ import annotations

from pydantic import BaseModel, Field, SecretStr


class CachePolicy(BaseModel):
    """
    Cache policy passed from the control plane toward the serving layer.

    cache_salt is secret material and should never be logged or exposed
    through normal model serialization.
    """

    isolation_required: bool = True

    namespace: str = Field(min_length=1)

    cache_salt: SecretStr

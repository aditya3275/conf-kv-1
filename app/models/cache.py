"""
Canonical cache-policy contract for ConfidentialKV-Scheduler.

The cache policy is produced after authorization and carried to the
enforcement layer. The cache salt is treated as secret material and
must not be exposed as a normal plaintext field.
"""

from __future__ import annotations

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, SecretStr


class CachePolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    enabled: bool = True

    # Canonical name used by the model contract/tests.
    #
    # `isolation_enabled` is accepted as a compatibility alias because
    # earlier enforcement code used that name.
    isolation_required: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "isolation_required",
            "isolation_enabled",
        ),
    )

    namespace: str

    cache_salt: SecretStr | None = None

    @property
    def isolation_enabled(self) -> bool:
        """
        Backward-compatible attribute for code that previously used
        `isolation_enabled`.
        """
        return self.isolation_required

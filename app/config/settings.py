from __future__ import annotations

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized ConfidentialKV-Scheduler configuration.

    Configuration can come from environment variables or a local
    .env file.

    The control plane uses centralized configuration so that:
        - OPA endpoint
        - VerifKV endpoint
        - serving backend timeout
        - database paths
        - backend configuration
        - health monitoring
        - VerifKV reconciliation

    are all controlled from one place.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    app_name: str = "ConfidentialKV-Scheduler Control Plane"

    # ------------------------------------------------------------------
    # OPA
    # ------------------------------------------------------------------

    opa_url: str = "http://127.0.0.1:8181"
    opa_timeout_seconds: float = 2.0

    # ------------------------------------------------------------------
    # VerifKV external provenance service
    # ------------------------------------------------------------------

    verifkv_url: str = "http://127.0.0.1:9000"

    # ------------------------------------------------------------------
    # Upstream serving backend
    # ------------------------------------------------------------------

    upstream_timeout_seconds: float = 60.0

    # ------------------------------------------------------------------
    # Unified control-plane storage
    # ------------------------------------------------------------------

    control_plane_db_path: str = "data/control_plane.db"

    # Compatibility alias used by existing tenant-registry code.
    @property
    def tenant_db_path(self) -> str:
        return self.control_plane_db_path

    # ------------------------------------------------------------------
    # Existing compatibility paths
    # ------------------------------------------------------------------

    outbox_db_path: str = "data/outbox.db"

    verifkv_db_path: str = "data/verifkv.db"

    backends_config_path: str = "configs/backends.yaml"

    # ------------------------------------------------------------------
    # VerifKV security
    # ------------------------------------------------------------------

    verifkv_hmac_secret: SecretStr

    # ------------------------------------------------------------------
    # Backend health
    # ------------------------------------------------------------------

    health_cache_ttl_seconds: float = 5.0

    health_check_timeout_seconds: float = 1.5

    # ------------------------------------------------------------------
    # VerifKV background processing
    # ------------------------------------------------------------------

    verifkv_reconcile_interval_seconds: float = 30.0


@lru_cache
def get_settings() -> Settings:
    """
    Return the process-wide Settings instance.
    """

    return Settings()


settings = get_settings()

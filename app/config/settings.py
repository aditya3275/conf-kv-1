from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------
    # Control-plane database
    # -------------------------------------------------

    database_path: str = "data/control_plane.db"

    # -------------------------------------------------
    # OPA
    # -------------------------------------------------

    opa_url: str = "http://127.0.0.1:8181"

    opa_policy_path: str = "/v1/data/confidentialkv/authz"

    # -------------------------------------------------
    # VerifKV
    # -------------------------------------------------

    verifkv_url: str = "http://127.0.0.1:8100"

    verifkv_db_path: str = "data/verifkv.db"

    verifkv_queue_maxsize: int = 10_000

    verifkv_watch_interval_seconds: float = 5.0

    verifkv_watch_timeout_seconds: float = 1.5

    verifkv_hmac_secret: SecretStr = SecretStr("change-this-in-production")


@lru_cache
def get_settings() -> Settings:
    return Settings()

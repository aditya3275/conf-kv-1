from app.config.settings import Settings


def test_settings_loads_with_explicit_secret() -> None:
    settings = Settings(
        verifkv_hmac_secret="test-secret",
    )

    assert settings.app_name == "Conf-kv-1"
    assert settings.opa_url == "http://127.0.0.1:8181"
    assert settings.control_plane_db_path == "data/control_plane.db"
    assert settings.verifkv_hmac_secret.get_secret_value() == "test-secret"

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Database
    database_url: str = "postgresql+asyncpg://vpn:vpnpass@localhost:5432/vpndb"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Auth
    admin_api_key: str = "change-me"

    # Public-facing base URL (no trailing slash)
    base_url: str = "http://localhost:8000"

    # Middleware / Upstream
    subscription_page_url: str = "http://remnawave-subscription-page:3010"
    remnawave_db_url: str = ""
    bot_db_url: str = ""
    db_schema: str = "public"
    bot_db_schema: str = "public"
    api_timeout_seconds: float = 3.0

    # Balancer config
    outbounds_per_user: int = 6
    probe_interval_seconds: int = 300

    # Cache
    config_cache_ttl_seconds: int = 86400  # 24h

    # Pool health threshold
    min_health_score: float = 0.05

    debug: bool = False


settings = Settings()

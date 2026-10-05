import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("SENTINEL_HOST", "127.0.0.1")
    port: int = int(os.getenv("SENTINEL_PORT", "5000"))

    debug: bool = _bool("SENTINEL_DEBUG", False)

    max_body_bytes: int = int(
        os.getenv("MAX_BODY_BYTES", "1048576")
    )

    rate_limit_max: int = int(
        os.getenv("RATE_LIMIT_MAX", "30")
    )

    rate_limit_window: int = int(
        os.getenv("RATE_LIMIT_WINDOW", "10")
    )

    rate_limit_block_seconds: int = int(
        os.getenv("RATE_LIMIT_BLOCK_SECONDS", "30")
    )

    log_file: str = os.getenv(
        "SENTINEL_LOG_FILE",
        "logs/waf.log"
    )

    log_max_bytes: int = int(
        os.getenv("SENTINEL_LOG_MAX_BYTES", "5242880")
    )

    log_backups: int = int(
        os.getenv("SENTINEL_LOG_BACKUPS", "5")
    )

    dashboard_user: str = os.getenv(
        "DASHBOARD_USER",
        "admin"
    )

    dashboard_password: str = os.getenv(
        "DASHBOARD_PASSWORD",
        "change-me-now"
    )

    @classmethod
    def from_env(cls):
        return cls()

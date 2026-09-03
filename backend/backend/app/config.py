"""Centralized application configuration loaded from environment variables."""

import os
from pydantic_settings import BaseSettings
from typing import List


def _find_dotenv() -> str | None:
    """Walk up from this file to find a .env in the repo root."""
    current = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        candidate = os.path.join(current, ".env")
        if os.path.isfile(candidate):
            return candidate
        current = os.path.dirname(current)
    return None


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str

    # Auth
    SECRET_KEY: str = "dev-secret-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    ALGORITHM: str = "HS256"

    # CORS
    # Development browser requests are same-origin through Vite's /api proxy.
    # Deployments that bypass that proxy can supply an explicit JSON list here.
    CORS_ORIGINS: List[str] = []

    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds
    WS_HEARTBEAT_TIMEOUT: int = 10   # seconds

    # M8 Security
    DEVICE_TOKEN_SECRET: str = "dev-device-token-secret-change-in-production"
    ENROLLMENT_BOOTSTRAP_KEY: str = "spemcs-enrollment-bootstrap-key-default"

    model_config = {
        "env_file": _find_dotenv(),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()

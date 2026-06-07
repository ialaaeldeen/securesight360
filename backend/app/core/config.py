from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration for CyberShield360 backend.

    This file controls project settings, database connection,
    scanner limits, security options, and environment behavior.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    PROJECT_NAME: str = "CyberShield360"
    API_PREFIX: str = "/api/v1"
    APP_ENV: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = True

    # Backend
    BACKEND_HOST: str = "127.0.0.1"
    BACKEND_PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite:///./data/cybershield360.db"

    # CORS: frontend URLs allowed to communicate with backend
    CORS_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    )

    # Scanner feature switches
    ENABLE_WEBSITE_SCANNER: bool = True
    ENABLE_NETWORK_SCANNER: bool = True

    # Scanner safety limits
    MAX_SCAN_TIMEOUT_SECONDS: int = 30
    REQUEST_TIMEOUT_SECONDS: int = 10
    MAX_NETWORK_TARGETS: int = 32

    # Reports
    REPORTS_DIR: str = "generated_reports"

    # Logging
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    @field_validator("API_PREFIX")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        """
        Ensures API prefix always starts with '/' and does not end with '/'.
        Example: /api/v1
        """
        if not value.startswith("/"):
            raise ValueError("API_PREFIX must start with '/'")

        if value.endswith("/"):
            return value.rstrip("/")

        return value

    @field_validator("MAX_SCAN_TIMEOUT_SECONDS", "REQUEST_TIMEOUT_SECONDS")
    @classmethod
    def validate_positive_timeout(cls, value: int) -> int:
        """
        Prevents unsafe or invalid timeout values.
        """
        if value <= 0:
            raise ValueError("Timeout values must be greater than 0")

        return value

    @field_validator("MAX_NETWORK_TARGETS")
    @classmethod
    def validate_max_network_targets(cls, value: int) -> int:
        """
        Keeps network scanning controlled and safe.
        This prevents large unauthorized scan ranges.
        """
        if value < 1:
            raise ValueError("MAX_NETWORK_TARGETS must be at least 1")

        if value > 256:
            raise ValueError("MAX_NETWORK_TARGETS must not exceed 256")

        return value


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings object.

    This avoids reloading environment variables repeatedly
    and keeps configuration consistent across the backend.
    """
    return Settings()


settings = get_settings()
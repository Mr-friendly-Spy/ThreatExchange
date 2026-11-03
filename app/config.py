"""Validated configuration loaded from environment variables or a local .env file."""

from pathlib import Path

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREAT_", env_file=".env", extra="ignore")

    db_path: Path = Path("data/threats.db")
    public_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:8000")
    api_key: SecretStr | None = None
    rate_limit_requests: int = Field(default=60, ge=1, le=100_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)
    rate_limit_max_clients: int = Field(default=10_000, ge=1, le=1_000_000)
    max_body_bytes: int = Field(default=65_536, ge=128, le=1_048_576)

    @field_validator("api_key", mode="before")
    @classmethod
    def validate_api_key(cls, value):
        if value is None or value == "":
            return None
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if len(raw) < 32 or not raw.isascii() or any(char.isspace() for char in raw):
            raise ValueError("API key must contain at least 32 ASCII characters without whitespace")
        return value

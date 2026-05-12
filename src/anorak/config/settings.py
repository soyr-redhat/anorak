"""Configuration settings for Anorak proxy using Pydantic BaseSettings."""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AnorakSettings(BaseSettings):
    """Configuration for Anorak split-key API security proxy."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Server configuration
    HOST: str = Field(default="0.0.0.0", description="Server host")
    PORT: int = Field(default=8080, description="Server port")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")

    # Upstream API configuration (provider agnostic)
    UPSTREAM_API_URL: str = Field(
        ...,
        description="Upstream LLM API URL (e.g., https://api.openai.com, http://localhost:11434)",
    )
    UPSTREAM_API_TOKEN: SecretStr = Field(
        ..., description="Upstream API token (for rotation - not used for requests)"
    )

    # Shard configuration (encrypted at rest)
    SHARD_1_ENCRYPTED: SecretStr = Field(
        ..., description="First encrypted shard (Fernet encrypted with static key)"
    )
    SHARD_2_ENCRYPTED: SecretStr = Field(
        ..., description="Second encrypted shard (Fernet encrypted with static key)"
    )
    SHARD_3_ENCRYPTED: SecretStr = Field(
        ..., description="Third encrypted shard (Fernet encrypted with time-derived key)"
    )
    SHARD_ENCRYPTION_KEY: SecretStr = Field(
        ..., description="Fernet key for shards 1 and 2 encryption"
    )

    # Time-derived encryption configuration for shard 3
    SHARD_3_MASTER_SECRET: SecretStr = Field(
        ..., description="Master secret for deriving shard 3 encryption key (HKDF)"
    )
    SHARD_3_TIME_WINDOW_HOURS: int = Field(
        default=24, description="Time window for shard 3 encryption key rotation (hours)"
    )

    # Shamir's Secret Sharing parameters
    SHARD_THRESHOLD: int = Field(
        default=3, description="Minimum shards required to reconstruct token (3/3 for maximum security)"
    )
    SHARD_TOTAL: int = Field(default=3, description="Total number of shards")

    # Handshake configuration
    HANDSHAKE_SHARED_SECRET: SecretStr = Field(
        ..., description="Shared secret for HMAC handshake"
    )
    HANDSHAKE_TIMEOUT_SECONDS: int = Field(
        default=30, description="Challenge timeout in seconds"
    )

    # Rotation configuration
    ROTATION_ENABLED: bool = Field(default=True, description="Enable automatic rotation")
    ROTATION_TIME_HOURS: int = Field(
        default=24, description="Time-based rotation interval (hours)"
    )
    ROTATION_REQUEST_THRESHOLD: int = Field(
        default=10000, description="Request count threshold for rotation"
    )
    ROTATION_GRACE_PERIOD_MINUTES: int = Field(
        default=5, description="Grace period for old token after rotation (minutes)"
    )

    # Redis configuration
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL for replay prevention and metrics",
    )

    # Admin API configuration
    ADMIN_API_ENABLED: bool = Field(default=True, description="Enable admin endpoints")
    ADMIN_API_KEY: SecretStr = Field(..., description="Admin API key for authentication")


# Global settings instance
settings = AnorakSettings()

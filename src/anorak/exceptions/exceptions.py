"""Custom exceptions for Anorak proxy."""

from enum import Enum
from typing import Optional


class AnorakErrorCode(Enum):
    """Error codes for Anorak exceptions."""

    # Handshake errors (4xx)
    MISSING_HEADERS = (400, "Missing required headers", "E_001")
    INVALID_CHALLENGE = (400, "Invalid challenge format", "E_002")
    CHALLENGE_EXPIRED = (401, "Challenge has expired", "E_003")
    INVALID_HMAC = (401, "Invalid HMAC response", "E_004")
    REPLAY_ATTACK = (403, "Replay attack detected", "E_005")

    # Shard/token errors (5xx)
    SHARD_RECONSTRUCTION_FAILED = (500, "Failed to reconstruct token", "E_101")
    INSUFFICIENT_SHARDS = (500, "Insufficient shards to reconstruct token", "E_102")
    DECRYPTION_FAILED = (500, "Failed to decrypt shard", "E_103")

    # Proxy errors (5xx)
    UPSTREAM_ERROR = (502, "Upstream API error", "E_201")
    UPSTREAM_TIMEOUT = (504, "Upstream API timeout", "E_202")

    # Admin errors (4xx)
    UNAUTHORIZED = (401, "Unauthorized", "E_301")
    ADMIN_API_DISABLED = (403, "Admin API is disabled", "E_302")

    def __init__(self, status_code: int, message: str, code: str):
        self.status_code = status_code
        self.message = message
        self.code = code


class AnorakException(Exception):
    """Base exception for Anorak errors."""

    def __init__(
        self,
        error_code: AnorakErrorCode,
        detail: Optional[str] = None,
    ):
        """
        Initialize Anorak exception.

        Args:
            error_code: AnorakErrorCode enum value
            detail: Optional additional detail message
        """
        self.error_code = error_code
        self.status_code = error_code.status_code
        self.message = error_code.message
        self.code = error_code.code
        self.detail = detail or error_code.message

        super().__init__(self.detail)

    def to_dict(self) -> dict:
        """Convert exception to dictionary for API response."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "detail": self.detail,
                "status_code": self.status_code,
            }
        }


class HandshakeException(AnorakException):
    """Exception for handshake validation failures."""

    pass


class ShardException(AnorakException):
    """Exception for shard-related errors."""

    pass


class ProxyException(AnorakException):
    """Exception for proxy-related errors."""

    pass


class AdminException(AnorakException):
    """Exception for admin API errors."""

    pass

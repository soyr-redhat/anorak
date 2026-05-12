"""Proxy middleware for request interception and handshake validation."""

from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from anorak.config.settings import settings
from anorak.core.crypto.handshake import HandshakeManager
from anorak.core.crypto.shard import reconstruct_token_from_env
from anorak.core.crypto.redis_storage import RedisShardStorage
from anorak.exceptions.exceptions import (
    AnorakErrorCode,
    HandshakeException,
    ShardException,
)
from anorak.utils.logger import get_logger
from anorak.utils.metrics import MetricsTracker

logger = get_logger(__name__)

# Global Redis storage (injected at startup)
_redis_storage: Optional[RedisShardStorage] = None


def set_redis_storage(storage: RedisShardStorage):
    """Set the global Redis storage."""
    global _redis_storage
    _redis_storage = storage


class AnorakProxyMiddleware(BaseHTTPMiddleware):
    """Middleware to intercept requests, validate handshakes, and inject tokens."""

    def __init__(
        self,
        app,
        handshake_manager: HandshakeManager,
        metrics_tracker: Optional[MetricsTracker] = None,
    ):
        """
        Initialize proxy middleware.

        Args:
            app: FastAPI application
            handshake_manager: HandshakeManager for validation
            metrics_tracker: Optional metrics tracker
        """
        super().__init__(app)
        self.handshake_manager = handshake_manager
        self.metrics_tracker = metrics_tracker

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Intercept and process requests.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain

        Returns:
            HTTP response
        """
        # Skip handshake validation for health and challenge endpoints
        if request.url.path.startswith("/health"):
            return await call_next(request)

        # Skip handshake validation for admin endpoints (has its own auth)
        if request.url.path.startswith("/admin"):
            return await call_next(request)

        # Validate handshake for proxy requests
        if request.url.path.startswith("/v1/"):
            try:
                await self._validate_handshake(request)
                logger.info("Handshake validated", path=request.url.path)
            except HandshakeException as e:
                logger.warning(
                    "Handshake validation failed",
                    path=request.url.path,
                    error=e.detail,
                )
                if self.metrics_tracker:
                    await self.metrics_tracker.record_handshake_failure(e.code)
                return Response(
                    content=str(e.to_dict()),
                    status_code=e.status_code,
                    media_type="application/json",
                )

            # Increment request count
            if self.metrics_tracker:
                await self.metrics_tracker.increment_request_count()

        # Continue with request
        return await call_next(request)

    async def _validate_handshake(self, request: Request) -> None:
        """
        Validate HMAC handshake from request headers.

        Args:
            request: HTTP request

        Raises:
            HandshakeException: If validation fails
        """
        # Extract headers
        client_id = request.headers.get("X-Client-ID")
        response_hmac = request.headers.get("X-Response")

        if not client_id or not response_hmac:
            raise HandshakeException(
                AnorakErrorCode.MISSING_HEADERS,
                detail="Missing X-Client-ID or X-Response headers",
            )

        # Get challenge from query params or body
        # For simplicity, we expect the challenge in a header or query param
        # In production, you might have clients fetch challenges first
        challenge = request.headers.get("X-Challenge")

        if not challenge:
            # Try query params
            challenge = request.query_params.get("challenge")

        if not challenge:
            raise HandshakeException(
                AnorakErrorCode.MISSING_HEADERS,
                detail="Missing X-Challenge header or challenge query param",
            )

        # Validate full handshake
        is_valid, error_msg = await self.handshake_manager.validate_full_handshake(
            challenge, response_hmac
        )

        if not is_valid:
            if "expired" in error_msg.lower():
                raise HandshakeException(
                    AnorakErrorCode.CHALLENGE_EXPIRED, detail=error_msg
                )
            elif "replay" in error_msg.lower():
                raise HandshakeException(
                    AnorakErrorCode.REPLAY_ATTACK, detail=error_msg
                )
            else:
                raise HandshakeException(
                    AnorakErrorCode.INVALID_HMAC, detail=error_msg
                )


async def reconstruct_api_token() -> str:
    """
    Reconstruct API token from Redis shards (or env vars fallback).

    Returns:
        Reconstructed API token

    Raises:
        ShardException: If reconstruction fails or time window expired
    """
    try:
        # Try loading from Redis first
        shard_data = None
        if _redis_storage:
            try:
                shard_data = await _redis_storage.load_shards()
                if shard_data:
                    logger.debug("Loading shards from Redis")
            except Exception as redis_error:
                logger.warning(
                    "Failed to load shards from Redis, falling back to env",
                    error=str(redis_error),
                )

        # Fallback to env vars if Redis doesn't have shards
        if not shard_data:
            logger.debug("Loading shards from environment variables")
            shard_data = {
                "shard1_encrypted": settings.SHARD_1_ENCRYPTED.get_secret_value(),
                "shard2_encrypted": settings.SHARD_2_ENCRYPTED.get_secret_value(),
                "shard3_encrypted": settings.SHARD_3_ENCRYPTED.get_secret_value(),
                "encryption_key": settings.SHARD_ENCRYPTION_KEY.get_secret_value(),
                "master_secret": settings.SHARD_3_MASTER_SECRET.get_secret_value(),
            }

        # Reconstruct token
        token = reconstruct_token_from_env(
            shard1_encrypted=shard_data["shard1_encrypted"],
            shard2_encrypted=shard_data["shard2_encrypted"],
            shard3_encrypted=shard_data["shard3_encrypted"],
            shard3_master_secret=shard_data["master_secret"],
            encryption_key=shard_data["encryption_key"],
            time_window_hours=settings.SHARD_3_TIME_WINDOW_HOURS,
            threshold=settings.SHARD_THRESHOLD,
            total_shards=settings.SHARD_TOTAL,
        )
        logger.debug("Token reconstructed successfully (3/3 shards)")
        return token
    except Exception as e:
        logger.error("Token reconstruction failed", error=str(e))
        raise ShardException(
            AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
            detail=f"Failed to reconstruct token: {str(e)}",
        )

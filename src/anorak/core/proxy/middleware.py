"""Proxy middleware for request interception and handshake validation."""

import asyncio
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from anorak.config.settings import settings
from anorak.core.crypto.handshake import HandshakeManager
from anorak.core.crypto.shard import reconstruct_token_from_env
from anorak.core.crypto.redis_storage import RedisShardStorage
from anorak.core.crypto.master_key import validate_master_key
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

# Token caches (to avoid reconstructing on every request)
_cached_maas_token: Optional[str] = None
_maas_token_cache_time: Optional[float] = None
_cached_internal_key: Optional[str] = None
_internal_key_cache_time: Optional[float] = None
_TOKEN_CACHE_SECONDS = 300  # Cache for 5 minutes


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

        # Validate authentication for proxy requests (supports both simple and HMAC modes)
        if request.url.path.startswith("/v1/"):
            try:
                await self._validate_auth(request)
                logger.info("Authentication validated", path=request.url.path)
            except HandshakeException as e:
                logger.warning(
                    "Authentication failed",
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
            logger.info("About to increment request count")
            if self.metrics_tracker:
                await self.metrics_tracker.increment_request_count()
                logger.info("Request count incremented")

        # Continue with request
        logger.info("About to call next middleware/handler")
        response = await call_next(request)
        logger.info("Response received from handler")
        return response

    async def _validate_auth(self, request: Request) -> None:
        """
        Validate authentication - supports both master key and HMAC modes.

        Master key mode: Authorization: Bearer <master-key>
        HMAC mode: X-Client-ID + X-Challenge + X-Response headers

        Args:
            request: HTTP request

        Raises:
            HandshakeException: If validation fails
        """
        # Check for Bearer token auth (for trusted clients like Open WebUI)
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            # Master key mode - validate derived key
            try:
                # Reconstruct internal API key from shards
                internal_api_key = await reconstruct_internal_api_key()

                from anorak.core.proxy.simple_auth import validate_simple_auth
                await validate_simple_auth(auth_header, internal_api_key)
                logger.debug("Master key auth validated")
                return
            except Exception as e:
                raise HandshakeException(
                    AnorakErrorCode.UNAUTHORIZED,
                    detail=f"Master key auth failed: {str(e)}",
                )

        # Fall back to HMAC handshake for external clients
        await self._validate_handshake(request)

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


async def reconstruct_internal_api_key() -> str:
    """
    Reconstruct internal API key from Redis shards.

    Uses caching to avoid expensive reconstruction on every request.

    Returns:
        Reconstructed internal API key

    Raises:
        ShardException: If reconstruction fails
    """
    global _cached_internal_key, _internal_key_cache_time

    # Check cache
    import time
    now = time.time()
    if _cached_internal_key and _internal_key_cache_time and (now - _internal_key_cache_time) < _TOKEN_CACHE_SECONDS:
        logger.debug("Using cached internal API key")
        return _cached_internal_key

    logger.info("Reconstructing internal API key (cache miss or expired)")
    try:
        # Try loading from Redis
        shard_data = None
        if _redis_storage:
            try:
                shard_data = await _redis_storage.load_internal_key_shards()
                if shard_data:
                    logger.debug("Loading internal key shards from Redis")
            except Exception as redis_error:
                logger.warning(
                    "Failed to load internal key shards from Redis",
                    error=str(redis_error),
                )

        if not shard_data:
            raise ShardException(
                AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
                detail="No internal API key shards in Redis. Call POST /admin/init to initialize.",
            )

        # Reconstruct key (run in default thread pool executor since it's CPU-intensive)
        logger.info("Starting internal key reconstruction in thread pool")
        loop = asyncio.get_running_loop()
        key = await loop.run_in_executor(
            None,  # Use default thread pool
            reconstruct_token_from_env,
            shard_data["shard1_encrypted"],
            shard_data["shard2_encrypted"],
            shard_data["shard3_encrypted"],
            shard_data["master_secret"],
            shard_data["encryption_key"],
            settings.SHARD_3_TIME_WINDOW_HOURS,
            settings.SHARD_THRESHOLD,
            settings.SHARD_TOTAL,
        )
        logger.info("Internal API key reconstructed successfully")

        # Cache the key
        _cached_internal_key = key
        _internal_key_cache_time = time.time()

        return key
    except Exception as e:
        logger.error("Internal API key reconstruction failed", error=str(e))
        raise ShardException(
            AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
            detail=f"Failed to reconstruct internal API key: {str(e)}",
        )


async def reconstruct_maas_token() -> str:
    """
    Reconstruct MaaS token from Redis shards (or env vars fallback).

    Uses caching to avoid expensive reconstruction on every request.

    Returns:
        Reconstructed MaaS token

    Raises:
        ShardException: If reconstruction fails
    """
    global _cached_maas_token, _maas_token_cache_time

    # Check cache
    import time
    now = time.time()
    if _cached_maas_token and _maas_token_cache_time and (now - _maas_token_cache_time) < _TOKEN_CACHE_SECONDS:
        logger.debug("Using cached MaaS token")
        return _cached_maas_token

    logger.info("Reconstructing MaaS token (cache miss or expired)")
    try:
        # Try loading from Redis first
        shard_data = None
        if _redis_storage:
            try:
                shard_data = await _redis_storage.load_maas_token_shards()
                if shard_data:
                    logger.debug("Loading MaaS token shards from Redis")
            except Exception as redis_error:
                logger.warning(
                    "Failed to load MaaS token shards from Redis, falling back to env",
                    error=str(redis_error),
                )

        # Fallback to env vars if Redis doesn't have shards
        if not shard_data:
            if not all([settings.SHARD_1_ENCRYPTED, settings.SHARD_2_ENCRYPTED,
                       settings.SHARD_3_ENCRYPTED, settings.SHARD_ENCRYPTION_KEY]):
                raise ShardException(
                    AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
                    detail="No MaaS token shards in Redis and env vars not configured. Call POST /admin/init to initialize.",
                )

            logger.debug("Loading MaaS token shards from environment variables")
            shard_data = {
                "shard1_encrypted": settings.SHARD_1_ENCRYPTED.get_secret_value(),
                "shard2_encrypted": settings.SHARD_2_ENCRYPTED.get_secret_value(),
                "shard3_encrypted": settings.SHARD_3_ENCRYPTED.get_secret_value(),
                "encryption_key": settings.SHARD_ENCRYPTION_KEY.get_secret_value(),
                "master_secret": settings.SHARD_3_MASTER_SECRET.get_secret_value(),
            }

        # Reconstruct token (run in default thread pool executor since it's CPU-intensive)
        logger.info("Starting MaaS token reconstruction in thread pool")
        loop = asyncio.get_running_loop()
        token = await loop.run_in_executor(
            None,  # Use default thread pool
            reconstruct_token_from_env,
            shard_data["shard1_encrypted"],
            shard_data["shard2_encrypted"],
            shard_data["shard3_encrypted"],
            shard_data["master_secret"],
            shard_data["encryption_key"],
            settings.SHARD_3_TIME_WINDOW_HOURS,
            settings.SHARD_THRESHOLD,
            settings.SHARD_TOTAL,
        )
        logger.info("MaaS token reconstructed successfully")

        # Cache the token
        _cached_maas_token = token
        _maas_token_cache_time = time.time()

        return token
    except Exception as e:
        logger.error("MaaS token reconstruction failed", error=str(e))
        raise ShardException(
            AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
            detail=f"Failed to reconstruct MaaS token: {str(e)}",
        )


# Legacy alias for backward compatibility
async def reconstruct_api_token() -> str:
    """Legacy alias - reconstructs MaaS token."""
    return await reconstruct_maas_token()

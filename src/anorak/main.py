"""Anorak - Split-key API security proxy for LLM APIs."""

from contextlib import asynccontextmanager
from typing import Callable

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from anorak.api.routes import admin, health, proxy
from anorak.config.settings import settings
from anorak.core.crypto.handshake import create_handshake_manager
from anorak.core.crypto.redis_storage import RedisShardStorage
from anorak.core.proxy.middleware import AnorakProxyMiddleware, set_redis_storage
from anorak.core.proxy.passthrough import ProxyPassthrough
from anorak.exceptions.exceptions import AnorakException
from anorak.utils.logger import configure_logging, get_logger
from anorak.utils.metrics import MetricsTracker

# Configure logging
configure_logging(settings.LOG_LEVEL)
logger = get_logger(__name__)


# Global state
_proxy_passthrough: ProxyPassthrough = None
_redis_client: aioredis.Redis = None
_handshake_manager = None
_metrics_tracker = None
_redis_storage: RedisShardStorage = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    global _proxy_passthrough, _redis_client, _handshake_manager, _metrics_tracker, _redis_storage

    logger.info("Starting Anorak proxy server")

    # Initialize Redis client
    try:
        _redis_client = await aioredis.from_url(
            settings.REDIS_URL, decode_responses=True, encoding="utf-8"
        )
        await _redis_client.ping()
        logger.info("Redis connected", url=settings.REDIS_URL)
    except Exception as e:
        logger.warning("Redis connection failed, continuing without replay protection", error=str(e))
        _redis_client = None

    # Initialize handshake manager
    _handshake_manager = await create_handshake_manager(
        shared_secret=settings.HANDSHAKE_SHARED_SECRET.get_secret_value(),
        timeout_seconds=settings.HANDSHAKE_TIMEOUT_SECONDS,
        redis_url=settings.REDIS_URL if _redis_client else None,
    )
    health.set_handshake_manager(_handshake_manager)
    logger.info("Handshake manager initialized")

    # Initialize metrics tracker
    _metrics_tracker = MetricsTracker(redis_client=_redis_client)
    admin.set_metrics_tracker(_metrics_tracker)
    logger.info("Metrics tracker initialized")

    # Initialize Redis shard storage (if Redis available)
    if _redis_client:
        _redis_storage = RedisShardStorage(_redis_client)
        set_redis_storage(_redis_storage)
        admin.set_redis_storage(_redis_storage)
        logger.info("Redis shard storage initialized")
    else:
        logger.warning("Redis unavailable - shard storage disabled")

    # Initialize proxy passthrough
    _proxy_passthrough = ProxyPassthrough(
        upstream_url=settings.UPSTREAM_API_URL, timeout=300
    )
    proxy.set_proxy(_proxy_passthrough)
    logger.info("Proxy passthrough initialized", upstream_url=settings.UPSTREAM_API_URL)

    # Pre-warm token caches on startup (so first request doesn't timeout)
    from anorak.core.proxy.middleware import reconstruct_internal_api_key, reconstruct_maas_token
    logger.info("Pre-warming token caches (this may take 20-60 seconds)...")
    try:
        # Warm internal API key cache
        await reconstruct_internal_api_key()
        logger.info("Internal API key cache pre-warmed")

        # Warm MaaS token cache
        await reconstruct_maas_token()
        logger.info("MaaS token cache pre-warmed")

        logger.info("All token caches pre-warmed successfully")
    except Exception as e:
        logger.warning("Failed to pre-warm token caches", error=str(e))

    yield

    # Cleanup
    logger.info("Shutting down Anorak proxy server")

    if _proxy_passthrough:
        await _proxy_passthrough.close()

    if _redis_client:
        await _redis_client.close()


# Lazy-loading middleware wrapper
class LazyAnorakMiddleware(BaseHTTPMiddleware):
    """Lazy-loading wrapper that gets dependencies from globals."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get dependencies from globals at request time
        if _handshake_manager is None or _metrics_tracker is None:
            # Dependencies not ready yet, just pass through
            return await call_next(request)

        # Create middleware instance with dependencies and dispatch
        middleware = AnorakProxyMiddleware(
            app=self.app,
            handshake_manager=_handshake_manager,
            metrics_tracker=_metrics_tracker,
        )
        return await middleware.dispatch(request, call_next)


# Create FastAPI application
app = FastAPI(
    title="Anorak",
    description="Split-key API security proxy for LLM APIs",
    version="0.1.0",
    lifespan=lifespan,
)

# Add lazy middleware (before routes are added)
app.add_middleware(LazyAnorakMiddleware)


# Exception handler
@app.exception_handler(AnorakException)
async def anorak_exception_handler(request, exc: AnorakException):
    """Handle Anorak exceptions."""
    logger.error(
        "Anorak exception",
        code=exc.code,
        detail=exc.detail,
        path=request.url.path,
    )
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())


# Include routers
app.include_router(health.router, tags=["health"])
app.include_router(proxy.router, tags=["proxy"])
app.include_router(admin.router, tags=["admin"])


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "Anorak",
        "description": "Split-key API security proxy for LLM APIs",
        "version": "0.1.0",
        "upstream": settings.UPSTREAM_API_URL,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "anorak.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL.lower(),
    )

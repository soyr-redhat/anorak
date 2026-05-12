"""Anorak - Split-key API security proxy for LLM APIs."""

from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from anorak.api.routes import admin, health, proxy
from anorak.config.settings import settings
from anorak.core.crypto.handshake import create_handshake_manager
from anorak.core.proxy.middleware import AnorakProxyMiddleware
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    global _proxy_passthrough, _redis_client, _handshake_manager, _metrics_tracker

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

    # Initialize proxy passthrough
    _proxy_passthrough = ProxyPassthrough(
        upstream_url=settings.UPSTREAM_API_URL, timeout=300
    )
    proxy.set_proxy(_proxy_passthrough)
    logger.info("Proxy passthrough initialized", upstream_url=settings.UPSTREAM_API_URL)

    yield

    # Cleanup
    logger.info("Shutting down Anorak proxy server")

    if _proxy_passthrough:
        await _proxy_passthrough.close()

    if _redis_client:
        await _redis_client.close()


# Create FastAPI application
app = FastAPI(
    title="Anorak",
    description="Split-key API security proxy for LLM APIs",
    version="0.1.0",
    lifespan=lifespan,
)


# Add middleware
@app.on_event("startup")
async def add_middleware():
    """Add middleware after initialization."""
    if _handshake_manager and _metrics_tracker:
        app.add_middleware(
            AnorakProxyMiddleware,
            handshake_manager=_handshake_manager,
            metrics_tracker=_metrics_tracker,
        )
        logger.info("Proxy middleware added")


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

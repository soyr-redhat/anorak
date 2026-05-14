"""Admin API endpoints for management and monitoring."""

from typing import Optional
from fastapi import APIRouter, Header
from pydantic import BaseModel

from anorak.config.settings import settings
from anorak.core.crypto.redis_storage import RedisShardStorage
from anorak.core.crypto.shard import split_and_encrypt_token
from anorak.core.crypto.master_key import generate_internal_api_key, derive_master_key
from anorak.exceptions.exceptions import AdminException, AnorakErrorCode
from anorak.utils.logger import get_logger
from anorak.utils.metrics import MetricsTracker

logger = get_logger(__name__)

router = APIRouter()

# Global metrics tracker and Redis storage (injected at startup)
_metrics_tracker: MetricsTracker = None
_redis_storage: RedisShardStorage = None


def set_metrics_tracker(tracker: MetricsTracker):
    """Set the global metrics tracker."""
    global _metrics_tracker
    _metrics_tracker = tracker


def set_redis_storage(storage: RedisShardStorage):
    """Set the global Redis storage."""
    global _redis_storage
    _redis_storage = storage


class ShardStatusResponse(BaseModel):
    """Shard status response (no sensitive data)."""

    total_shards: int
    threshold: int
    time_window_hours: int
    encryption_enabled: bool


class MetricsResponse(BaseModel):
    """Metrics response."""

    request_count: int
    timestamp: str


class InitRequest(BaseModel):
    """Initialization request."""

    maas_token: str  # MaaS token to shard and store


class InitResponse(BaseModel):
    """Initialization response."""

    success: bool
    message: str
    master_key: str  # Derived master key for Open WebUI


class MasterKeyResponse(BaseModel):
    """Master key response."""

    master_key: str
    message: str


def validate_admin_key(api_key: str):
    """
    Validate admin API key.

    Args:
        api_key: API key from header

    Raises:
        AdminException: If key is invalid or admin API is disabled
    """
    if not settings.ADMIN_API_ENABLED:
        raise AdminException(
            AnorakErrorCode.ADMIN_API_DISABLED,
            detail="Admin API is disabled in configuration",
        )

    expected_key = settings.ADMIN_API_KEY.get_secret_value()
    if api_key != expected_key:
        raise AdminException(AnorakErrorCode.UNAUTHORIZED, detail="Invalid admin API key")


@router.get("/admin/shards", response_model=ShardStatusResponse)
async def get_shard_status(api_key: str = Header(..., alias="X-Admin-Key")):
    """
    Get shard status (no sensitive data exposed).

    Args:
        api_key: Admin API key from header

    Returns:
        Shard configuration status
    """
    validate_admin_key(api_key)

    return ShardStatusResponse(
        total_shards=settings.SHARD_TOTAL,
        threshold=settings.SHARD_THRESHOLD,
        time_window_hours=settings.SHARD_3_TIME_WINDOW_HOURS,
        encryption_enabled=True,
    )


@router.get("/admin/metrics", response_model=MetricsResponse)
async def get_metrics(api_key: str = Header(..., alias="X-Admin-Key")):
    """
    Get proxy metrics.

    Args:
        api_key: Admin API key from header

    Returns:
        Current metrics
    """
    validate_admin_key(api_key)

    if not _metrics_tracker:
        return MetricsResponse(request_count=0, timestamp="N/A")

    metrics = await _metrics_tracker.get_metrics_summary()

    return MetricsResponse(
        request_count=metrics.get("request_count", 0),
        timestamp=metrics.get("timestamp", "N/A"),
    )


@router.post("/admin/init", response_model=InitResponse)
async def initialize_system(
    init_request: InitRequest,
    api_key: str = Header(..., alias="X-Admin-Key"),
):
    """
    Initialize Anorak with double-layer Shamir crypto.

    This endpoint:
    1. Generates a new internal API key
    2. Shards and stores internal API key in Redis
    3. Shards and stores MaaS token in Redis
    4. Returns the derived master key for distribution to Open WebUI

    Args:
        init_request: Initialization request with MaaS token
        api_key: Admin API key from header

    Returns:
        Initialization result with master key
    """
    validate_admin_key(api_key)

    if not _redis_storage:
        raise AdminException(
            AnorakErrorCode.ADMIN_API_DISABLED,
            detail="Redis storage not initialized",
        )

    logger.info("System initialization requested")

    try:
        # Generate internal API key
        internal_api_key = generate_internal_api_key()
        logger.info("Generated internal API key")

        # Shard and encrypt internal API key
        internal_shards = split_and_encrypt_token(
            internal_api_key,
            threshold=settings.SHARD_THRESHOLD,
            total_shards=settings.SHARD_TOTAL,
        )

        # Store internal key shards in Redis
        await _redis_storage.store_internal_key_shards(
            shard1_encrypted=internal_shards["shard1_encrypted"],
            shard2_encrypted=internal_shards["shard2_encrypted"],
            shard3_encrypted=internal_shards["shard3_encrypted"],
            encryption_key=internal_shards["encryption_key"],
            master_secret=internal_shards["master_secret"],
        )
        logger.info("Stored internal API key shards in Redis")

        # Shard and encrypt MaaS token
        maas_shards = split_and_encrypt_token(
            init_request.maas_token,
            threshold=settings.SHARD_THRESHOLD,
            total_shards=settings.SHARD_TOTAL,
        )

        # Store MaaS token shards in Redis
        await _redis_storage.store_maas_token_shards(
            shard1_encrypted=maas_shards["shard1_encrypted"],
            shard2_encrypted=maas_shards["shard2_encrypted"],
            shard3_encrypted=maas_shards["shard3_encrypted"],
            encryption_key=maas_shards["encryption_key"],
            master_secret=maas_shards["master_secret"],
        )
        logger.info("Stored MaaS token shards in Redis")

        # Derive master key for Open WebUI
        master_key = derive_master_key(internal_api_key)
        logger.info("Derived master key")

        return InitResponse(
            success=True,
            message="System initialized successfully. Use the master_key with Open WebUI.",
            master_key=master_key,
        )
    except Exception as e:
        logger.error("Initialization failed", error=str(e))
        raise AdminException(
            AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
            detail=f"Initialization failed: {str(e)}",
        )


@router.get("/admin/master-key", response_model=MasterKeyResponse)
async def get_master_key(api_key: str = Header(..., alias="X-Admin-Key")):
    """
    Get the current master key (derived from internal API key).

    This is useful if you need to retrieve the master key after initialization.

    Args:
        api_key: Admin API key from header

    Returns:
        Master key response
    """
    validate_admin_key(api_key)

    if not _redis_storage:
        raise AdminException(
            AnorakErrorCode.ADMIN_API_DISABLED,
            detail="Redis storage not initialized",
        )

    try:
        # Load and reconstruct internal API key
        from anorak.core.proxy.middleware import reconstruct_internal_api_key
        internal_api_key = await reconstruct_internal_api_key()

        # Derive master key
        master_key = derive_master_key(internal_api_key)

        return MasterKeyResponse(
            master_key=master_key,
            message="Master key derived successfully",
        )
    except Exception as e:
        logger.error("Failed to get master key", error=str(e))
        raise AdminException(
            AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
            detail=f"Failed to get master key: {str(e)}",
        )

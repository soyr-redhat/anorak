"""Admin API endpoints for management and monitoring."""

from typing import Optional
from fastapi import APIRouter, Header
from pydantic import BaseModel

from anorak.config.settings import settings
from anorak.exceptions.exceptions import AdminException, AnorakErrorCode
from anorak.utils.logger import get_logger
from anorak.utils.metrics import MetricsTracker
from anorak.core.rotation.engine import RotationEngine

logger = get_logger(__name__)

router = APIRouter()

# Global metrics tracker and rotation engine (injected at startup)
_metrics_tracker: MetricsTracker = None
_rotation_engine: RotationEngine = None


def set_metrics_tracker(tracker: MetricsTracker):
    """Set the global metrics tracker."""
    global _metrics_tracker
    _metrics_tracker = tracker


def set_rotation_engine(engine: RotationEngine):
    """Set the global rotation engine."""
    global _rotation_engine
    _rotation_engine = engine


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


class RotationRequest(BaseModel):
    """Rotation request."""

    reason: str = "manual"


class RotationResponse(BaseModel):
    """Rotation response."""

    success: bool
    message: str
    window_id: Optional[int] = None
    expires_at: Optional[str] = None
    time_until_expiry_hours: Optional[float] = None


class RotationStatusResponse(BaseModel):
    """Rotation status response."""

    shards_in_redis: bool
    rotation_required: bool
    rotation_reason: str = ""
    current_window_id: Optional[int] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    time_until_expiry_seconds: Optional[float] = None
    time_until_expiry_hours: Optional[float] = None
    message: str = ""


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


@router.get("/admin/rotation/status", response_model=RotationStatusResponse)
async def get_rotation_status(api_key: str = Header(..., alias="X-Admin-Key")):
    """
    Get current rotation status.

    Args:
        api_key: Admin API key from header

    Returns:
        Rotation status including time until expiry
    """
    validate_admin_key(api_key)

    if not _rotation_engine:
        return RotationStatusResponse(
            shards_in_redis=False,
            rotation_required=False,
            message="Rotation engine not initialized",
        )

    status = await _rotation_engine.get_status()

    return RotationStatusResponse(
        shards_in_redis=status.get("shards_in_redis", False),
        rotation_required=status.get("rotation_required", False),
        rotation_reason=status.get("rotation_reason", ""),
        current_window_id=status.get("current_window_id"),
        created_at=status.get("created_at"),
        expires_at=status.get("expires_at"),
        time_until_expiry_seconds=status.get("time_until_expiry_seconds"),
        time_until_expiry_hours=status.get("time_until_expiry_hours"),
        message=status.get("message", ""),
    )


@router.post("/admin/rotate", response_model=RotationResponse)
async def trigger_rotation(
    rotation_request: RotationRequest,
    api_key: str = Header(..., alias="X-Admin-Key"),
):
    """
    Manually trigger token rotation.

    This endpoint regenerates shards from UPSTREAM_API_TOKEN and stores them in Redis.

    Args:
        rotation_request: Rotation request with reason
        api_key: Admin API key from header

    Returns:
        Rotation result with new window metadata
    """
    validate_admin_key(api_key)

    if not _rotation_engine:
        raise AdminException(
            AnorakErrorCode.ADMIN_API_DISABLED,
            detail="Rotation engine not initialized",
        )

    logger.info("Manual rotation requested", reason=rotation_request.reason)

    try:
        # Read token from settings
        token = settings.UPSTREAM_API_TOKEN.get_secret_value()

        result = await _rotation_engine.rotate_token(token)

        return RotationResponse(
            success=result["success"],
            message="Token rotation completed successfully",
            window_id=result["window_id"],
            expires_at=result["expires_at"],
            time_until_expiry_hours=result["time_until_expiry_hours"],
        )
    except Exception as e:
        logger.error("Rotation failed", error=str(e))
        raise AdminException(
            AnorakErrorCode.SHARD_RECONSTRUCTION_FAILED,
            detail=f"Rotation failed: {str(e)}",
        )

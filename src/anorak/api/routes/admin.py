"""Admin API endpoints for management and monitoring."""

from fastapi import APIRouter, Header
from pydantic import BaseModel

from anorak.config.settings import settings
from anorak.exceptions.exceptions import AdminException, AnorakErrorCode
from anorak.utils.logger import get_logger
from anorak.utils.metrics import MetricsTracker

logger = get_logger(__name__)

router = APIRouter()

# Global metrics tracker (injected at startup)
_metrics_tracker: MetricsTracker = None


def set_metrics_tracker(tracker: MetricsTracker):
    """Set the global metrics tracker."""
    global _metrics_tracker
    _metrics_tracker = tracker


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


@router.post("/admin/rotate", response_model=RotationResponse)
async def trigger_rotation(
    rotation_request: RotationRequest,
    api_key: str = Header(..., alias="X-Admin-Key"),
):
    """
    Manually trigger token rotation.

    NOTE: For MVP, this endpoint returns instructions for manual rotation.
    In production, this would orchestrate automatic rotation.

    Args:
        rotation_request: Rotation request with reason
        api_key: Admin API key from header

    Returns:
        Rotation result
    """
    validate_admin_key(api_key)

    logger.info("Manual rotation requested", reason=rotation_request.reason)

    # For MVP, rotation is manual - provide instructions
    return RotationResponse(
        success=True,
        message=(
            "Manual rotation: Generate new token, run scripts/init_shards.py "
            "with new token, update environment variables, restart service"
        ),
    )

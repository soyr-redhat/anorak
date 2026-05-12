"""Metrics tracking for Anorak proxy."""

import datetime
from typing import Optional

import redis.asyncio as aioredis


class MetricsTracker:
    """Track proxy metrics using Redis."""

    def __init__(self, redis_client: Optional[aioredis.Redis] = None):
        """
        Initialize metrics tracker.

        Args:
            redis_client: Optional Redis client for storing metrics
        """
        self.redis_client = redis_client

    async def increment_request_count(self) -> int:
        """
        Increment total request count.

        Returns:
            New request count
        """
        if not self.redis_client:
            return 0

        key = "anorak:metrics:request_count"
        return await self.redis_client.incr(key)

    async def get_request_count(self) -> int:
        """
        Get current request count.

        Returns:
            Total request count
        """
        if not self.redis_client:
            return 0

        key = "anorak:metrics:request_count"
        count = await self.redis_client.get(key)
        return int(count) if count else 0

    async def record_rotation(self, rotation_id: str, reason: str) -> None:
        """
        Record a rotation event.

        Args:
            rotation_id: Unique rotation identifier
            reason: Reason for rotation (time, request_count, manual, etc.)
        """
        if not self.redis_client:
            return

        key = f"anorak:metrics:rotation:{rotation_id}"
        data = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "reason": reason,
        }
        await self.redis_client.hset(key, mapping=data)
        await self.redis_client.expire(key, 86400 * 30)  # 30 days retention

    async def record_handshake_failure(self, reason: str) -> None:
        """
        Record a handshake failure.

        Args:
            reason: Failure reason (expired, replay, invalid_hmac, etc.)
        """
        if not self.redis_client:
            return

        key = f"anorak:metrics:handshake_failures:{reason}"
        await self.redis_client.incr(key)

    async def get_metrics_summary(self) -> dict:
        """
        Get summary of all metrics.

        Returns:
            Dictionary of metric values
        """
        if not self.redis_client:
            return {}

        request_count = await self.get_request_count()

        return {
            "request_count": request_count,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

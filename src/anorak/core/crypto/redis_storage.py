"""Redis-based shard storage for runtime rotation support."""

import datetime
import json
from typing import Optional, Dict, Any

import redis.asyncio as redis

from anorak.utils.logger import get_logger

logger = get_logger(__name__)


class RedisShardStorage:
    """Manages shard storage in Redis for runtime rotation."""

    SHARD_KEY_PREFIX = "anorak:shard"
    METADATA_KEY = "anorak:shard:metadata"
    ROTATION_STATUS_KEY = "anorak:rotation:status"

    def __init__(self, redis_client: redis.Redis):
        """
        Initialize Redis shard storage.

        Args:
            redis_client: Async Redis client
        """
        self.redis = redis_client

    async def store_shards(
        self,
        shard1_encrypted: str,
        shard2_encrypted: str,
        shard3_encrypted: str,
        encryption_key: str,
        master_secret: str,
        window_id: int,
        time_window_hours: int = 24,
    ) -> None:
        """
        Store encrypted shards in Redis.

        Args:
            shard1_encrypted: Encrypted shard 1
            shard2_encrypted: Encrypted shard 2
            shard3_encrypted: Encrypted shard 3 (time-derived encryption)
            encryption_key: Fernet key for shards 1 and 2
            master_secret: Master secret for shard 3 time-derived encryption
            window_id: Current time window ID
            time_window_hours: Time window size in hours
        """
        # Store shards (no TTL - we manage expiry via metadata)
        await self.redis.set(f"{self.SHARD_KEY_PREFIX}:1:encrypted", shard1_encrypted)
        await self.redis.set(f"{self.SHARD_KEY_PREFIX}:2:encrypted", shard2_encrypted)
        await self.redis.set(f"{self.SHARD_KEY_PREFIX}:3:encrypted", shard3_encrypted)

        # Store encryption keys (for reconstruction)
        await self.redis.set(f"{self.SHARD_KEY_PREFIX}:encryption_key", encryption_key)
        await self.redis.set(f"{self.SHARD_KEY_PREFIX}:master_secret", master_secret)

        # Store metadata
        metadata = {
            "window_id": window_id,
            "time_window_hours": time_window_hours,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "expires_at": datetime.datetime.utcfromtimestamp(
                (window_id + 1) * time_window_hours * 3600
            ).isoformat(),
        }
        await self.redis.set(self.METADATA_KEY, json.dumps(metadata))

        logger.info(
            "Stored shards in Redis",
            window_id=window_id,
            expires_at=metadata["expires_at"],
        )

    async def load_shards(self) -> Optional[Dict[str, str]]:
        """
        Load encrypted shards from Redis.

        Returns:
            Dict with shard data, or None if not found
        """
        shard1 = await self.redis.get(f"{self.SHARD_KEY_PREFIX}:1:encrypted")
        shard2 = await self.redis.get(f"{self.SHARD_KEY_PREFIX}:2:encrypted")
        shard3 = await self.redis.get(f"{self.SHARD_KEY_PREFIX}:3:encrypted")
        encryption_key = await self.redis.get(f"{self.SHARD_KEY_PREFIX}:encryption_key")
        master_secret = await self.redis.get(f"{self.SHARD_KEY_PREFIX}:master_secret")

        if not all([shard1, shard2, shard3, encryption_key, master_secret]):
            logger.warning("Shards not found in Redis, falling back to env vars")
            return None

        # Redis client is configured with decode_responses=True, so values are already strings
        return {
            "shard1_encrypted": shard1,
            "shard2_encrypted": shard2,
            "shard3_encrypted": shard3,
            "encryption_key": encryption_key,
            "master_secret": master_secret,
        }

    async def get_metadata(self) -> Optional[Dict[str, Any]]:
        """
        Get shard metadata from Redis.

        Returns:
            Metadata dict, or None if not found
        """
        metadata_json = await self.redis.get(self.METADATA_KEY)
        if not metadata_json:
            return None

        # Redis client configured with decode_responses=True, so already a string
        return json.loads(metadata_json)

    async def is_rotation_required(self) -> bool:
        """
        Check if rotation is required (time window expired).

        Returns:
            True if rotation required
        """
        metadata = await self.get_metadata()
        if not metadata:
            logger.warning("No metadata found in Redis")
            return False

        # Check if current time is past expiry
        expires_at = datetime.datetime.fromisoformat(metadata["expires_at"])
        now = datetime.datetime.utcnow()

        if now >= expires_at:
            logger.warning(
                "Time window expired, rotation required",
                expires_at=expires_at.isoformat(),
                now=now.isoformat(),
            )
            return True

        return False

    async def set_rotation_status(
        self, required: bool, reason: Optional[str] = None
    ) -> None:
        """
        Set rotation status flag.

        Args:
            required: Whether rotation is required
            reason: Optional reason for status change
        """
        status = {
            "required": required,
            "reason": reason or "",
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        await self.redis.set(self.ROTATION_STATUS_KEY, json.dumps(status))

        logger.info("Rotation status updated", required=required, reason=reason)

    async def get_rotation_status(self) -> Dict[str, Any]:
        """
        Get current rotation status.

        Returns:
            Status dict
        """
        status_json = await self.redis.get(self.ROTATION_STATUS_KEY)
        if not status_json:
            return {"required": False, "reason": "", "timestamp": None}

        # Redis client configured with decode_responses=True, so already a string
        return json.loads(status_json)

    async def clear_shards(self) -> None:
        """Clear all shards from Redis (for rotation)."""
        keys_to_delete = [
            f"{self.SHARD_KEY_PREFIX}:1:encrypted",
            f"{self.SHARD_KEY_PREFIX}:2:encrypted",
            f"{self.SHARD_KEY_PREFIX}:3:encrypted",
            f"{self.SHARD_KEY_PREFIX}:encryption_key",
            f"{self.SHARD_KEY_PREFIX}:master_secret",
            self.METADATA_KEY,
            self.ROTATION_STATUS_KEY,
        ]
        await self.redis.delete(*keys_to_delete)
        logger.info("Cleared shards from Redis")

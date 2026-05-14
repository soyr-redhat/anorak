"""Redis-based dual shard storage for internal API key and MaaS token."""

import datetime
import json
from typing import Optional, Dict, Any

import redis.asyncio as redis

from anorak.utils.logger import get_logger

logger = get_logger(__name__)


class RedisShardStorage:
    """Manages dual shard storage in Redis: internal API key + MaaS token."""

    INTERNAL_KEY_PREFIX = "anorak:internal_key:shard"
    MAAS_TOKEN_PREFIX = "anorak:maas_token:shard"
    INTERNAL_KEY_METADATA = "anorak:internal_key:metadata"
    MAAS_TOKEN_METADATA = "anorak:maas_token:metadata"

    def __init__(self, redis_client: redis.Redis):
        """
        Initialize Redis shard storage.

        Args:
            redis_client: Async Redis client
        """
        self.redis = redis_client

    async def store_internal_key_shards(
        self,
        shard1_encrypted: str,
        shard2_encrypted: str,
        shard3_encrypted: str,
        encryption_key: str,
        master_secret: str,
    ) -> None:
        """
        Store encrypted internal API key shards in Redis.

        Args:
            shard1_encrypted: Encrypted shard 1
            shard2_encrypted: Encrypted shard 2
            shard3_encrypted: Encrypted shard 3
            encryption_key: Fernet key for shard encryption
            master_secret: Master secret for time-derived shard
        """
        await self.redis.set(f"{self.INTERNAL_KEY_PREFIX}:1:encrypted", shard1_encrypted)
        await self.redis.set(f"{self.INTERNAL_KEY_PREFIX}:2:encrypted", shard2_encrypted)
        await self.redis.set(f"{self.INTERNAL_KEY_PREFIX}:3:encrypted", shard3_encrypted)
        await self.redis.set(f"{self.INTERNAL_KEY_PREFIX}:encryption_key", encryption_key)
        await self.redis.set(f"{self.INTERNAL_KEY_PREFIX}:master_secret", master_secret)

        # Store metadata
        metadata = {
            "created_at": datetime.datetime.utcnow().isoformat(),
            "type": "internal_api_key",
        }
        await self.redis.set(self.INTERNAL_KEY_METADATA, json.dumps(metadata))

        logger.info("Stored internal API key shards in Redis")

    async def load_internal_key_shards(self) -> Optional[Dict[str, str]]:
        """
        Load encrypted internal API key shards from Redis.

        Returns:
            Dict with shard data, or None if not found
        """
        shard1 = await self.redis.get(f"{self.INTERNAL_KEY_PREFIX}:1:encrypted")
        shard2 = await self.redis.get(f"{self.INTERNAL_KEY_PREFIX}:2:encrypted")
        shard3 = await self.redis.get(f"{self.INTERNAL_KEY_PREFIX}:3:encrypted")
        encryption_key = await self.redis.get(f"{self.INTERNAL_KEY_PREFIX}:encryption_key")
        master_secret = await self.redis.get(f"{self.INTERNAL_KEY_PREFIX}:master_secret")

        if not all([shard1, shard2, shard3, encryption_key, master_secret]):
            logger.debug("Internal API key shards not found in Redis")
            return None

        return {
            "shard1_encrypted": shard1,
            "shard2_encrypted": shard2,
            "shard3_encrypted": shard3,
            "encryption_key": encryption_key,
            "master_secret": master_secret,
        }

    async def store_maas_token_shards(
        self,
        shard1_encrypted: str,
        shard2_encrypted: str,
        shard3_encrypted: str,
        encryption_key: str,
        master_secret: str,
    ) -> None:
        """
        Store encrypted MaaS token shards in Redis.

        Args:
            shard1_encrypted: Encrypted shard 1
            shard2_encrypted: Encrypted shard 2
            shard3_encrypted: Encrypted shard 3
            encryption_key: Fernet key for shard encryption
            master_secret: Master secret for time-derived shard
        """
        await self.redis.set(f"{self.MAAS_TOKEN_PREFIX}:1:encrypted", shard1_encrypted)
        await self.redis.set(f"{self.MAAS_TOKEN_PREFIX}:2:encrypted", shard2_encrypted)
        await self.redis.set(f"{self.MAAS_TOKEN_PREFIX}:3:encrypted", shard3_encrypted)
        await self.redis.set(f"{self.MAAS_TOKEN_PREFIX}:encryption_key", encryption_key)
        await self.redis.set(f"{self.MAAS_TOKEN_PREFIX}:master_secret", master_secret)

        # Store metadata
        metadata = {
            "created_at": datetime.datetime.utcnow().isoformat(),
            "type": "maas_token",
        }
        await self.redis.set(self.MAAS_TOKEN_METADATA, json.dumps(metadata))

        logger.info("Stored MaaS token shards in Redis")

    async def load_maas_token_shards(self) -> Optional[Dict[str, str]]:
        """
        Load encrypted MaaS token shards from Redis.

        Returns:
            Dict with shard data, or None if not found
        """
        shard1 = await self.redis.get(f"{self.MAAS_TOKEN_PREFIX}:1:encrypted")
        shard2 = await self.redis.get(f"{self.MAAS_TOKEN_PREFIX}:2:encrypted")
        shard3 = await self.redis.get(f"{self.MAAS_TOKEN_PREFIX}:3:encrypted")
        encryption_key = await self.redis.get(f"{self.MAAS_TOKEN_PREFIX}:encryption_key")
        master_secret = await self.redis.get(f"{self.MAAS_TOKEN_PREFIX}:master_secret")

        if not all([shard1, shard2, shard3, encryption_key, master_secret]):
            logger.debug("MaaS token shards not found in Redis")
            return None

        return {
            "shard1_encrypted": shard1,
            "shard2_encrypted": shard2,
            "shard3_encrypted": shard3,
            "encryption_key": encryption_key,
            "master_secret": master_secret,
        }

    async def get_internal_key_metadata(self) -> Optional[Dict[str, Any]]:
        """Get internal API key metadata from Redis."""
        metadata_json = await self.redis.get(self.INTERNAL_KEY_METADATA)
        if not metadata_json:
            return None
        return json.loads(metadata_json)

    async def get_maas_token_metadata(self) -> Optional[Dict[str, Any]]:
        """Get MaaS token metadata from Redis."""
        metadata_json = await self.redis.get(self.MAAS_TOKEN_METADATA)
        if not metadata_json:
            return None
        return json.loads(metadata_json)

    async def clear_internal_key_shards(self) -> None:
        """Clear internal API key shards from Redis."""
        keys_to_delete = [
            f"{self.INTERNAL_KEY_PREFIX}:1:encrypted",
            f"{self.INTERNAL_KEY_PREFIX}:2:encrypted",
            f"{self.INTERNAL_KEY_PREFIX}:3:encrypted",
            f"{self.INTERNAL_KEY_PREFIX}:encryption_key",
            f"{self.INTERNAL_KEY_PREFIX}:master_secret",
            self.INTERNAL_KEY_METADATA,
        ]
        await self.redis.delete(*keys_to_delete)
        logger.info("Cleared internal API key shards from Redis")

    async def clear_maas_token_shards(self) -> None:
        """Clear MaaS token shards from Redis."""
        keys_to_delete = [
            f"{self.MAAS_TOKEN_PREFIX}:1:encrypted",
            f"{self.MAAS_TOKEN_PREFIX}:2:encrypted",
            f"{self.MAAS_TOKEN_PREFIX}:3:encrypted",
            f"{self.MAAS_TOKEN_PREFIX}:encryption_key",
            f"{self.MAAS_TOKEN_PREFIX}:master_secret",
            self.MAAS_TOKEN_METADATA,
        ]
        await self.redis.delete(*keys_to_delete)
        logger.info("Cleared MaaS token shards from Redis")

    # Legacy compatibility - maps old methods to MaaS token methods
    async def store_shards(self, *args, **kwargs) -> None:
        """Legacy method - stores MaaS token shards."""
        # Remove window_id and time_window_hours from kwargs if present
        kwargs.pop("window_id", None)
        kwargs.pop("time_window_hours", None)
        await self.store_maas_token_shards(*args, **kwargs)

    async def load_shards(self) -> Optional[Dict[str, str]]:
        """Legacy method - loads MaaS token shards."""
        return await self.load_maas_token_shards()

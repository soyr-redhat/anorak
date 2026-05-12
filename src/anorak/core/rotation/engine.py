"""Rotation engine for automatic shard rotation."""

import asyncio
import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from anorak.core.crypto.redis_storage import RedisShardStorage
from anorak.core.crypto.shard import ShardManager, ShardData
from anorak.core.crypto.encryption import EncryptionManager
from anorak.utils.logger import get_logger

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import secrets

logger = get_logger(__name__)


class RotationEngine:
    """Manages automatic shard rotation based on time windows."""

    def __init__(
        self,
        redis_storage: RedisShardStorage,
        check_interval_minutes: int = 60,
        time_window_hours: int = 24,
    ):
        """
        Initialize rotation engine.

        Args:
            redis_storage: Redis shard storage instance
            check_interval_minutes: How often to check for rotation (minutes)
            time_window_hours: Time window size in hours
        """
        self.redis_storage = redis_storage
        self.check_interval_minutes = check_interval_minutes
        self.time_window_hours = time_window_hours
        self.scheduler = AsyncIOScheduler()

    async def start(self) -> None:
        """Start the rotation monitoring scheduler."""
        # Add scheduled job to check rotation status
        self.scheduler.add_job(
            self._check_rotation_required,
            trigger=IntervalTrigger(minutes=self.check_interval_minutes),
            id="rotation_check",
            name="Check if rotation required",
            replace_existing=True,
        )

        self.scheduler.start()
        logger.info(
            "Rotation engine started",
            check_interval_minutes=self.check_interval_minutes,
        )

        # Run initial check
        await self._check_rotation_required()

    async def stop(self) -> None:
        """Stop the rotation monitoring scheduler."""
        self.scheduler.shutdown()
        logger.info("Rotation engine stopped")

    async def _check_rotation_required(self) -> None:
        """
        Check if rotation is required (called periodically).

        Sets rotation status flag if time window has expired.
        """
        try:
            is_required = await self.redis_storage.is_rotation_required()

            if is_required:
                # Get current status to avoid duplicate logs
                current_status = await self.redis_storage.get_rotation_status()
                if not current_status.get("required"):
                    metadata = await self.redis_storage.get_metadata()
                    expires_at = metadata.get("expires_at") if metadata else "unknown"

                    await self.redis_storage.set_rotation_status(
                        required=True,
                        reason=f"Time window expired at {expires_at}",
                    )

                    logger.warning(
                        "Rotation required - time window expired",
                        expires_at=expires_at,
                    )
        except Exception as e:
            logger.error("Error checking rotation status", error=str(e))

    async def rotate_token(
        self,
        new_token: str,
        encryption_key: Optional[str] = None,
        master_secret: Optional[str] = None,
    ) -> dict:
        """
        Perform token rotation with new token.

        Args:
            new_token: New API token to split into shards
            encryption_key: Optional new encryption key (generated if not provided)
            master_secret: Optional new master secret (generated if not provided)

        Returns:
            Dict with rotation status and metadata
        """
        try:
            # Generate keys if not provided
            if not encryption_key:
                from cryptography.fernet import Fernet

                encryption_key = Fernet.generate_key().decode()
                logger.info("Generated new encryption key")

            if not master_secret:
                master_secret = secrets.token_urlsafe(32)
                logger.info("Generated new master secret")

            # Calculate current time window
            now = datetime.datetime.utcnow()
            window_id = int(now.timestamp() // (self.time_window_hours * 3600))

            # Split token into shards (3/3 threshold)
            manager = ShardManager(threshold=3, total_shards=3)
            shards = manager.split_token(new_token)

            # Encrypt shards 1 and 2 with static key
            static_encryptor = EncryptionManager(encryption_key)
            shard1_encrypted = static_encryptor.encrypt(shards[0].shard_value)
            shard2_encrypted = static_encryptor.encrypt(shards[1].shard_value)

            # Derive time-based encryption key for shard 3
            time_info = f"anorak-shard3-encrypt-{window_id}".encode()
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=time_info,
            )
            time_key_bytes = hkdf.derive(master_secret.encode())
            time_encryption_key = base64.urlsafe_b64encode(time_key_bytes).decode()

            # Encrypt shard 3 with time-derived key
            time_encryptor = EncryptionManager(time_encryption_key)
            shard3_encrypted = time_encryptor.encrypt(shards[2].shard_value)

            # Store shards in Redis
            await self.redis_storage.store_shards(
                shard1_encrypted=shard1_encrypted,
                shard2_encrypted=shard2_encrypted,
                shard3_encrypted=shard3_encrypted,
                encryption_key=encryption_key,
                master_secret=master_secret,
                window_id=window_id,
                time_window_hours=self.time_window_hours,
            )

            # Clear rotation required flag
            await self.redis_storage.set_rotation_status(
                required=False, reason="Rotation completed successfully"
            )

            logger.info(
                "Token rotation completed",
                window_id=window_id,
                expires_at=datetime.datetime.utcfromtimestamp(
                    (window_id + 1) * self.time_window_hours * 3600
                ).isoformat(),
            )

            return {
                "success": True,
                "window_id": window_id,
                "expires_at": datetime.datetime.utcfromtimestamp(
                    (window_id + 1) * self.time_window_hours * 3600
                ).isoformat(),
                "time_until_expiry_hours": (
                    ((window_id + 1) * self.time_window_hours * 3600)
                    - now.timestamp()
                )
                / 3600,
            }

        except Exception as e:
            logger.error("Token rotation failed", error=str(e))
            raise

    async def get_status(self) -> dict:
        """
        Get current rotation status.

        Returns:
            Dict with rotation status, metadata, and time until expiry
        """
        metadata = await self.redis_storage.get_metadata()
        rotation_status = await self.redis_storage.get_rotation_status()

        if not metadata:
            return {
                "shards_in_redis": False,
                "rotation_required": False,
                "message": "No shards in Redis - using env vars",
            }

        now = datetime.datetime.utcnow()
        expires_at = datetime.datetime.fromisoformat(metadata["expires_at"])
        time_until_expiry = (expires_at - now).total_seconds()

        return {
            "shards_in_redis": True,
            "rotation_required": rotation_status.get("required", False),
            "rotation_reason": rotation_status.get("reason", ""),
            "current_window_id": metadata["window_id"],
            "created_at": metadata["created_at"],
            "expires_at": metadata["expires_at"],
            "time_until_expiry_seconds": max(0, time_until_expiry),
            "time_until_expiry_hours": max(0, time_until_expiry / 3600),
        }

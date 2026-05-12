"""HMAC-based handshake protocol with replay attack prevention."""

import datetime
import hashlib
import hmac
import secrets
from typing import Optional

from pydantic import BaseModel
import redis.asyncio as aioredis


class ChallengeData(BaseModel):
    """Challenge sent to client for handshake authentication."""

    challenge: str
    issued_at: datetime.datetime
    expires_at: datetime.datetime


class HandshakeManager:
    """Manages cryptographic handshakes for request authentication."""

    def __init__(
        self,
        shared_secret: str,
        timeout_seconds: int = 30,
        redis_client: Optional[aioredis.Redis] = None,
    ):
        """
        Initialize handshake manager.

        Args:
            shared_secret: Shared secret for HMAC computation
            timeout_seconds: Challenge timeout in seconds
            redis_client: Optional Redis client for replay prevention
        """
        self.shared_secret = shared_secret.encode()
        self.timeout_seconds = timeout_seconds
        self.redis_client = redis_client

    def generate_challenge(self) -> ChallengeData:
        """
        Generate a new challenge for client authentication.

        Challenge format: {timestamp}:{random_nonce}

        Returns:
            ChallengeData containing challenge string and expiry
        """
        now = datetime.datetime.utcnow()
        timestamp = int(now.timestamp())
        nonce = secrets.token_hex(16)  # 16 bytes = 32 hex chars

        challenge = f"{timestamp}:{nonce}"

        return ChallengeData(
            challenge=challenge,
            issued_at=now,
            expires_at=now + datetime.timedelta(seconds=self.timeout_seconds),
        )

    def compute_response(self, challenge: str) -> str:
        """
        Compute expected HMAC response for a challenge.

        This is what the client should compute and send back.

        Args:
            challenge: Challenge string

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        return hmac.new(
            self.shared_secret, challenge.encode(), hashlib.sha256
        ).hexdigest()

    def validate_response(self, challenge: str, response: str) -> bool:
        """
        Validate client's HMAC response to a challenge.

        Args:
            challenge: Original challenge string
            response: Client's HMAC response

        Returns:
            True if response is valid, False otherwise
        """
        expected_response = self.compute_response(challenge)
        return hmac.compare_digest(expected_response, response)

    def is_challenge_expired(self, challenge: str) -> bool:
        """
        Check if a challenge has expired based on its timestamp.

        Args:
            challenge: Challenge string (format: timestamp:nonce)

        Returns:
            True if expired, False if still valid
        """
        try:
            timestamp_str = challenge.split(":")[0]
            timestamp = int(timestamp_str)
            issued_at = datetime.datetime.utcfromtimestamp(timestamp)
            now = datetime.datetime.utcnow()
            age_seconds = (now - issued_at).total_seconds()
            return age_seconds > self.timeout_seconds
        except (ValueError, IndexError):
            # Invalid challenge format
            return True

    async def check_replay(self, challenge: str) -> bool:
        """
        Check if a challenge has already been used (replay attack).

        Args:
            challenge: Challenge string to check

        Returns:
            True if challenge was already used, False if new

        Note:
            Requires Redis client to be configured
        """
        if not self.redis_client:
            # No Redis configured - skip replay check (less secure)
            return False

        key = f"anorak:challenge:{challenge}"
        exists = await self.redis_client.exists(key)
        return bool(exists)

    async def mark_challenge_used(self, challenge: str) -> None:
        """
        Mark a challenge as used in Redis to prevent replay.

        Args:
            challenge: Challenge string to mark

        Note:
            Sets TTL to timeout + 60s buffer
        """
        if not self.redis_client:
            return

        key = f"anorak:challenge:{challenge}"
        ttl = self.timeout_seconds + 60  # Add buffer
        await self.redis_client.setex(key, ttl, "used")

    async def validate_full_handshake(
        self, challenge: str, response: str, check_replay: bool = True
    ) -> tuple[bool, Optional[str]]:
        """
        Perform full handshake validation with all checks.

        Args:
            challenge: Challenge string
            response: Client's HMAC response
            check_replay: Whether to check for replay attacks

        Returns:
            Tuple of (is_valid, error_message)
            - (True, None) if valid
            - (False, error_message) if invalid
        """
        # Check if challenge is expired
        if self.is_challenge_expired(challenge):
            return False, "Challenge expired"

        # Check for replay attack
        if check_replay:
            if await self.check_replay(challenge):
                return False, "Replay attack detected"

        # Validate HMAC response
        if not self.validate_response(challenge, response):
            return False, "Invalid HMAC response"

        # Mark challenge as used
        if check_replay:
            await self.mark_challenge_used(challenge)

        return True, None


async def create_handshake_manager(
    shared_secret: str,
    timeout_seconds: int = 30,
    redis_url: Optional[str] = None,
) -> HandshakeManager:
    """
    Factory function to create HandshakeManager with Redis connection.

    Args:
        shared_secret: Shared secret for HMAC
        timeout_seconds: Challenge timeout
        redis_url: Optional Redis URL for replay prevention

    Returns:
        Configured HandshakeManager instance
    """
    redis_client = None
    if redis_url:
        redis_client = await aioredis.from_url(redis_url, decode_responses=True)

    return HandshakeManager(
        shared_secret=shared_secret,
        timeout_seconds=timeout_seconds,
        redis_client=redis_client,
    )

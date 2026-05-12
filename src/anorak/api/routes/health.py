"""Health check and challenge endpoints."""

from fastapi import APIRouter, Query
from pydantic import BaseModel

from anorak.core.crypto.handshake import HandshakeManager
from anorak.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()

# Global handshake manager (injected at startup)
_handshake_manager: HandshakeManager = None


def set_handshake_manager(manager: HandshakeManager):
    """Set the global handshake manager."""
    global _handshake_manager
    _handshake_manager = manager


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    service: str
    version: str


class ChallengeResponse(BaseModel):
    """Challenge response for handshake."""

    challenge: str
    expires_at: str
    instructions: str


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Standard health check endpoint.

    Returns:
        Health status
    """
    return HealthResponse(status="healthy", service="anorak", version="0.1.0")


@router.get("/health/challenge", response_model=ChallengeResponse)
async def get_challenge(client_id: str = Query(..., description="Client identifier")):
    """
    Get a challenge for handshake authentication.

    Args:
        client_id: Client identifier

    Returns:
        Challenge data with expiry time
    """
    if not _handshake_manager:
        raise RuntimeError("Handshake manager not initialized")

    challenge_data = _handshake_manager.generate_challenge()

    logger.info("Challenge generated", client_id=client_id)

    return ChallengeResponse(
        challenge=challenge_data.challenge,
        expires_at=challenge_data.expires_at.isoformat(),
        instructions=(
            "Compute HMAC-SHA256(shared_secret, challenge) and include in "
            "X-Response header. Also include this challenge in X-Challenge header."
        ),
    )

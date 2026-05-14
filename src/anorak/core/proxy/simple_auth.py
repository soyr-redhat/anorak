"""Master key authentication for trusted clients like Open WebUI.

Uses double-layer Shamir crypto:
1. Internal API key (sharded in Redis, never exposed)
2. Master key derived from internal API key (distributed to clients)
3. MaaS token (sharded in Redis, used for proxying)
"""

from typing import Optional
from fastapi import Header, HTTPException
from anorak.core.crypto.master_key import validate_master_key
from anorak.utils.logger import get_logger

logger = get_logger(__name__)


async def validate_simple_auth(authorization: Optional[str] = Header(None), internal_api_key: Optional[str] = None) -> bool:
    """
    Validate master key authentication.

    The master key is derived from the internal API key using HMAC-SHA256.
    This provides double-layer security:
    - Internal API key is sharded (never exposed to clients)
    - Master key is derived cryptographically and given to trusted clients
    - MaaS token is sharded separately for proxying

    Args:
        authorization: Authorization header (Bearer <master-key>)
        internal_api_key: Reconstructed internal API key for validation

    Returns:
        True if valid

    Raises:
        HTTPException: If authentication fails
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. Use: Authorization: Bearer <master-key>",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization format. Use: Authorization: Bearer <master-key>",
        )

    if not internal_api_key:
        raise HTTPException(
            status_code=500,
            detail="Internal API key not available. Server misconfigured.",
        )

    provided_key = authorization.replace("Bearer ", "").strip()

    # Validate master key by deriving from internal API key
    if not validate_master_key(provided_key, internal_api_key):
        logger.warning("Master key validation failed")
        raise HTTPException(
            status_code=401,
            detail="Invalid master key",
        )

    logger.debug("Master key authentication successful")
    return True

"""Master key derivation for Open WebUI integration.

The internal API key is sharded and stored in Redis (never exposed).
A master key is derived from it using HMAC for distribution to trusted clients.
"""

import hashlib
import hmac
import secrets
from typing import Tuple

from anorak.utils.logger import get_logger

logger = get_logger(__name__)


def derive_master_key(internal_api_key: str, context: str = "anorak-master-key-v1") -> str:
    """
    Derive a master key from the internal API key using HMAC-SHA256.

    This creates a cryptographically secure derived key that can be distributed
    to trusted clients (like Open WebUI) without exposing the internal API key.

    Args:
        internal_api_key: The sharded internal API key
        context: Context string for key derivation (version/purpose)

    Returns:
        Hex-encoded master key
    """
    # Use HMAC-SHA256 for key derivation
    h = hmac.new(
        key=internal_api_key.encode("utf-8"),
        msg=context.encode("utf-8"),
        digestmod=hashlib.sha256,
    )
    master_key = h.hexdigest()

    logger.debug("Derived master key from internal API key")
    return master_key


def generate_internal_api_key() -> str:
    """
    Generate a cryptographically secure internal API key.

    Returns:
        Random 256-bit API key (hex-encoded)
    """
    # Generate 32 bytes (256 bits) of random data
    api_key = secrets.token_hex(32)
    logger.info("Generated new internal API key")
    return api_key


def validate_master_key(provided_key: str, internal_api_key: str, context: str = "anorak-master-key-v1") -> bool:
    """
    Validate a master key by re-deriving it from the internal API key.

    Args:
        provided_key: The master key provided by the client
        internal_api_key: The sharded internal API key
        context: Context string for key derivation (must match derive call)

    Returns:
        True if valid, False otherwise
    """
    expected_key = derive_master_key(internal_api_key, context)

    # Use constant-time comparison to prevent timing attacks
    is_valid = hmac.compare_digest(provided_key, expected_key)

    if not is_valid:
        logger.warning("Master key validation failed")

    return is_valid

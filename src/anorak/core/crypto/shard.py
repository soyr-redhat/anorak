"""Shard management using Shamir's Secret Sharing with time-derived shards."""

import datetime
import gc
import secrets
from typing import List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel
import shamirs

from anorak.core.crypto.encryption import decrypt_shard, encrypt_shard


class ShardData(BaseModel):
    """Represents a single shard of a split token."""

    shard_id: int
    shard_value: str  # Hex-encoded shard from Shamir
    created_at: datetime.datetime = datetime.datetime.utcnow()


class ShardManager:
    """Manages Shamir's Secret Sharing for API tokens with time-derived shards."""

    def __init__(self, threshold: int = 2, total_shards: int = 3):
        """
        Initialize shard manager.

        Args:
            threshold: Minimum number of shards needed to reconstruct token
            total_shards: Total number of shards to create
        """
        if threshold > total_shards:
            raise ValueError("Threshold cannot be greater than total shards")
        if threshold < 2:
            raise ValueError("Threshold must be at least 2 for security")

        self.threshold = threshold
        self.total_shards = total_shards

    def split_token(self, token: str) -> List[ShardData]:
        """
        Split token into shards using Shamir's Secret Sharing.

        Args:
            token: API token to split

        Returns:
            List of ShardData objects containing shard values
        """
        # Convert token to integer (bytes -> int)
        token_bytes = token.encode('utf-8')
        original_length = len(token_bytes)  # Store original length
        token_int = int.from_bytes(token_bytes, byteorder='big')

        # Use Shamir's Secret Sharing to split the token
        # Use a large Mersenne prime as modulus (2^19937 - 1 is a known Mersenne prime)
        # This is large enough for any realistic API token
        modulus = 2**19937 - 1

        share_objects = shamirs.shares(
            token_int, self.total_shards, modulus=modulus, threshold=self.threshold
        )

        shard_objects = []
        for idx, share_obj in enumerate(share_objects, start=1):
            # Convert share to hex string for storage
            # Share objects have index, value, and modulus attributes
            # IMPORTANT: Include original_length so we can reconstruct properly
            shard_hex = f"{share_obj.index:x}:{share_obj.value:x}:{share_obj.modulus:x}:{original_length:x}"
            shard_objects.append(ShardData(shard_id=idx, shard_value=shard_hex))

        return shard_objects

    def reconstruct_token(self, shards: List[ShardData]) -> str:
        """
        Reconstruct token from threshold number of shards.

        Args:
            shards: List of at least threshold ShardData objects

        Returns:
            Reconstructed API token

        Raises:
            ValueError: If insufficient shards provided
        """
        if len(shards) < self.threshold:
            raise ValueError(
                f"Need at least {self.threshold} shards, got {len(shards)}"
            )

        # Convert hex shards back to share objects
        # Parse "index:value:modulus:original_length" format and create share objects
        share_objects = []
        original_length = None
        modulus = None
        for shard in shards[: self.threshold]:
            parts = shard.shard_value.split(":")
            index = int(parts[0], 16)
            value = int(parts[1], 16)
            shard_modulus = int(parts[2], 16)
            if modulus is None:
                modulus = shard_modulus
            # Original length is in the 4th field (if present, for backwards compatibility)
            if len(parts) >= 4:
                original_length = int(parts[3], 16)
            # Create share object (shamirs library uses share class)
            from shamirs import share
            share_obj = share(index, value, shard_modulus)
            share_objects.append(share_obj)

        # Reconstruct using Shamir's Secret Sharing with modulus
        token_int = shamirs.interpolate(share_objects, modulus=modulus, threshold=self.threshold)

        # Convert integer back to bytes, then to string
        # Use original_length if available, otherwise calculate
        if original_length:
            byte_length = original_length
        else:
            byte_length = (token_int.bit_length() + 7) // 8

        token_bytes = token_int.to_bytes(byte_length, byteorder='big')
        token = token_bytes.decode('utf-8')

        # Remove ALL whitespace characters (newlines, spaces, tabs, etc.)
        # JWT tokens should not have any whitespace
        token = ''.join(token.split())

        return token

    def wipe_memory(self, sensitive_str: str) -> None:
        """
        Attempt to securely wipe sensitive string from memory.

        Args:
            sensitive_str: String to wipe (e.g., reconstructed token)

        Note:
            This is a best-effort approach. Python's memory management
            makes true secure wiping difficult. The string may still exist
            in memory until garbage collected.
        """
        # Overwrite the string with zeros (creates new object)
        _ = "0" * len(sensitive_str)

        # Force garbage collection
        gc.collect()


def derive_time_shard(
    master_secret: str, time_window_hours: int = 24, current_time: datetime.datetime = None
) -> str:
    """
    Derive a shard from master secret and current time window using HKDF.

    This shard changes automatically when the time window changes,
    providing implicit rotation.

    Args:
        master_secret: Master secret for derivation
        time_window_hours: Size of time window in hours (default 24 = daily rotation)
        current_time: Override current time (for testing)

    Returns:
        Hex-encoded derived shard value
    """
    # Use current time or provided time
    now = current_time or datetime.datetime.utcnow()

    # Calculate time window ID (floor division by window size)
    window_id = int(now.timestamp() // (time_window_hours * 3600))

    # Create info string that includes window ID
    info = f"anorak-shard3-{window_id}".encode()

    # Derive key material using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=None,
        info=info,
    )

    derived_bytes = hkdf.derive(master_secret.encode())

    # Convert to hex string (similar format to Shamir shards)
    return derived_bytes.hex()


class ShardStorage:
    """Manages loading and storing shards from environment/configuration."""

    def __init__(self, encryption_key: str):
        """
        Initialize shard storage.

        Args:
            encryption_key: Fernet key for encrypting/decrypting shards
        """
        self.encryption_key = encryption_key

    def load_encrypted_shard(self, encrypted_shard: str) -> str:
        """
        Load and decrypt a shard from encrypted storage.

        Args:
            encrypted_shard: Encrypted shard value (from env var)

        Returns:
            Decrypted shard value
        """
        return decrypt_shard(encrypted_shard, self.encryption_key)

    def save_shard_encrypted(self, shard: str) -> str:
        """
        Encrypt a shard for storage.

        Args:
            shard: Plain shard value

        Returns:
            Encrypted shard value (for storage in env var)
        """
        return encrypt_shard(shard, self.encryption_key)


def split_and_encrypt_token(
    token: str,
    threshold: int = 3,
    total_shards: int = 3,
) -> dict:
    """
    Split a token into shards and encrypt them.

    Args:
        token: Token to split
        threshold: Minimum shards needed for reconstruction
        total_shards: Total number of shards to create

    Returns:
        Dict with encrypted shards and keys
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    import base64
    from cryptography.fernet import Fernet

    # Split token using Shamir
    manager = ShardManager(threshold=threshold, total_shards=total_shards)
    shards = manager.split_token(token)

    # Generate encryption key for shards 1 and 2
    encryption_key = Fernet.generate_key().decode()

    # Generate master secret for shard 3
    master_secret = secrets.token_hex(32)

    # Derive time-based encryption key for shard 3
    now = datetime.datetime.utcnow()
    window_id = int(now.timestamp() // (24 * 3600))  # 24-hour window
    time_info = f"anorak-shard3-encrypt-{window_id}".encode()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=time_info,
    )
    time_key_bytes = hkdf.derive(master_secret.encode())
    time_encryption_key = base64.urlsafe_b64encode(time_key_bytes).decode()

    # Encrypt shards
    storage = ShardStorage(encryption_key)
    shard1_encrypted = storage.save_shard_encrypted(shards[0].shard_value)
    shard2_encrypted = storage.save_shard_encrypted(shards[1].shard_value)

    time_storage = ShardStorage(time_encryption_key)
    shard3_encrypted = time_storage.save_shard_encrypted(shards[2].shard_value)

    return {
        "shard1_encrypted": shard1_encrypted,
        "shard2_encrypted": shard2_encrypted,
        "shard3_encrypted": shard3_encrypted,
        "encryption_key": encryption_key,
        "master_secret": master_secret,
    }


def reconstruct_token_from_env(
    shard1_encrypted: str,
    shard2_encrypted: str,
    shard3_encrypted: str,
    shard3_master_secret: str,
    encryption_key: str,
    time_window_hours: int = 24,
    threshold: int = 3,
    total_shards: int = 3,
) -> str:
    """
    Convenience function to reconstruct token from environment variables.

    Args:
        shard1_encrypted: Encrypted shard 1 (from env)
        shard2_encrypted: Encrypted shard 2 (from env)
        shard3_encrypted: Encrypted shard 3 (from env) - encrypted with time-derived key
        shard3_master_secret: Master secret for deriving shard 3 encryption key
        encryption_key: Fernet key for shards 1 and 2
        time_window_hours: Time window for shard 3 encryption key
        threshold: Shamir threshold (default 3/3)
        total_shards: Total Shamir shards

    Returns:
        Reconstructed API token

    Raises:
        Exception: If shard 3 can't be decrypted (time window expired)
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    import base64

    # Decrypt static shards (1 and 2)
    storage = ShardStorage(encryption_key)
    shard1 = storage.load_encrypted_shard(shard1_encrypted)
    shard2 = storage.load_encrypted_shard(shard2_encrypted)

    # Derive time-based encryption key for shard 3
    now = datetime.datetime.utcnow()
    window_id = int(now.timestamp() // (time_window_hours * 3600))
    time_info = f"anorak-shard3-encrypt-{window_id}".encode()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=time_info,
    )
    time_key_bytes = hkdf.derive(shard3_master_secret.encode())
    time_encryption_key = base64.urlsafe_b64encode(time_key_bytes).decode()

    # Decrypt shard 3 with time-derived key
    try:
        time_storage = ShardStorage(time_encryption_key)
        shard3 = time_storage.load_encrypted_shard(shard3_encrypted)
    except Exception as e:
        raise Exception(
            f"Failed to decrypt shard 3 - time window may have expired. "
            f"Current window: {window_id}. Error: {e}"
        )

    # Create ShardData objects
    shards = [
        ShardData(shard_id=1, shard_value=shard1),
        ShardData(shard_id=2, shard_value=shard2),
        ShardData(shard_id=3, shard_value=shard3),
    ]

    # Reconstruct token (need all 3 shards with threshold 3/3)
    manager = ShardManager(threshold=threshold, total_shards=total_shards)
    token = manager.reconstruct_token(shards)

    return token

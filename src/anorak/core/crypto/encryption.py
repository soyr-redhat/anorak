"""Encryption utilities for shard storage using Fernet symmetric encryption."""

from cryptography.fernet import Fernet


class EncryptionManager:
    """Manages encryption and decryption of shards at rest using Fernet."""

    def __init__(self, encryption_key: str):
        """
        Initialize encryption manager with Fernet key.

        Args:
            encryption_key: Base64-encoded Fernet key
        """
        self.fernet = Fernet(encryption_key.encode())

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using Fernet.

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        encrypted_bytes = self.fernet.encrypt(plaintext.encode())
        return encrypted_bytes.decode()

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using Fernet.

        Args:
            ciphertext: Base64-encoded encrypted string

        Returns:
            Decrypted plaintext string
        """
        decrypted_bytes = self.fernet.decrypt(ciphertext.encode())
        return decrypted_bytes.decode()

    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet encryption key.

        Returns:
            Base64-encoded Fernet key as string
        """
        return Fernet.generate_key().decode()


def encrypt_shard(shard: str, encryption_key: str) -> str:
    """
    Helper function to encrypt a single shard.

    Args:
        shard: Shard data to encrypt
        encryption_key: Fernet key

    Returns:
        Encrypted shard string
    """
    manager = EncryptionManager(encryption_key)
    return manager.encrypt(shard)


def decrypt_shard(encrypted_shard: str, encryption_key: str) -> str:
    """
    Helper function to decrypt a single shard.

    Args:
        encrypted_shard: Encrypted shard data
        encryption_key: Fernet key

    Returns:
        Decrypted shard string
    """
    manager = EncryptionManager(encryption_key)
    return manager.decrypt(encrypted_shard)

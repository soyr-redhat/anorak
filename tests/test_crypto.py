"""Tests for cryptographic functions."""

import datetime

import pytest

from anorak.core.crypto.encryption import EncryptionManager, decrypt_shard, encrypt_shard
from anorak.core.crypto.shard import ShardManager, derive_time_shard


class TestEncryption:
    """Test encryption utilities."""

    def test_generate_key(self):
        """Test Fernet key generation."""
        key = EncryptionManager.generate_key()
        assert isinstance(key, str)
        assert len(key) > 0

    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        key = EncryptionManager.generate_key()
        manager = EncryptionManager(key)

        plaintext = "test-shard-value-123"
        ciphertext = manager.encrypt(plaintext)

        assert ciphertext != plaintext
        assert manager.decrypt(ciphertext) == plaintext

    def test_encrypt_decrypt_helpers(self):
        """Test helper functions for shard encryption."""
        key = EncryptionManager.generate_key()
        shard = "shard-value-abc"

        encrypted = encrypt_shard(shard, key)
        decrypted = decrypt_shard(encrypted, key)

        assert decrypted == shard


class TestShardManager:
    """Test shard manager functionality."""

    def test_split_and_reconstruct(self):
        """Test splitting and reconstructing a token."""
        token = "sk-1234567890abcdef"
        manager = ShardManager(threshold=2, total_shards=3)

        shards = manager.split_token(token)

        assert len(shards) == 3
        for shard in shards:
            assert shard.shard_id in [1, 2, 3]
            assert shard.shard_value is not None

        # Reconstruct with threshold shards
        reconstructed = manager.reconstruct_token(shards[:2])
        assert reconstructed == token

        # Also works with different combinations
        reconstructed2 = manager.reconstruct_token([shards[0], shards[2]])
        assert reconstructed2 == token

    def test_insufficient_shards(self):
        """Test that reconstruction fails with insufficient shards."""
        token = "sk-test-token"
        manager = ShardManager(threshold=2, total_shards=3)

        shards = manager.split_token(token)

        with pytest.raises(ValueError, match="at least 2 shards"):
            manager.reconstruct_token([shards[0]])

    def test_invalid_threshold(self):
        """Test that invalid threshold raises error."""
        with pytest.raises(ValueError, match="Threshold cannot be greater"):
            ShardManager(threshold=4, total_shards=3)

        with pytest.raises(ValueError, match="at least 2"):
            ShardManager(threshold=1, total_shards=3)


class TestTimeDerivedShard:
    """Test time-derived shard functionality."""

    def test_derive_time_shard(self):
        """Test deriving a shard from master secret and time."""
        master_secret = "test-master-secret-123"
        shard = derive_time_shard(master_secret, time_window_hours=24)

        assert isinstance(shard, str)
        assert len(shard) > 0
        # Should be hex string
        int(shard, 16)  # Will raise if not hex

    def test_same_time_window_produces_same_shard(self):
        """Test that same time window produces same shard."""
        master_secret = "test-master-secret"
        now = datetime.datetime(2024, 5, 7, 12, 0, 0)

        shard1 = derive_time_shard(master_secret, 24, now)
        # 1 hour later (same window)
        shard2 = derive_time_shard(
            master_secret, 24, now + datetime.timedelta(hours=1)
        )

        assert shard1 == shard2

    def test_different_time_window_produces_different_shard(self):
        """Test that different time window produces different shard."""
        master_secret = "test-master-secret"
        now = datetime.datetime(2024, 5, 7, 12, 0, 0)

        shard1 = derive_time_shard(master_secret, 24, now)
        # 25 hours later (different window)
        shard2 = derive_time_shard(
            master_secret, 24, now + datetime.timedelta(hours=25)
        )

        assert shard1 != shard2

    def test_different_master_secret_produces_different_shard(self):
        """Test that different master secret produces different shard."""
        now = datetime.datetime(2024, 5, 7, 12, 0, 0)

        shard1 = derive_time_shard("secret1", 24, now)
        shard2 = derive_time_shard("secret2", 24, now)

        assert shard1 != shard2


class TestIntegration:
    """Integration tests for full workflow."""

    def test_full_shard_workflow(self):
        """Test complete workflow: split, encrypt, decrypt, reconstruct."""
        # Original token
        token = "sk-original-token-12345"

        # Generate encryption key
        encryption_key = EncryptionManager.generate_key()

        # Split token
        manager = ShardManager(threshold=2, total_shards=3)
        shards = manager.split_token(token)

        # Encrypt shards
        encrypted_shards = [
            encrypt_shard(shard.shard_value, encryption_key) for shard in shards
        ]

        # Simulate storage/retrieval
        # Decrypt shards
        decrypted_shards = [
            decrypt_shard(enc_shard, encryption_key) for enc_shard in encrypted_shards
        ]

        # Reconstruct shards objects
        from anorak.core.crypto.shard import ShardData

        reconstructed_shards = [
            ShardData(shard_id=i + 1, shard_value=dec_shard)
            for i, dec_shard in enumerate(decrypted_shards)
        ]

        # Reconstruct token
        final_token = manager.reconstruct_token(reconstructed_shards[:2])

        assert final_token == token

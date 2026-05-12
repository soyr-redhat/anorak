#!/usr/bin/env python3
"""Test loading shards from Redis and reconstructing token."""

import sys
from pathlib import Path
import asyncio

sys.path.insert(0, str(Path(__file__).parent / "src"))

import redis.asyncio as aioredis
from anorak.core.crypto.redis_storage import RedisShardStorage
from anorak.core.crypto.shard import reconstruct_token_from_env
from dotenv import load_dotenv
import os

load_dotenv()

async def main():
    print("🔍 Testing Redis Shard Loading\n")

    # Connect to Redis
    redis_client = await aioredis.from_url(
        "redis://localhost:6379/0", decode_responses=True, encoding="utf-8"
    )

    storage = RedisShardStorage(redis_client)

    # Load shards
    print("Loading shards from Redis...")
    shard_data = await storage.load_shards()

    if not shard_data:
        print("❌ No shards in Redis")
        await redis_client.close()
        return

    print(f"✅ Loaded shards from Redis")
    print(f"   Shard 1 length: {len(shard_data['shard1_encrypted'])}")
    print(f"   Shard 2 length: {len(shard_data['shard2_encrypted'])}")
    print(f"   Shard 3 length: {len(shard_data['shard3_encrypted'])}")
    print(f"   Encryption key length: {len(shard_data['encryption_key'])}")
    print(f"   Master secret length: {len(shard_data['master_secret'])}")

    print(f"\n   Shard 1 prefix: {shard_data['shard1_encrypted'][:50]}")
    print(f"   Shard 2 prefix: {shard_data['shard2_encrypted'][:50]}")
    print(f"   Shard 3 prefix: {shard_data['shard3_encrypted'][:50]}")

    # Try decrypting shards first
    print("\nDecrypting shards...")
    try:
        from anorak.core.crypto.encryption import EncryptionManager
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        import base64
        import datetime

        # Decrypt shards 1 and 2 with static key
        static_encryptor = EncryptionManager(shard_data["encryption_key"])
        shard1_decrypted = static_encryptor.decrypt(shard_data["shard1_encrypted"])
        shard2_decrypted = static_encryptor.decrypt(shard_data["shard2_encrypted"])
        print(f"✅ Decrypted shard 1: {shard1_decrypted[:60]}")
        print(f"✅ Decrypted shard 2: {shard2_decrypted[:60]}")

        # Derive time-based key for shard 3
        now = datetime.datetime.utcnow()
        window_id = int(now.timestamp() // (24 * 3600))
        time_info = f"anorak-shard3-encrypt-{window_id}".encode()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=time_info,
        )
        time_key_bytes = hkdf.derive(shard_data["master_secret"].encode())
        time_encryption_key = base64.urlsafe_b64encode(time_key_bytes).decode()

        time_encryptor = EncryptionManager(time_encryption_key)
        shard3_decrypted = time_encryptor.decrypt(shard_data["shard3_encrypted"])
        print(f"✅ Decrypted shard 3: {shard3_decrypted[:60]}")

    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        import traceback
        traceback.print_exc()

    # Try reconstruction
    print("\nAttempting token reconstruction...")
    try:
        token = reconstruct_token_from_env(
            shard1_encrypted=shard_data["shard1_encrypted"],
            shard2_encrypted=shard_data["shard2_encrypted"],
            shard3_encrypted=shard_data["shard3_encrypted"],
            shard3_master_secret=shard_data["master_secret"],
            encryption_key=shard_data["encryption_key"],
            time_window_hours=24,
            threshold=3,
            total_shards=3,
        )
        print(f"✅ Token reconstructed!")
        print(f"   Length: {len(token)}")
        print(f"   Starts with: {token[:50]}")
    except Exception as e:
        print(f"❌ Failed to reconstruct: {e}")
        import traceback
        traceback.print_exc()

    await redis_client.close()

if __name__ == "__main__":
    asyncio.run(main())

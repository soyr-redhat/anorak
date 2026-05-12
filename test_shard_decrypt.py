#!/usr/bin/env python3
"""Debug shard decryption."""

import sys
from pathlib import Path
import datetime
import base64

sys.path.insert(0, str(Path(__file__).parent / "src"))

from anorak.core.crypto.encryption import EncryptionManager
from anorak.core.crypto.shard import ShardManager, ShardData
from dotenv import load_dotenv
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Load environment
load_dotenv()

SHARD_1_ENCRYPTED = os.getenv("SHARD_1_ENCRYPTED")
SHARD_2_ENCRYPTED = os.getenv("SHARD_2_ENCRYPTED")
SHARD_3_ENCRYPTED = os.getenv("SHARD_3_ENCRYPTED")
ENCRYPTION_KEY = os.getenv("SHARD_ENCRYPTION_KEY")
MASTER_SECRET = os.getenv("SHARD_3_MASTER_SECRET")

print("🔍 Debugging Shard Decryption\n")

# Test 1: Decrypt shards 1 and 2
print("=" * 80)
print("Test 1: Decrypt shards 1 and 2 with static key")
print("-" * 80)

try:
    static_encryptor = EncryptionManager(ENCRYPTION_KEY)
    shard1 = static_encryptor.decrypt(SHARD_1_ENCRYPTED)
    print(f"✅ Shard 1 decrypted: {shard1[:50]}...")

    shard2 = static_encryptor.decrypt(SHARD_2_ENCRYPTED)
    print(f"✅ Shard 2 decrypted: {shard2[:50]}...")
except Exception as e:
    print(f"❌ Failed to decrypt shards 1/2: {e}")

# Test 2: Derive time-based encryption key for shard 3
print("\n" + "=" * 80)
print("Test 2: Derive time-based encryption key for shard 3")
print("-" * 80)

now = datetime.datetime.utcnow()
time_window_hours = 24
window_id = int(now.timestamp() // (time_window_hours * 3600))
time_info = f"anorak-shard3-encrypt-{window_id}".encode()

print(f"Current time: {now}")
print(f"Window ID: {window_id}")
print(f"Time info: {time_info}")

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=time_info,
    backend=default_backend()
)
time_key_bytes = hkdf.derive(MASTER_SECRET.encode())
time_encryption_key = base64.urlsafe_b64encode(time_key_bytes).decode()

print(f"✅ Time-derived key: {time_encryption_key[:32]}...")

# Test 3: Decrypt shard 3
print("\n" + "=" * 80)
print("Test 3: Decrypt shard 3 with time-derived key")
print("-" * 80)

try:
    time_encryptor = EncryptionManager(time_encryption_key)
    shard3 = time_encryptor.decrypt(SHARD_3_ENCRYPTED)
    print(f"✅ Shard 3 decrypted: {shard3[:50]}...")
except Exception as e:
    print(f"❌ Failed to decrypt shard 3: {e}")
    sys.exit(1)

# Test 4: Reconstruct token
print("\n" + "=" * 80)
print("Test 4: Reconstruct token from 3 shards")
print("-" * 80)

shards = [
    ShardData(shard_id=1, shard_value=shard1),
    ShardData(shard_id=2, shard_value=shard2),
    ShardData(shard_id=3, shard_value=shard3),
]

try:
    manager = ShardManager(threshold=3, total_shards=3)
    token = manager.reconstruct_token(shards)
    print(f"✅ Token reconstructed!")
    print(f"   Length: {len(token)} bytes")
    print(f"   Prefix: {token[:50]}...")

    if token.startswith("eyJ"):
        print(f"\n✅ Token is a valid JWT!")
    else:
        print(f"\n⚠️  Warning: Token doesn't look like a JWT")

    # Output token to file for rotation
    with open("/tmp/reconstructed_token.txt", "w") as f:
        f.write(token)
    print(f"\n💾 Token saved to /tmp/reconstructed_token.txt")

except Exception as e:
    print(f"❌ Failed to reconstruct token: {e}")
    import traceback
    traceback.print_exc()

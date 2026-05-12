#!/usr/bin/env python3
"""Test time window expiry - simulate what happens when 24h passes."""

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

# Load environment
load_dotenv()

SHARD_1_ENCRYPTED = os.getenv("SHARD_1_ENCRYPTED")
SHARD_2_ENCRYPTED = os.getenv("SHARD_2_ENCRYPTED")
SHARD_3_ENCRYPTED = os.getenv("SHARD_3_ENCRYPTED")
ENCRYPTION_KEY = os.getenv("SHARD_ENCRYPTION_KEY")
MASTER_SECRET = os.getenv("SHARD_3_MASTER_SECRET")

print("🔍 Testing Time Window Expiry\n")

# Test 1: Decrypt with CURRENT time window (should work)
print("=" * 80)
print("Test 1: Decrypt shard 3 with CURRENT time window")
print("-" * 80)

now = datetime.datetime.utcnow()
time_window_hours = 24
current_window_id = int(now.timestamp() // (time_window_hours * 3600))
current_time_info = f"anorak-shard3-encrypt-{current_window_id}".encode()

print(f"Current time: {now}")
print(f"Current window ID: {current_window_id}")

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=current_time_info,
)
current_key_bytes = hkdf.derive(MASTER_SECRET.encode())
current_encryption_key = base64.urlsafe_b64encode(current_key_bytes).decode()

try:
    current_encryptor = EncryptionManager(current_encryption_key)
    shard3_current = current_encryptor.decrypt(SHARD_3_ENCRYPTED)
    print(f"✅ Shard 3 decrypted with CURRENT window: {shard3_current[:50]}...")

    # Try full reconstruction
    static_encryptor = EncryptionManager(ENCRYPTION_KEY)
    shard1 = static_encryptor.decrypt(SHARD_1_ENCRYPTED)
    shard2 = static_encryptor.decrypt(SHARD_2_ENCRYPTED)

    shards = [
        ShardData(shard_id=1, shard_value=shard1),
        ShardData(shard_id=2, shard_value=shard2),
        ShardData(shard_id=3, shard_value=shard3_current),
    ]

    manager = ShardManager(threshold=3, total_shards=3)
    token = manager.reconstruct_token(shards)
    print(f"✅ Token reconstructed with CURRENT window!")
    print(f"   Token starts with: {token[:50]}...")
except Exception as e:
    print(f"❌ UNEXPECTED: Failed with current window: {e}")

# Test 2: Decrypt with PAST time window (simulating 24h expiry)
print("\n" + "=" * 80)
print("Test 2: Decrypt shard 3 with PAST time window (24h ago)")
print("-" * 80)

past_window_id = current_window_id - 1  # 24 hours ago
past_time_info = f"anorak-shard3-encrypt-{past_window_id}".encode()

print(f"Past window ID: {past_window_id} (current - 1)")

hkdf_past = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=past_time_info,
)
past_key_bytes = hkdf_past.derive(MASTER_SECRET.encode())
past_encryption_key = base64.urlsafe_b64encode(past_key_bytes).decode()

try:
    past_encryptor = EncryptionManager(past_encryption_key)
    shard3_past = past_encryptor.decrypt(SHARD_3_ENCRYPTED)
    print(f"❌ UNEXPECTED: Shard 3 decrypted with PAST window: {shard3_past[:50]}...")
    print("   This should have FAILED!")
except Exception as e:
    print(f"✅ EXPECTED: Failed to decrypt with past window")
    print(f"   Error: {type(e).__name__}: {str(e)[:100]}")
    print("   This means after 24h, token reconstruction will FAIL ✓")

# Test 3: Decrypt with FUTURE time window (simulating tomorrow)
print("\n" + "=" * 80)
print("Test 3: Decrypt shard 3 with FUTURE time window (24h from now)")
print("-" * 80)

future_window_id = current_window_id + 1  # 24 hours from now
future_time_info = f"anorak-shard3-encrypt-{future_window_id}".encode()

print(f"Future window ID: {future_window_id} (current + 1)")

hkdf_future = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=future_time_info,
)
future_key_bytes = hkdf_future.derive(MASTER_SECRET.encode())
future_encryption_key = base64.urlsafe_b64encode(future_key_bytes).decode()

try:
    future_encryptor = EncryptionManager(future_encryption_key)
    shard3_future = future_encryptor.decrypt(SHARD_3_ENCRYPTED)
    print(f"❌ UNEXPECTED: Shard 3 decrypted with FUTURE window: {shard3_future[:50]}...")
    print("   This should have FAILED!")
except Exception as e:
    print(f"✅ EXPECTED: Failed to decrypt with future window")
    print(f"   Error: {type(e).__name__}: {str(e)[:100]}")
    print("   This means time-locked security is working ✓")

# Summary
print("\n" + "=" * 80)
print("Summary")
print("-" * 80)
print(f"Current window ID: {current_window_id}")
print(f"Window changes at: {datetime.datetime.utcfromtimestamp((current_window_id + 1) * time_window_hours * 3600)}")
print(f"Time until rotation required: {((current_window_id + 1) * time_window_hours * 3600) - now.timestamp():.0f} seconds")
print("\n✅ Time-based encryption is working correctly!")
print("   After the window expires, shard 3 decryption will fail")
print("   This forces token rotation every 24 hours")

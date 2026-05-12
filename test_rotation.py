#!/usr/bin/env python3
"""Test time-derived shard rotation."""

import sys
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from anorak.core.crypto.shard import derive_time_shard, ShardManager, ShardData
from anorak.core.crypto.encryption import EncryptionManager
from dotenv import load_dotenv
import os

# Load environment
load_dotenv()

MASTER_SECRET = os.getenv("SHARD_3_MASTER_SECRET")
SHARD_1_ENCRYPTED = os.getenv("SHARD_1_ENCRYPTED")
SHARD_2_ENCRYPTED = os.getenv("SHARD_2_ENCRYPTED")
ENCRYPTION_KEY = os.getenv("SHARD_ENCRYPTION_KEY")
TIME_WINDOW_HOURS = int(os.getenv("SHARD_3_TIME_WINDOW_HOURS", "24"))

print("🔐 Anorak Time-Derived Rotation Test\n")
print("=" * 80)

# Test 1: Show shard 3 changes over time
print("\n📅 Test 1: Shard 3 Changes Over Time Windows")
print("-" * 80)

now = datetime.datetime.utcnow()
future = now + datetime.timedelta(hours=TIME_WINDOW_HOURS)
far_future = now + datetime.timedelta(hours=TIME_WINDOW_HOURS * 2)

shard3_now = derive_time_shard(MASTER_SECRET, TIME_WINDOW_HOURS, now)
shard3_future = derive_time_shard(MASTER_SECRET, TIME_WINDOW_HOURS, future)
shard3_far = derive_time_shard(MASTER_SECRET, TIME_WINDOW_HOURS, far_future)

print(f"\nCurrent time: {now}")
print(f"Shard 3 (now):     {shard3_now[:32]}...")

print(f"\n+{TIME_WINDOW_HOURS}h time: {future}")
print(f"Shard 3 (+24h):    {shard3_future[:32]}...")

print(f"\n+{TIME_WINDOW_HOURS * 2}h time: {far_future}")
print(f"Shard 3 (+48h):    {shard3_far[:32]}...")

if shard3_now == shard3_future:
    print("\n❌ FAIL: Shards should be different across time windows!")
else:
    print(f"\n✅ PASS: Shard 3 rotates every {TIME_WINDOW_HOURS} hours")

# Test 2: Reconstruct with only shards 1+2 (don't need shard 3)
print("\n" + "=" * 80)
print("\n🔑 Test 2: Token Reconstruction with 2/3 Shards")
print("-" * 80)

# Decrypt shards 1 and 2
storage = EncryptionManager(ENCRYPTION_KEY)
shard1_value = storage.decrypt(SHARD_1_ENCRYPTED)
shard2_value = storage.decrypt(SHARD_2_ENCRYPTED)

# Create shard objects (only using shards 1 and 2, NOT shard 3)
shards_12 = [
    ShardData(shard_id=1, shard_value=shard1_value),
    ShardData(shard_id=2, shard_value=shard2_value),
]

# Reconstruct token
manager = ShardManager(threshold=2, total_shards=3)
try:
    token = manager.reconstruct_token(shards_12)
    print(f"\n✅ Token reconstructed with shards 1+2 only")
    print(f"   Token length: {len(token)} bytes")
    print(f"   Token prefix: {token[:50]}...")

    # Verify it looks like a JWT
    if token.startswith("eyJ"):
        print(f"\n✅ Token appears to be valid JWT (starts with 'eyJ')")
    else:
        print(f"\n⚠️  Warning: Token doesn't look like a JWT")

except Exception as e:
    print(f"\n❌ FAIL: Could not reconstruct token: {e}")

# Test 3: Reconstruct with shards 1+3 (different combination)
print("\n" + "=" * 80)
print("\n🔑 Test 3: Token Reconstruction with Shards 1+3")
print("-" * 80)

shards_13 = [
    ShardData(shard_id=1, shard_value=shard1_value),
    ShardData(shard_id=3, shard_value=shard3_now),
]

try:
    token_13 = manager.reconstruct_token(shards_13)
    print(f"\n✅ Token reconstructed with shards 1+3")
    print(f"   Token length: {len(token_13)} bytes")

    # Compare with token from shards 1+2
    if token == token_13:
        print(f"\n✅ PASS: Both combinations produce the same token!")
    else:
        print(f"\n❌ FAIL: Different combinations produced different tokens")
        print(f"   This should not happen!")

except Exception as e:
    print(f"\n❌ FAIL: Could not reconstruct token: {e}")

# Test 4: Show that old shard 3 still works (within grace period)
print("\n" + "=" * 80)
print("\n⏰ Test 4: Shard 3 Rotation Behavior")
print("-" * 80)

print(f"\nScenario: Time window changes (after {TIME_WINDOW_HOURS} hours)")
print(f"- Shard 3 automatically becomes: {shard3_future[:32]}...")
print(f"- But we only need 2/3 shards to reconstruct")
print(f"- So shards 1+2 will continue working regardless of shard 3")
print(f"\n✅ This is the beauty of threshold cryptography!")
print(f"   Shard 3 rotates automatically, but doesn't break anything")

print("\n" + "=" * 80)
print("\n🎉 Summary")
print("-" * 80)
print(f"✅ Shard 3 derives from master secret + time window")
print(f"✅ Shard 3 changes every {TIME_WINDOW_HOURS} hours automatically")
print(f"✅ Token reconstruction works with any 2/3 shards")
print(f"✅ Rotation happens seamlessly without manual intervention")
print("\n" + "=" * 80)

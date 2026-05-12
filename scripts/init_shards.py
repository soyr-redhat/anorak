#!/usr/bin/env python3
"""Initialize shards from an API token.

This script splits an API token into encrypted shards for use with Anorak.

Usage:
    python scripts/init_shards.py --token "sk-your-token-here"

    # Or read from stdin
    echo "sk-your-token" | python scripts/init_shards.py

Output:
    - Encrypted shards for SHARD_1 and SHARD_2
    - Encryption key for SHARD_ENCRYPTION_KEY
    - Master secret for SHARD_3_MASTER_SECRET
    - Example .env configuration
"""

import argparse
import secrets
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from anorak.core.crypto.encryption import EncryptionManager
from anorak.core.crypto.shard import ShardManager


def generate_master_secret() -> str:
    """Generate a random master secret for time-derived shard."""
    return secrets.token_hex(32)  # 32 bytes = 64 hex chars


def main():
    """Main function to initialize shards."""
    parser = argparse.ArgumentParser(
        description="Initialize encrypted shards from API token"
    )
    parser.add_argument(
        "--token",
        type=str,
        help="API token to split (or read from stdin if not provided)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=2,
        help="Minimum shards required (default: 2)",
    )
    parser.add_argument(
        "--total",
        type=int,
        default=3,
        help="Total number of shards (default: 3)",
    )

    args = parser.parse_args()

    # Get token
    if args.token:
        token = args.token
    else:
        print("Reading token from stdin...", file=sys.stderr)
        token = sys.stdin.read().strip()

    if not token:
        print("Error: No token provided", file=sys.stderr)
        sys.exit(1)

    print(f"\nInitializing {args.total} shards (threshold: {args.threshold})...\n")

    # Generate static encryption key (for shards 1 and 2)
    static_encryption_key = EncryptionManager.generate_key()
    print("Generated static encryption key (for shards 1 and 2)")

    # Generate master secret for time-derived encryption (for shard 3)
    master_secret = generate_master_secret()
    print("Generated master secret for time-derived encryption (for shard 3)")

    # Split token into shards (threshold 3/3 - need ALL shards)
    manager = ShardManager(threshold=3, total_shards=3)
    shards = manager.split_token(token)
    print(f"Split token into {len(shards)} shards (threshold: 3/3)\n")

    # Encrypt shards 1 and 2 with static key
    static_encryptor = EncryptionManager(static_encryption_key)
    shard1_encrypted = static_encryptor.encrypt(shards[0].shard_value)
    shard2_encrypted = static_encryptor.encrypt(shards[1].shard_value)
    print("Encrypted shards 1 and 2 with static key")

    # Derive time-based encryption key for shard 3
    from anorak.core.crypto.shard import derive_time_shard
    import datetime

    # Use current time to derive encryption key for shard 3
    now = datetime.datetime.utcnow()
    window_id = int(now.timestamp() // (24 * 3600))  # 24-hour window
    time_info = f"anorak-shard3-encrypt-{window_id}".encode()

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=time_info,
        backend=default_backend()
    )
    time_key_bytes = hkdf.derive(master_secret.encode())

    # Convert to Fernet-compatible key (base64 encoded)
    import base64
    time_encryption_key = base64.urlsafe_b64encode(time_key_bytes).decode()

    # Encrypt shard 3 with time-derived key
    time_encryptor = EncryptionManager(time_encryption_key)
    shard3_encrypted = time_encryptor.encrypt(shards[2].shard_value)
    print(f"Encrypted shard 3 with time-derived key (window: {window_id})\n")

    # Output configuration
    print("=" * 80)
    print("Anorak Shard Configuration (Threshold 3/3)")
    print("=" * 80)
    print("\nAdd these to your .env file:\n")

    print(f"SHARD_1_ENCRYPTED={shard1_encrypted}")
    print(f"SHARD_2_ENCRYPTED={shard2_encrypted}")
    print(f"SHARD_3_ENCRYPTED={shard3_encrypted}")
    print(f"SHARD_ENCRYPTION_KEY={static_encryption_key}")
    print(f"SHARD_3_MASTER_SECRET={master_secret}")

    print("\n" + "=" * 80)
    print("\n⚠️  IMPORTANT: Threshold is 3/3 - ALL shards required!")
    print(f"   Shard 3 encryption key rotates every 24 hours.")
    print(f"   After rotation, you MUST re-run this script to generate new shards.")
    print(f"   Current time window: {window_id}")
    print("\nKeep these values secure and never commit them to version control!")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()

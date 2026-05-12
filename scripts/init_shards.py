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

    # Generate encryption key
    encryption_key = EncryptionManager.generate_key()
    print("Generated encryption key")

    # Generate master secret for time-derived shard
    master_secret = generate_master_secret()
    print("Generated master secret for time-derived shard")

    # Split token into shards
    manager = ShardManager(threshold=args.threshold, total_shards=args.total)
    shards = manager.split_token(token)
    print(f"Split token into {len(shards)} shards")

    # Encrypt shards
    encryptor = EncryptionManager(encryption_key)
    encrypted_shards = []
    for shard in shards:
        encrypted = encryptor.encrypt(shard.shard_value)
        encrypted_shards.append(encrypted)

    print("Encrypted shards\n")

    # Output configuration
    print("=" * 80)
    print("Anorak Shard Configuration")
    print("=" * 80)
    print("\nAdd these to your .env file:\n")

    print(f"SHARD_1_ENCRYPTED={encrypted_shards[0]}")
    print(f"SHARD_2_ENCRYPTED={encrypted_shards[1]}")
    print(f"SHARD_ENCRYPTION_KEY={encryption_key}")
    print(f"SHARD_3_MASTER_SECRET={master_secret}")

    print("\n" + "=" * 80)
    print("\nShard 3 is time-derived and rotates automatically every 24 hours.")
    print("Keep these values secure and never commit them to version control!")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()

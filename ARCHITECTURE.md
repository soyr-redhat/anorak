# Anorak Architecture - Double-Layer Shamir Crypto

## Overview

Anorak uses a **double-layer Shamir Secret Sharing** design for maximum security:

1. **Internal API Key** - Sharded and stored in Redis, never exposed
2. **Master Key** - Derived from internal API key using HMAC-SHA256, distributed to trusted clients
3. **MaaS Token** - Sharded and stored in Redis, used for proxying to upstream API

## Security Model

### Layer 1: Internal API Key (Never Exposed)
- Generated once using cryptographically secure random number generator
- Split into 3 shards using Shamir's Secret Sharing (3/3 threshold)
- Each shard encrypted with Fernet
- Stored in Redis (never in environment variables or config files)
- Reconstructed in memory only when needed for master key validation

### Layer 2: Master Key (Distributed to Clients)
- Derived from internal API key using HMAC-SHA256 with context string
- Cryptographically linked to internal API key but cannot be reversed
- Given to trusted clients (like Open WebUI) as Bearer token
- Validated on each request by re-deriving from internal API key

### Layer 3: MaaS Token (For Proxying)
- Also split into 3 shards using Shamir's Secret Sharing (3/3 threshold)
- Encrypted and stored in Redis
- Reconstructed in memory only for proxying requests to upstream API
- Wiped from memory after each request

## Why This Design?

### Problem with Previous Design
The original design had a single Bearer token (ADMIN_API_KEY) stored in plaintext environment variables. This was the weakest link - if an attacker compromised the container, they got full access.

### Solution: Double-Layer Crypto
1. **No static Bearer tokens** - The master key is derived, not stored
2. **Internal key never leaves Redis** - Even with container access, attacker needs Redis
3. **Separate secrets** - Compromising one doesn't compromise the other
4. **Master key can be rotated** - Just regenerate internal API key and distribute new master key

## Request Flow

### Initialization (POST /admin/init)
```
1. Generate random internal API key (256-bit)
2. Shard internal API key → Store in Redis
3. Take MaaS token from request
4. Shard MaaS token → Store in Redis
5. Derive master key from internal API key
6. Return master key to admin
7. Admin distributes master key to Open WebUI
```

### Request Validation
```
1. Open WebUI sends: Authorization: Bearer <master-key>
2. Anorak reconstructs internal API key from Redis shards
3. Derives expected master key from internal API key
4. Compares provided master key vs. expected (constant-time)
5. If valid, reconstructs MaaS token from Redis shards
6. Proxies request with MaaS token
7. Wipes both keys from memory
```

## Key Components

### `src/anorak/core/crypto/master_key.py`
- `generate_internal_api_key()` - Generate 256-bit random key
- `derive_master_key(internal_key)` - HMAC-SHA256 derivation
- `validate_master_key(provided, internal)` - Constant-time comparison

### `src/anorak/core/crypto/redis_storage.py`
- `store_internal_key_shards()` - Store internal API key shards
- `load_internal_key_shards()` - Load internal API key shards
- `store_maas_token_shards()` - Store MaaS token shards
- `load_maas_token_shards()` - Load MaaS token shards

### `src/anorak/core/proxy/middleware.py`
- `reconstruct_internal_api_key()` - Reconstruct from Redis (cached)
- `reconstruct_maas_token()` - Reconstruct from Redis (cached)
- Dual authentication: Master key OR HMAC handshake

### `src/anorak/api/routes/admin.py`
- `POST /admin/init` - Initialize system with MaaS token
- `GET /admin/master-key` - Retrieve master key (requires admin auth)

## Removed Complexity

### What Was Removed
- **Rotation Engine** (`src/anorak/core/rotation/`) - Deleted entirely
- **Time-based rotation** - MaaS tokens are static anyway
- **Request-count rotation** - Added complexity without security benefit
- **Rotation status endpoints** - No longer needed
- **ROTATION_ENABLED setting** - Removed from config

### Why Rotation Was Removed
1. MaaS tokens don't actually rotate (they're long-lived JWTs)
2. Rotation added 10-30 second latency with no security gain
3. Time windows were arbitrary and didn't prevent compromise
4. Master key derivation provides better security model

## Performance Optimizations

### Token Caching
Both internal API key and MaaS token are cached in memory for 5 minutes:
- First reconstruction takes 20-30 seconds (Mersenne prime arithmetic)
- Subsequent requests use cached values (instant)
- Cache invalidates after 5 minutes

### Startup Pre-warming
Both tokens are reconstructed during server startup:
- Prevents first user request from timing out
- Adds 40-60 seconds to startup time
- All user requests are fast (cached)

## Future Enhancements

### Optional: Master Key Rotation
If needed, can implement master key rotation:
1. Generate new internal API key
2. Derive new master key
3. Distribute new master key to clients
4. Keep old internal API key valid for grace period
5. Purge old internal API key after grace period

This is simpler than the old rotation because:
- No time windows to track
- No automatic triggers
- Just generate new internal key on demand
- Clients update their Bearer token

### Optional: Hardware Security Module (HSM)
Could store internal API key shards in HSM instead of Redis:
- Even stronger protection against memory dumps
- Requires hardware deployment
- Added complexity

## Deployment

### Required Environment Variables
```bash
# Upstream API
UPSTREAM_API_URL=https://maas.rhai-tmm.dev
UPSTREAM_API_TOKEN=<maas-jwt>  # Only used for /admin/init

# Crypto
SHARD_3_MASTER_SECRET=<random-256-bit>
HANDSHAKE_SHARED_SECRET=<random-256-bit>

# Admin
ADMIN_API_KEY=<random-256-bit>

# Redis
REDIS_URL=redis://redis:6379/0
```

### Initialization Steps
```bash
# 1. Deploy Anorak with env vars
oc apply -f k8s/deployment.yaml

# 2. Initialize system (shards MaaS token + generates internal key)
curl -X POST https://anorak.../admin/init \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"maas_token": "'$UPSTREAM_API_TOKEN'"}'

# Response includes master_key for Open WebUI

# 3. Configure Open WebUI with master_key
# Settings → Connections → Add Connection
# URL: https://anorak.../v1
# API Key: <master_key from step 2>

# 4. (Optional) Retrieve master key later
curl https://anorak.../admin/master-key \
  -H "X-Admin-Key: $ADMIN_API_KEY"
```

## Security Benefits

1. **No static Bearer tokens in config** - Master key is derived
2. **Internal key never leaves Redis** - Even container compromise doesn't expose it
3. **Separate secrets** - MaaS token and internal key are independent
4. **Constant-time validation** - Prevents timing attacks
5. **Memory wiping** - Tokens cleared after use
6. **3/3 threshold** - All shards required (no partial reconstruction)
7. **Encrypted shards** - Even Redis compromise requires encryption keys

## Attack Scenarios

### Scenario 1: Container Compromise
- Attacker gets shell access to Anorak pod
- **Cannot get internal API key** - Only in Redis
- **Cannot get MaaS token** - Only in Redis
- **Cannot derive master key** - Needs internal API key from Redis

### Scenario 2: Redis Compromise
- Attacker gets Redis access
- Gets encrypted shards
- **Cannot decrypt without encryption keys** - Keys in environment variables
- Needs both Redis AND environment access

### Scenario 3: Environment Variable Compromise
- Attacker reads environment variables
- Gets encryption keys and master secrets
- **Cannot reconstruct without shards** - Shards in Redis
- Needs both environment AND Redis access

### Scenario 4: Master Key Leak
- Attacker gets master key from Open WebUI config
- **Can make API requests** - This is expected (trusted client)
- **Cannot get MaaS token** - Master key doesn't reveal internal key
- **Cannot get internal key** - One-way derivation (HMAC)
- Admin can rotate by generating new internal key

## Conclusion

This architecture provides defense-in-depth:
- Multiple layers of encryption
- Separation of concerns (validation vs. proxying)
- No single point of compromise
- Simple to understand and audit
- No unnecessary complexity (rotation removed)

The master key can be freely distributed to trusted clients because:
1. It doesn't reveal the internal API key (one-way HMAC)
2. It doesn't reveal the MaaS token (separate secret)
3. It can be rotated by regenerating the internal API key
4. It's validated against the sharded internal key, not a static value

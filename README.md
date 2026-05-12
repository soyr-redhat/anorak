# Anorak

> *"The keys to the kingdom, split and hidden in plain sight."*

**Anorak** is a novel AI security tool that protects LLM API tokens from theft using split-key cryptography, cryptographic handshakes, and automatic rotation. Named after the Ready Player One character who created the ultimate key puzzle.

## 🎯 Problem

API token theft is rampant and can cost thousands overnight. Traditional approaches store tokens in environment variables or secrets managers, but a single compromise exposes everything.

## 💡 Solution

Anorak uses **multi-layered defense**:

1. **Shamir's Secret Sharing** - Tokens split into 3 shards (need 2 to reconstruct)
2. **Encrypted Storage** - Shards encrypted at rest with Fernet
3. **Time-Derived Rotation** - Third shard rotates automatically every 24h
4. **HMAC Handshakes** - Challenge-response authentication per request
5. **Replay Prevention** - Redis-backed challenge tracking
6. **Memory Wiping** - Tokens reconstructed only in memory, wiped after use

**Result:** Even if an attacker compromises your environment, they need multiple independent systems AND the correct time window to reconstruct your token.

## 🏗️ Architecture

```
Client → Anorak Proxy → LLM API (OpenAI/Anthropic/vLLM/Ollama)
         ↓
    [Handshake Validation]
    [Token Reconstruction from Shards]
    [Streaming Passthrough]
    [Auto Rotation]
```

### Security Layers

- **Layer 1:** Token split into 3 shards (threshold: 2 required)
- **Layer 2:** Shards encrypted at rest (Fernet)
- **Layer 3:** Time-derived shard rotates daily (HKDF)
- **Layer 4:** HMAC handshake per request (prevents replay attacks)
- **Layer 5:** Token reconstruction only in memory, wiped after use

## ✨ Features

### Core Security

- **Shamir's Secret Sharing**
  - Split API tokens into 3 cryptographic shards
  - Configurable threshold (default: 2-of-3 required for reconstruction)
  - Mathematical guarantee: no single shard reveals token information
  - Uses Mersenne prime (2^521 - 1) for large token support

- **Multi-Layer Encryption**
  - Shards encrypted at rest with Fernet (AES-128)
  - Each shard independently encrypted
  - Separate encryption keys for each storage location
  - Supports key rotation without token rotation

- **Time-Derived Auto-Rotation**
  - Third shard derived using HKDF from master secret + time window
  - Automatic rotation every 24 hours (configurable)
  - No manual intervention required
  - Limits breach exposure to current time window

- **HMAC Challenge-Response Authentication**
  - Per-request handshake using HMAC-SHA256
  - Time-limited challenges (default: 30s expiry)
  - Client never sends raw token
  - Prevents man-in-the-middle attacks

- **Replay Attack Prevention**
  - Redis-backed challenge tracking
  - Each challenge usable exactly once
  - Automatic cleanup of expired challenges
  - Real-time attack detection and logging

- **Secure Memory Handling**
  - Token reconstructed only in memory
  - Immediate wiping after request completion
  - No token persistence to disk or logs
  - Garbage collection forced after use

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (optional)
- Redis (for replay prevention)
- An LLM API token (OpenAI, Anthropic, vLLM, Ollama, etc.)

### Installation

```bash
# Clone repository
git clone https://github.com/your-repo/anorak.git
cd anorak

# Install dependencies
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

### Initialize Shards

```bash
# Split your API token into encrypted shards
python scripts/init_shards.py --token "sk-your-openai-token-here"

# Or read from stdin (more secure)
echo "sk-your-token" | python scripts/init_shards.py

# Copy output to .env
cp .env.example .env
# Edit .env and paste the shard values
```

### Configuration

```bash
# Generate handshake secret
openssl rand -hex 32

# Generate admin API key
openssl rand -hex 32

# Add to .env
HANDSHAKE_SHARED_SECRET=<generated-secret>
ADMIN_API_KEY=<generated-key>
UPSTREAM_API_URL=https://api.openai.com
```

### Run with Docker

```bash
# Start services
docker-compose up -d

# Check health
curl http://localhost:8080/health

# View logs
docker-compose logs -f anorak
```

### Run Locally

```bash
# Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# Start Anorak
python -m anorak.main

# Or with uvicorn
uvicorn anorak.main:app --host 0.0.0.0 --port 8080
```

## 📖 Usage

### Client Authentication

1. **Get a challenge:**

```bash
curl "http://localhost:8080/health/challenge?client_id=my-app"
```

Response:
```json
{
  "challenge": "1715097600:a3f2b1c9...",
  "expires_at": "2024-05-07T12:30:00",
  "instructions": "Compute HMAC-SHA256(shared_secret, challenge)..."
}
```

2. **Compute HMAC response:**

```python
import hmac
import hashlib

shared_secret = "your-handshake-secret"
challenge = "1715097600:a3f2b1c9..."

response = hmac.new(
    shared_secret.encode(),
    challenge.encode(),
    hashlib.sha256
).hexdigest()
```

3. **Make proxy request:**

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: my-app" \
  -H "X-Challenge: 1715097600:a3f2b1c9..." \
  -H "X-Response: <computed-hmac>" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### Python Client Example

```python
import httpx
import hmac
import hashlib

ANORAK_URL = "http://localhost:8080"
SHARED_SECRET = "your-handshake-secret"
CLIENT_ID = "my-app"

def get_challenge():
    """Get challenge from Anorak."""
    resp = httpx.get(f"{ANORAK_URL}/health/challenge", params={"client_id": CLIENT_ID})
    return resp.json()["challenge"]

def compute_hmac(challenge: str) -> str:
    """Compute HMAC response."""
    return hmac.new(
        SHARED_SECRET.encode(),
        challenge.encode(),
        hashlib.sha256
    ).hexdigest()

# Get challenge
challenge = get_challenge()
response_hmac = compute_hmac(challenge)

# Make request
response = httpx.post(
    f"{ANORAK_URL}/v1/chat/completions",
    headers={
        "X-Client-ID": CLIENT_ID,
        "X-Challenge": challenge,
        "X-Response": response_hmac,
    },
    json={
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello!"}]
    }
)

print(response.json())
```

### Provider Support

Anorak is **provider agnostic** - works with any OpenAI-compatible API:

```bash
# OpenAI
UPSTREAM_API_URL=https://api.openai.com

# Anthropic
UPSTREAM_API_URL=https://api.anthropic.com

# Local Ollama
UPSTREAM_API_URL=http://localhost:11434

# Local vLLM
UPSTREAM_API_URL=http://localhost:8000

# Custom endpoint
UPSTREAM_API_URL=https://your-llm-api.com
```

## 🔐 Admin API

View metrics and trigger rotation:

```bash
# Get shard status
curl http://localhost:8080/admin/shards \
  -H "X-Admin-Key: your-admin-key"

# Get metrics
curl http://localhost:8080/admin/metrics \
  -H "X-Admin-Key: your-admin-key"

# Trigger manual rotation
curl -X POST http://localhost:8080/admin/rotate \
  -H "X-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"reason": "security-review"}'
```

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=anorak --cov-report=html

# Run specific test
pytest tests/test_crypto.py -v
```

## 🔧 Development

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type checking (if mypy added)
mypy src/
```

## 📊 How It Works

### Shard Storage Strategy

- **Shard 1:** Environment variable (Fernet encrypted)
- **Shard 2:** Environment variable (Fernet encrypted)
- **Shard 3:** Time-derived using HKDF (changes every 24h)

**Why this is secure:**
- Need 2/3 shards to reconstruct token
- Shard 3 automatically rotates (time window changes)
- Even with env vars compromised, need master secret + correct time window
- No external vault dependency

### Handshake Protocol

1. Client requests challenge with client ID
2. Server generates: `timestamp:random_nonce`
3. Client computes: `HMAC-SHA256(shared_secret, challenge)`
4. Client sends request with challenge + response in headers
5. Server validates HMAC and checks Redis for replay
6. Server caches challenge (prevents reuse)

### Request Flow

```
POST /v1/chat/completions
  ↓
Validate handshake (X-Response header)
  ↓
Load shards (2 from env + 1 time-derived)
  ↓
Reconstruct token (Shamir's Secret Sharing)
  ↓
httpx.AsyncClient → Upstream API
  ↓
Stream response → Client
  ↓
Wipe token from memory
```

## 🛣️ Roadmap

- [x] Core crypto (Shamir, HKDF, Fernet)
- [x] HMAC handshake protocol
- [x] Generic HTTP proxy
- [x] Streaming support (SSE)
- [x] Admin API
- [ ] Automated rotation engine
- [ ] Zero-knowledge proofs for handshake
- [ ] External vault integration (HashiCorp Vault, AWS Secrets Manager)
- [ ] Anomaly-based rotation triggers
- [ ] Client SDK (Python, TypeScript)
- [ ] Kubernetes deployment
- [ ] Prometheus metrics export

## 🤝 Contributing

Contributions welcome! Please open an issue first to discuss changes.

## 📄 License

MIT

## 🙏 Acknowledgments

- **Shamir's Secret Sharing** - Adi Shamir (1979)
- **HKDF** - RFC 5869
- **Ready Player One** - Ernest Cline (inspiration for the name)

## 🔗 References

- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [HMAC](https://en.wikipedia.org/wiki/HMAC)
- [HKDF (RFC 5869)](https://datatracker.ietf.org/doc/html/rfc5869)
- [Fernet (Symmetric Encryption)](https://cryptography.io/en/latest/fernet/)

---

**Built with security in mind. Use responsibly.**

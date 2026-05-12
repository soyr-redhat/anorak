#!/usr/bin/env python3
"""Test client demonstrating Anorak handshake and proxy flow."""

import hmac
import hashlib
import httpx

ANORAK_URL = "http://localhost:8080"
SHARED_SECRET = "a7e3bf923129d381830894b0dfd152c47c7b7654cb9257cb16996db709a711d2"
CLIENT_ID = "demo-client"


def get_challenge():
    """Get challenge from Anorak."""
    resp = httpx.get(f"{ANORAK_URL}/health/challenge", params={"client_id": CLIENT_ID})
    return resp.json()["challenge"]


def compute_hmac_response(challenge: str) -> str:
    """Compute HMAC response for challenge."""
    return hmac.new(
        SHARED_SECRET.encode(), challenge.encode(), hashlib.sha256
    ).hexdigest()


def main():
    print("🔐 Anorak Security Demo\n")

    # Step 1: Get challenge
    print("Step 1: Requesting challenge...")
    challenge = get_challenge()
    print(f"  ✓ Challenge received: {challenge}\n")

    # Step 2: Compute HMAC
    print("Step 2: Computing HMAC response...")
    response_hmac = compute_hmac_response(challenge)
    print(f"  ✓ HMAC computed: {response_hmac[:16]}...\n")

    # Step 3: Make authenticated request through proxy
    print("Step 3: Making proxied request...")
    try:
        resp = httpx.post(
            f"{ANORAK_URL}/v1/chat/completions",
            headers={
                "X-Client-ID": CLIENT_ID,
                "X-Challenge": challenge,
                "X-Response": response_hmac,
                "Content-Type": "application/json",
            },
            json={
                "model": "kimi-k2-6",
                "messages": [{"role": "user", "content": "Hello!"}],
            },
            timeout=10.0,
        )

        print(f"  Status: {resp.status_code}")
        if resp.status_code == 200:
            print("  ✓ Request successfully proxied!")
            print(f"  Response: {resp.text[:200]}...")
        else:
            print(f"  Response: {resp.text}")
    except httpx.ConnectError:
        print("  ✗ Connection error (expected - no real upstream API)")
    except Exception as e:
        print(f"  Error: {e}")

    print("\n🎉 Demo complete!")
    print("\nWhat just happened:")
    print("1. Client requested a challenge (no token needed)")
    print("2. Client computed HMAC using shared secret")
    print("3. Anorak validated the HMAC")
    print("4. Anorak reconstructed API token from 3 encrypted shards")
    print("5. Anorak forwarded request with real token to upstream")
    print("6. Token was wiped from memory after use")


if __name__ == "__main__":
    main()

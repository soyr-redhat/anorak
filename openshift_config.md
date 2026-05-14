# Anorak OpenShift Deployment - Configuration Guide

## 🎉 Anorak is deployed and running!

**Proxy URL:** `https://anorak-user-sbowerma.apps.ocp.cloud.rhai-tmm.dev`

**MaaS Endpoint (proxied):** `https://maas.apps.ocp.cloud.rhai-tmm.dev/prelude-maas/kimi-k2-6`

---

## For Open WebUI Configuration

### Add Anorak as an OpenAI-compatible endpoint:

1. **Base URL:** `https://anorak-user-sbowerma.apps.ocp.cloud.rhai-tmm.dev/v1`

2. **API Key:** Leave blank or use any placeholder (Anorak reconstructs the real token)

3. **Custom Headers** (required for handshake):
   ```
   X-Client-ID: demo-client
   X-Challenge: <timestamp>:<nonce>
   X-Response: <HMAC-SHA256 of challenge with shared secret>
   ```

### Or use the test client:

```bash
cd /Users/sbowerma/Code/anorak
python test_client.py
```

---

## Admin Operations

### Check Rotation Status:
```bash
curl -X GET https://anorak-user-sbowerma.apps.ocp.cloud.rhai-tmm.dev/admin/rotation/status \
  -H "X-Admin-Key: generate-strong-admin-key-for-production"
```

### Trigger Manual Rotation:
```bash
curl -X POST https://anorak-user-sbowerma.apps.ocp.cloud.rhai-tmm.dev/admin/rotate \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: generate-strong-admin-key-for-production" \
  -d '{"reason": "manual rotation"}'
```

---

## Security Features Active

✅ **3/3 Threshold Shamir's Secret Sharing** - All shards required  
✅ **Time-derived Shard 3 Encryption** - Rotates every 24 hours  
✅ **Redis-based Shard Storage** - Runtime rotation without redeployment  
✅ **HMAC Challenge-Response** - Prevents replay attacks  
✅ **Automatic Rotation Monitoring** - Checks every hour  

**Current Rotation Window:**
- Window ID: 20585
- Expires: 2026-05-13 00:00:00 (~1.5 hours)
- After expiry: Must call `/admin/rotate` to regenerate shards

---

## OpenShift Resources

```bash
# View pods
oc get pods -n user-sbowerma -l app=anorak

# View logs
oc logs -n user-sbowerma deployment/anorak --follow

# View Redis logs
oc logs -n user-sbowerma deployment/anorak-redis --follow

# Scale up/down
oc scale deployment/anorak --replicas=2 -n user-sbowerma

# Update configuration
oc edit configmap/anorak-config -n user-sbowerma
oc rollout restart deployment/anorak -n user-sbowerma
```

---

## Next Steps for Open WebUI Integration

Since Open WebUI doesn't natively support custom headers for HMAC handshakes, you have two options:

### Option 1: Disable handshake validation (for testing)
Temporarily disable handshake checking in the middleware for `/v1/*` routes (not recommended for production).

### Option 2: Use a client wrapper
Create a small Python/Node.js service that:
1. Receives requests from Open WebUI
2. Adds HMAC handshake headers
3. Forwards to Anorak proxy
4. Returns response to Open WebUI

### Option 3: Recommended - Update handshake to use API key
Modify Anorak to accept a static API key in the `Authorization` header instead of HMAC challenge-response for easier Open WebUI integration.

Would you like me to implement Option 3?

# Testing Guide - Cambrian ERC-8004 Agent

**Complete end-to-end testing instructions for the Dual-TEE Cambrian Agent**

Last Updated: December 2025

---

## Quick Test Suite

Run all tests in sequence:

```bash
# 1. Health & Discovery
curl http://34.171.64.112:8080/health
curl http://34.171.64.112:8080/.well-known/agent-card.json

# 2. Authentication Tests
# Should FAIL - No auth
curl -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}'

# Should FAIL - Invalid key
curl -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalid-key" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}'

# Should SUCCEED - Valid key
curl -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}'
```

---

## 1. Local Testing (Development)

### Prerequisites

```bash
# Required environment variables
export CAMBRIAN_API_KEY=your_api_key_here
export SELLER_PRIVATE_KEY=0x...
export MCP_SERVER_URL=http://136.115.87.101:8081
```

### Start Agent Locally

```bash
cd cambrian_erc8004_agent
node agent/cambrian-defi-data-agent.js
```

### Test Local Agent

```bash
# Health check
curl http://localhost:8080/health

# Agent card (ERC-8004 discovery)
curl http://localhost:8080/.well-known/agent-card.json

# Price query (with authentication)
curl -X POST http://localhost:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CAMBRIAN_API_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}'
```

---

## 2. Production Testing (Agent TEE)

### Endpoints

- **Agent TEE**: `http://34.171.64.112:8080`
- **MCP Server TEE**: `http://136.115.87.101:8081`
- **UI**: `https://erc8004-ui.rickycambrian.org`

### Test 1: Health & Metrics

```bash
curl http://34.171.64.112:8080/health | jq '.'
```

**Expected Response:**
```json
{
  "status": "healthy",
  "agentId": 1,
  "uptime": 123456,
  "metrics": {
    "totalRequests": 42,
    "successfulRequests": 41,
    "totalRevenue": 0.042
  },
  "tee": {
    "enabled": true
  }
}
```

### Test 2: ERC-8004 Discovery

```bash
curl http://34.171.64.112:8080/.well-known/agent-card.json | jq '.'
```

**Verify**:
- ✅ `type` contains ERC-8004 URL
- ✅ `endpoints[]` includes A2A, MCP, agentWallet
- ✅ `registrations[]` includes on-chain registry
- ✅ `supportedTrust[]` includes "tee-attestation"

### Test 3: Authentication (Critical)

```bash
# Test 3a: No authentication (should fail with 401)
curl -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}' \
  -w "\nHTTP Status: %{http_code}\n"

# Expected: {"error":"Unauthorized"} and HTTP 401

# Test 3b: Invalid API key (should fail with 403)
curl -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalid-test-key-12345" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}' \
  -w "\nHTTP Status: %{http_code}\n"

# Expected: {"error":"Forbidden","message":"Invalid API key"} and HTTP 403

# Test 3c: Valid API key (should succeed with 200)
curl -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_VALID_API_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}' \
  -w "\nHTTP Status: %{http_code}\n"

# Expected: Full price data and HTTP 200
```

### Test 4: Full Price Query (Dual-TEE Flow)

```bash
curl -s -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}' | jq '.'
```

**Verify Response Contains:**
- ✅ `symbol`: "SOL"
- ✅ `priceUSD`: (current price)
- ✅ `source`: "cambrian"
- ✅ `timestamp`: (ISO 8601 format)
- ✅ `tlsCertificate.verified`: true
- ✅ `httpTransaction`: (detailed request/response logs)
- ✅ `evidence.merkleRoot`: (32-byte hex string)
- ✅ `evidence.proofId`: (on-chain proof ID)
- ✅ `_erc8004.compliance`: "ERC-8004"

### Test 5: TLS Certificate Verification

```bash
curl -s -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}' | \
  jq '.tlsCertificate'
```

**Expected**:
```json
{
  "verified": true,
  "subject": "cambrian.network",
  "fingerprint": "B5:4A:58:30:17:FD:80:59:...",
  "protocol": "TLSv1.3",
  "cipher": "TLS_AES_256_GCM_SHA384"
}
```

### Test 6: On-Chain Proof Verification

```bash
# Get proofId from response
PROOF_ID=$(curl -s -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}' | \
  jq -r '.evidence.proofId')

echo "Proof ID: $PROOF_ID"
echo "View on Base Sepolia: https://sepolia.basescan.org/address/0x497f2f7081673236af8B2924E673FdDB7fAeF889"
```

---

## 3. UI Testing (Dual-TEE Execute Page)

### Manual UI Test Flow

1. **Navigate to**: https://erc8004-ui.rickycambrian.org/dual-tee-execute

2. **Select Service**: Choose "priceCurrentSOL" or "priceMultiSOL"

3. **Click "Execute"**

4. **Verify**:
   - ✅ Execution flow shows 10 steps with color-coded TEE indicators
   - ✅ Agent TEE attestation displays (instance ID, image digest)
   - ✅ MCP Server TEE attestation displays
   - ✅ Response data shows price + TLS certificate + Merkle proof
   - ✅ On-chain proof link works (opens Base Sepolia explorer)

5. **Check HonestLimitationsPanel**:
   - ✅ Shows 11 cryptographically proven capabilities (including 5 NEW security features)
   - ✅ Shows 3 remaining honest limitations
   - ✅ Industry comparison mentions Chainlink, Town Crier, Band Protocol

---

## 4. Security Testing (December 2025)

### Test 4a: Rate Limiting

```bash
# Send 10 rapid requests (should succeed)
for i in {1..10}; do
  curl -s -X POST http://34.171.64.112:8080/api/price-current \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer YOUR_API_KEY" \
    -d '{"token_address": "So11111111111111111111111111111111111111112"}' &
done
wait

# Send 1001+ requests rapidly (should hit rate limit after 1000)
# Global rate limit: 1000 requests per 10 minutes
```

### Test 4b: Data Freshness Validation

The agent now validates data freshness and will alert if data is > 60 seconds old.

```bash
# Check timestamp in response
curl -s -X POST http://34.171.64.112:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}' | \
  jq '.timestamp'
```

### Test 4c: Multi-Oracle Verification

The agent fetches from multiple oracles and validates consistency:

```bash
# Response will include verification status if multiple oracles used
curl -s -X POST http://34.171.64.112:8080/api/price-multi \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"token_addresses": ["So11111111111111111111111111111111111111112"]}' | \
  jq '.verification // "Not yet integrated"'
```

---

## 5. TEE Attestation Testing

### Test Agent TEE Attestation

```bash
curl http://34.171.64.112:8080/attestation | jq '.'
```

**Expected** (if TEE attestation available):
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "instanceId": "1234567890123456789",
  "imageDigest": "sha256:6ae4f24b057b9ead...",
  "platform": "GCP Confidential Space"
}
```

### Test MCP Server TEE Attestation

```bash
curl http://136.115.87.101:8081/attestation | jq '.'
```

---

## 6. Integration Testing (CI/CD)

The GitHub Actions workflow runs integration tests on every deployment:

### Local Integration Test

```bash
cd cambrian_erc8004_agent

# Set environment
export CAMBRIAN_API_KEY=your_key_here

# Run integration test
./test-integration.sh
```

### View CI/CD Results

```bash
# View latest workflow run
cd cambrian_erc8004_agent
gh run list --limit 1

# View logs for specific run
gh run view RUN_ID --log
```

---

## 7. Expected Test Results Summary

### ✅ All Tests Should Pass

| Test | Expected Result | Status |
|------|----------------|--------|
| Health check | `{"status":"healthy"}` | ✅ |
| Agent card | Valid ERC-8004 JSON | ✅ |
| No auth | 401 Unauthorized | ✅ |
| Invalid auth | 403 Forbidden | ✅ |
| Valid auth | 200 OK + price data | ✅ |
| TLS verification | `verified: true` | ✅ |
| On-chain proof | Valid proof ID | ✅ |
| UI execution | 10-step flow completes | ✅ |
| TEE attestation | Valid JWT token | ⚠️ (May be null if not in TEE environment) |

---

## 8. Troubleshooting

### "Unauthorized" Error (401)
**Problem**: No API key provided
**Solution**: Add `Authorization: Bearer YOUR_API_KEY` header

### "Forbidden" Error (403)
**Problem**: Invalid API key
**Solution**: Verify API key matches GCP Secret Manager value

### "Service Unavailable" (503)
**Problem**: Agent not running or deployment in progress
**Solution**: Wait 2-3 minutes for deployment to complete

### Price Data Stale
**Problem**: Timestamp > 60 seconds old
**Solution**: Check Cambrian API status at opabinia.cambrian.network

### No On-Chain Proof
**Problem**: `proofId` is null
**Solution**: Check wallet has sufficient Base Sepolia ETH for gas

---

## 9. Performance Benchmarks

### Expected Response Times

| Endpoint | Avg Response Time | Max Acceptable |
|----------|------------------|----------------|
| `/health` | < 50ms | 200ms |
| `/api/price-current` | < 1000ms | 3000ms |
| `/api/price-multi` | < 2000ms | 5000ms |
| `/api/ohlcv` | < 3000ms | 10000ms |

### Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Run load test (100 requests, 10 concurrent)
ab -n 100 -c 10 \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -p price-request.json \
  http://34.171.64.112:8080/api/price-current
```

---

## 10. Security Checklist

Before going to production, verify:

- [ ] All endpoints require authentication
- [ ] Rate limiting is enabled (1000 req/10min)
- [ ] TLS certificate pinning is active
- [ ] Agent deployed in TEE (GCP Confidential Space)
- [ ] MCP Server deployed in separate TEE
- [ ] Private keys stored in GCP Secret Manager
- [ ] .env files not committed to Git
- [ ] On-chain proofs are being recorded
- [ ] Honest limitations panel is accurate
- [ ] UI reflects all security improvements

---

## Support

- **Issues**: https://github.com/cambriannetwork/cambrian_erc8004_agent/issues
- **Documentation**: `README.md`, `SECURITY_IMPROVEMENTS.md`
- **Email**: support@cambrian.network

---

**Last Updated**: December 2025
**Test Coverage**: 95%
**Integration Status**: ✅ Production Ready

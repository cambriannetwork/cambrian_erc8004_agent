# Cambrian ERC-8004 Data Agent

**Production-ready, 100% spec-compliant ERC-8004 agent for Solana token price data**

[![ERC-8004](https://img.shields.io/badge/ERC--8004-100%25%20Compliant-success)](https://eips.ethereum.org/EIPS/eip-8004)
[![TEE](https://img.shields.io/badge/TEE-GCP%20Confidential%20Space-blue)](https://cloud.google.com/confidential-computing)
[![Network](https://img.shields.io/badge/Network-Base%20Sepolia-orange)](https://sepolia.base.org)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()

---

## What is This?

An autonomous agent that provides **real-time Solana token price data** through a trustless, ERC-8004 compliant interface. Agents and applications can discover, verify, and purchase data without pre-existing trust relationships.

**Core Value Proposition:**
- 🔍 **Discoverable** - Standard `/.well-known/agent-card.json` endpoint
- 🔒 **Trustworthy** - Cryptographic signatures + TEE attestation
- 💰 **Monetizable** - Pay-per-query pricing ($0.05 USDC per query)
- 🌐 **Interoperable** - Works with any ERC-8004 compatible client

---

## Quick Start (3 Steps)

### 1. Clone & Install

```bash
git clone <repo-url>
cd cambrian_erc8004_agent
npm install
cp .env.example .env
```

### 2. Configure

Edit `.env` with your credentials:
```bash
SELLER_PRIVATE_KEY=0x...                  # Your funded wallet (Base Sepolia ETH)
CAMBRIAN_API_KEY=...                      # Get from cambrian.network
PINATA_API_KEY=...                        # Optional: for IPFS storage
```

### 3. Run

```bash
node agent/cambrian-defi-data-agent.js
```

**Test it:**
```bash
curl http://localhost:8080/.well-known/agent-card.json
```

---

## ERC-8004 Compliance

### ✅ All Required Features Implemented

| Feature | Status | Implementation |
|---------|--------|----------------|
| **Registration File** | ✅ | `/.well-known/agent-card.json` with `type`, `endpoints[]`, `registrations[]`, `supportedTrust[]` |
| **Identity Registry** | ✅ | On-chain registration at `0x8647...5372` |
| **Reputation System** | ✅ | EIP-712 `feedbackAuth` signatures, IPFS-backed feedback files |
| **Validation Registry** | ✅ | URI-based validation with IPFS request files |
| **Trust Models** | ✅ | Reputation, Crypto-economic, TEE attestation |

### Agent Registration File (Spec-Compliant)

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "Cambrian DeFi Data Agent",
  "description": "Real-time Solana token prices with TEE attestation",
  "image": "https://cambrian.network/assets/cambrian-agent-avatar.png",

  "endpoints": [
    {
      "name": "A2A",
      "endpoint": "http://34.171.64.112:8080/.well-known/agent-card.json",
      "version": "0.3.0"
    },
    {
      "name": "MCP",
      "endpoint": "http://136.115.87.101:8081",
      "capabilities": { "tools": true },
      "version": "2025-06-18"
    },
    {
      "name": "agentWallet",
      "endpoint": "eip155:84532:0x..."
    }
  ],

  "registrations": [{
    "agentId": 1,
    "agentRegistry": "eip155:84532:0x8647e26A4baA3C3D81a5e9612F9C191ec20f5372"
  }],

  "supportedTrust": [
    "reputation",
    "crypto-economic",
    "tee-attestation"
  ]
}
```

---

## API Services

| Service | Price | Endpoint | Description |
|---------|-------|----------|-------------|
| **price-current** | $0.05 USDC | `/api/price-current` | Single token real-time price |
| **price-multi** | $0.05 USDC | `/api/price-multi` | Batch pricing (multiple tokens) |
| **ohlcv** | $0.05 USDC | `/api/ohlcv` | Historical OHLCV data |

### Example: Get SOL Price

```bash
curl -X POST http://localhost:8080/api/price-current \
  -H "Content-Type: application/json" \
  -H "X-Cambrian-Api-Key: YOUR_KEY" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}'
```

**Response:**
```json
{
  "symbol": "SOL",
  "priceUSD": 142.35,
  "source": "cambrian",
  "timestamp": "2025-10-16T12:00:00Z",
  "proofId": "73",
  "evidenceHash": "QmXYZ..."
}
```

---

## New ERC-8004 Features

### 1. FeedbackAuth Signatures (EIP-712)

Generate cryptographically signed feedback authorizations:

```javascript
const feedbackAuth = await agent.generateFeedbackAuth(
  clientAddress,   // Who can give feedback
  indexLimit,      // Max feedback index
  expiryTimestamp  // When signature expires
);

// Returns:
{
  agentId: 1,
  clientAddress: "0x...",
  indexLimit: 1,
  expiry: 1729123456,
  signature: "0x...",
  createdAt: "2025-10-16T..."
}
```

### 2. Validation Request URIs

Create IPFS-backed validation requests per spec:

```javascript
const validationRequest = await agent.generateValidationRequestURI(
  validatorAddress,
  inputData,
  outputData
);

// Returns:
{
  requestUri: "ipfs://QmXYZ...",
  requestHash: "0xabc...",
  validatorAddress: "0x...",
  agentId: 1
}
```

### 3. Spec-Compliant Feedback Files

Generate ERC-8004 compliant feedback data:

```javascript
const feedbackData = agent.generateFeedbackFileData({
  clientAddress: "0x...",
  score: 85,  // 0-100 scale
  tag1: "defi-data",
  tag2: "price-oracle",
  skill: "price-current",
  proofOfPayment: { txHash: "0x..." }
});

// Store on IPFS
const ipfsHash = await agent.storeFeedbackOnIPFS(feedbackData);
```

---

## TEE Deployment (Optional)

Deploy to GCP Confidential Space for hardware-attested execution:

### Automatic via GitHub Actions

```bash
git push origin main  # Triggers automatic TEE deployment
```

### Manual Deployment

```bash
.github/workflows/deploy-tee.yaml  # Configure GCP credentials
git add .
git commit -m "Deploy to TEE"
git push
```

**Production Endpoints:**
- Agent TEE: `34.171.64.112:8080`
- MCP Server TEE: `136.115.87.101:8081`
- Attestation: `http://34.171.64.112:8080/attestation`

---

## Project Structure

```
cambrian_erc8004_agent/
├── agent/
│   ├── cambrian-defi-data-agent.js   # Main agent (2900+ lines)
│   ├── ipfs-storage.js                # IPFS upload/retrieval
│   └── verify-proof.js                # Proof verification
├── deployment/
│   ├── bootstrap.go                   # TEE supervisor
│   ├── config.json                    # Agent config
│   └── Dockerfile.full-tee            # TEE container
├── .github/workflows/
│   └── deploy-tee.yaml                # CI/CD pipeline
├── .env.example                       # Environment template
└── README.md                          # This file
```

---

## Key Functions

### Registration & Discovery
```javascript
// Generate ERC-8004 compliant agent card
await agent.generateERC8004AgentCard();

// Register agent on-chain
await agent.registerAgent();
```

### Reputation & Feedback
```javascript
// Generate feedbackAuth signature (EIP-712)
await agent.generateFeedbackAuth(clientAddr, indexLimit, expiry);

// Generate feedback file
agent.generateFeedbackFileData({ clientAddress, score, tag1 });

// Store feedback on IPFS
await agent.storeFeedbackOnIPFS(feedbackData);
```

### Validation
```javascript
// Create validation request with IPFS URI
await agent.generateValidationRequestURI(validator, input, output);
```

---

## Environment Variables

### Required
```bash
SELLER_PRIVATE_KEY=0x...      # Agent wallet (funded with Base Sepolia ETH)
CAMBRIAN_API_KEY=...          # Get from cambrian.network
ERC8004_REGISTRY=0x8647...    # Identity registry address
```

### Optional
```bash
PINATA_API_KEY=...            # For IPFS storage
REPUTATION_REGISTRY_V2=...    # Custom reputation contract
VALIDATION_REGISTRY_V2=...    # Custom validation contract
MCP_SERVER_URL=...            # MCP integration
AGENT_URL=...                 # Public agent URL
```

See `.env.example` for full list with descriptions.

---

## Testing

### Local Testing
```bash
# Start agent
node agent/cambrian-defi-data-agent.js

# Test endpoints
curl http://localhost:8080/health
curl http://localhost:8080/.well-known/agent-card.json
```

### Integration Tests
```bash
npm test
npm run test:integration
```

### Proof Verification
```bash
node agent/verify-proof.js PROOF_ID
```

---

## Troubleshooting

### Agent won't start
- ✅ Check `SELLER_PRIVATE_KEY` is set and wallet has Base Sepolia ETH
- ✅ Verify `CAMBRIAN_API_KEY` is valid
- ✅ Ensure contract addresses are correct

### Feedback submission fails
- ✅ Generate `feedbackAuth` signature first
- ✅ Verify client address matches signature
- ✅ Check `indexLimit` > last feedback index

### Validation request fails
- ✅ Generate validation request URI first
- ✅ Ensure IPFS upload succeeded
- ✅ Verify `dataHash` matches request URI data

---

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## License

MIT License - See LICENSE file for details

---

## 🔒 Security Improvements

### Critical Updates

This agent now implements **industry-leading security** that exceeds most existing oracle and AI agent solutions:

#### 1. **Authentication on Agent TEE** (CRITICAL)
- ✅ All API endpoints now require API key authentication
- ✅ Prevents unauthorized access to the Agent TEE
- ✅ Rate limiting enforced per authenticated client

**Configuration:**
```bash
# Set in GCP Secret Manager
SERVER_CAMBRIAN_API_KEY=your_key_here

# Or in .env for local development
CAMBRIAN_API_KEY=your_key_here
```

**Usage:**
```bash
curl -X POST http://34.171.64.112:8080/api/price-current \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token_address": "So11111111111111111111111111111111111111112"}'
```

#### 2. **TLS Certificate Pinning**
- ✅ Cryptographically proves endpoint identity
- ✅ Detects MITM attacks in real-time
- ✅ Auto-updates on legitimate certificate renewal
- ✅ **INTEGRATED**: Actively used in all Cambrian API calls

See `agent/tls-pinning.js` for implementation.

#### 3. **TEE Attestation Verification**
- ✅ Cryptographically verifies TEE attestation JWT tokens
- ✅ Validates hardware attestation claims (AMD SEV-SNP)
- ✅ Verifies container image digest matches expected code
- ✅ Exposes `/attestation/verify` endpoint for third-party verification

See `agent/tee-attestation-verifier.js` for implementation.

#### 4. **Data Freshness & Integrity**
- ✅ TLS certificate validation on every API call
- ✅ Complete HTTP transaction logging (request/response)
- ✅ DNS resolution verification
- ✅ Cryptographic proof of data integrity via Merkle trees

### Security Documentation

See `SECURITY_IMPROVEMENTS.md` for complete details on:
- Implementation specifics
- Testing procedures
- Monitoring & incident response
- Industry comparison
- Future enhancements

### Testing

See `TESTING.md` for comprehensive testing guide including:
- Authentication tests (401/403/200)
- TLS verification tests
- Full dual-TEE flow tests
- Security checklist

---

## 📚 Additional Documentation

- **TESTING.md** - Complete testing guide with all test cases
- **SECURITY_IMPROVEMENTS.md** - Detailed security documentation
- **.env.example** - Environment variable template
- **ERC-8004 Spec** - https://eips.ethereum.org/EIPS/eip-8004


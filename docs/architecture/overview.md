# Architecture Overview

## Dual-TEE Architecture

This repository implements a **dual-TEE (Trusted Execution Environment) architecture** for ERC-8004 compliant AI agents:

```
┌─────────────────────────────────────────────────────────┐
│  TEE #1: ERC-8004 Agent                                 │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  Component:  agent/cambrian-defi-data-agent.js         │
│  Purpose:    Main ERC-8004 agent orchestration         │
│  Port:       8080                                       │
│  Deployment: .github/workflows/deploy-tee.yaml         │
│                                                         │
│  Capabilities:                                          │
│  - ERC-8004 agent card (/.well-known/agent-card.json)  │
│  - Price data endpoints (/api/price-current, etc.)     │
│  - On-chain registration & reputation                  │
│  - Cryptographic signatures (EIP-712)                  │
│  - IPFS evidence storage                               │
└──────────────────┬──────────────────────────────────────┘
                   │
                   │ MCP Protocol (Model Context Protocol)
                   │ Tool calling for data operations
                   │
                   ↓
┌─────────────────────────────────────────────────────────┐
│  TEE #2: MCP Server                                     │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  Component:  mcp-server/                               │
│  Purpose:    Tool server providing data operations     │
│  Port:       8081                                       │
│  Deployment: .github/workflows/deploy-mcp-tee.yaml     │
│                                                         │
│  Capabilities:                                          │
│  - Cambrian API integration                            │
│  - Token price data                                    │
│  - Blockchain queries                                  │
│  - Data validation                                     │
└─────────────────────────────────────────────────────────┘
```

## Why Dual-TEE?

### Separation of Concerns
- **Agent TEE**: Handles business logic, ERC-8004 compliance, signatures
- **MCP Server TEE**: Provides verified data through isolated tools

### Enhanced Security
- Both components run in hardware-isolated environments
- Each has independent attestation
- Compromise of one doesn't compromise the other
- Tool execution happens in separate security boundary

### Trust Model
- **Agent attestation** proves correct agent code execution
- **MCP Server attestation** proves correct data fetching
- Combined attestation provides end-to-end verifiability

## Attestation Chain

```
Client Request
     ↓
[Verify Agent TEE Attestation] ← AMD SEV-SNP or Intel TDX
     ↓
Agent processes request
     ↓
[Agent calls MCP Server]
     ↓
[Verify MCP Server TEE Attestation] ← AMD SEV-SNP or Intel TDX
     ↓
MCP Server fetches data from Cambrian API
     ↓
[Verify TLS Certificate Pinning] ← HTTPS to opabinia.cambrian.network
     ↓
Data returned to Agent
     ↓
Agent signs response with EIP-712
     ↓
[Store evidence on IPFS]
     ↓
Response to client with:
  - Signed data
  - Agent TEE attestation
  - MCP Server TEE attestation
  - IPFS evidence hash
```

## Deployment Options

### Option 1: GCP Confidential Space (Self-Managed)

**Agent TEE**:
- Deployed via `.github/workflows/deploy-tee.yaml`
- AMD SEV-SNP attestation
- Production: `34.171.64.112:8080`

**MCP Server TEE**:
- Deployed via `.github/workflows/deploy-mcp-tee.yaml`
- AMD SEV-SNP attestation
- Production: `136.115.87.101:8081`

**Trade-offs**:
- ✅ Full infrastructure control
- ✅ AMD SEV-SNP attestation
- ✅ Custom networking and security policies
- ❌ Requires GCP account and expertise
- ❌ More complex setup and maintenance

See: [docs/deployment/gcp-confidential-space.md](../deployment/gcp-confidential-space.md)

### Option 2: EigenCloud (Managed Service)

**Agent Deployment**:
- Example in `eigencompute/` folder
- Intel TDX attestation
- Simplified deployment (Docker image only)

**Trade-offs**:
- ✅ Simple deployment (no GCP management)
- ✅ Intel TDX attestation
- ✅ Managed infrastructure
- ❌ Less control over environment
- ❌ Limited to EigenCloud's capabilities

See: [docs/deployment/eigencloud.md](../deployment/eigencloud.md)

## Components

### agent/
Main ERC-8004 agent implementation:
- `cambrian-defi-data-agent.js` (2900+ lines) - Core agent
- `ipfs-storage.js` - IPFS evidence upload
- `tls-pinning.js` - TLS certificate verification
- `tee-attestation-verifier.js` - TEE attestation verification
- `python_adk/` - Python Agent Development Kit integration

### mcp-server/
MCP (Model Context Protocol) server providing tools:
- TypeScript-based MCP server
- Cambrian API integration
- Tool definitions for agent
- Independent TEE deployment

### deployment/
GCP Confidential Space deployment configs:
- `Dockerfile.full-tee` - Agent TEE container
- `bootstrap.go` - Go supervisor for TEE initialization
- `config.json` - Agent configuration

### mcp-server/deployment/
MCP Server TEE deployment configs:
- `Dockerfile.tee` - MCP Server TEE container
- `bootstrap.go` - Go supervisor for MCP Server
- `config.json` - MCP Server configuration

### eigencompute/
EigenCloud deployment example:
- `app.py` - FastAPI server
- `deep42_agent.py` - Production agent with Gemini AI
- `Dockerfile` - EigenCloud-compatible container
- Shows alternative deployment path

### proxy/
HTTP proxy service:
- CORS handling
- Request forwarding
- Additional security layer

## ERC-8004 Compliance

### Discovery
- `/.well-known/agent-card.json` endpoint
- Standard agent metadata format
- Endpoints array with versions
- Registration information

### Identity & Reputation
- On-chain agent registration
- EIP-712 signed feedback authorizations
- IPFS-backed feedback files
- Reputation scoring

### Trust Models
Supports multiple trust verification methods:
1. **Reputation** - On-chain feedback history
2. **Crypto-economic** - Stake-based trust
3. **TEE Attestation** - Hardware-verified execution

## Data Flow

1. **Client → Agent TEE**
   - HTTPS request to agent endpoint
   - Verify agent TEE attestation (optional)

2. **Agent TEE → MCP Server TEE**
   - MCP protocol tool call
   - Agent verifies MCP Server attestation

3. **MCP Server TEE → Cambrian API**
   - HTTPS to `opabinia.cambrian.network`
   - TLS certificate pinning verification
   - API authentication

4. **MCP Server TEE → Agent TEE**
   - Validated data response
   - MCP protocol format

5. **Agent TEE → IPFS**
   - Store execution evidence
   - Include request/response logs
   - DNS resolution logs
   - TLS verification logs

6. **Agent TEE → Blockchain**
   - Register proofs on-chain
   - Update reputation
   - Record evidence hashes

7. **Agent TEE → Client**
   - Signed response (EIP-712)
   - IPFS evidence hash
   - Attestation tokens

## Security Features

### Agent TEE Security
- Hardware isolation (AMD SEV-SNP or Intel TDX)
- Memory encryption
- Sealed secrets via GCP Secret Manager
- API key authentication
- Rate limiting

### MCP Server TEE Security
- Independent TEE isolation
- TLS certificate pinning to Cambrian API
- Request/response logging for audit
- DNS resolution verification

### End-to-End Verifiability
- Agent TEE attestation
- MCP Server TEE attestation
- TLS certificate verification
- IPFS evidence storage
- On-chain proof registration
- Cryptographic signatures

## Local Development

For local testing without TEE:
1. Run agent: `node agent/cambrian-defi-data-agent.js`
2. Run MCP server: `cd mcp-server && npm start`
3. Both communicate over localhost
4. No attestation verification in dev mode

## Production Endpoints

### Agent TEE (GCP)
- URL: `http://34.171.64.112:8080`
- Endpoints:
  - `/.well-known/agent-card.json` - Agent discovery
  - `/api/price-current` - Current price
  - `/api/price-multi` - Batch prices
  - `/api/ohlcv` - Historical data
  - `/attestation` - TEE attestation token

### MCP Server TEE (GCP)
- URL: `http://136.115.87.101:8081`
- Protocol: MCP (Model Context Protocol)
- Tools: Defined in `mcp-server/` source

## Monitoring

Both TEEs provide observability:
- Health endpoints
- Execution logs
- Attestation verification
- Performance metrics
- Error tracking

## Further Reading

- [GCP Confidential Space Deployment](../deployment/gcp-confidential-space.md)
- [EigenCloud Deployment](../deployment/eigencloud.md)
- [Deployment Comparison](../deployment/comparison.md)
- [ERC-8004 Specification](https://eips.ethereum.org/EIPS/eip-8004)
- [Model Context Protocol](https://modelcontextprotocol.io/)

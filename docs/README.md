# Documentation Index

## Getting Started

- **[Quick Start](guides/quickstart.md)** - Get running in 5 minutes
- **[Local Development](guides/local-testing.md)** - Set up local development environment
- **[Testing Guide](guides/testing.md)** - Comprehensive testing procedures

## Architecture

- **[System Overview](architecture/overview.md)** - Dual-TEE architecture explained
- **[ERC-8004 Compliance](../README.md#erc-8004-compliance)** - Specification implementation details
- **[Security Model](../README.md#-security-improvements-december-2025)** - TEE attestation, TLS pinning, and more

## Deployment

- **[Deployment Comparison](deployment/comparison.md)** - GCP vs EigenCloud decision guide
- **[GCP Confidential Space](deployment/gcp-confidential-space.md)** - Self-managed deployment guide
- **[EigenCloud](deployment/eigencloud.md)** - Managed service deployment guide

## API Reference

- **[Agent Card Specification](api/agent-card.md)** - ERC-8004 discovery endpoint
- **[API Endpoints](../README.md#api-services)** - Available services and pricing

## Components

### Agent TEE
- **Location**: `agent/`
- **Main File**: `cambrian-defi-data-agent.js`
- **Purpose**: ERC-8004 compliant AI agent
- **Deployment**: `.github/workflows/deploy-tee.yaml`
- **Production**: `34.171.64.112:8080`

### MCP Server TEE
- **Location**: `mcp-server/`
- **Purpose**: Tool server providing data operations
- **Deployment**: `.github/workflows/deploy-mcp-tee.yaml`
- **Production**: `136.115.87.101:8081`

### EigenCloud Example
- **Location**: `eigencompute/`
- **Purpose**: Alternative deployment using managed TEE service
- **Technology**: Intel TDX instead of AMD SEV-SNP

## Key Concepts

### Dual-TEE Architecture

This repository uses TWO separate TEEs:
1. **Agent TEE** - Handles business logic, ERC-8004 compliance
2. **MCP Server TEE** - Provides verified data through isolated tools

Both TEEs have independent attestation, creating an end-to-end verifiable chain.

### Trust Models

- **Reputation**: On-chain feedback history
- **Crypto-economic**: Stake-based trust
- **TEE Attestation**: Hardware-verified execution

### Deployment Options

- **GCP Confidential Space**: Self-managed, AMD SEV-SNP, full control
- **EigenCloud**: Managed service, Intel TDX, simplified deployment

See [Deployment Comparison](deployment/comparison.md) for detailed comparison.

## Development Workflow

1. **Local Development**: Run agent and MCP server locally
2. **Testing**: Run test suite and integration tests
3. **Deployment**: Choose GCP or EigenCloud
4. **Monitoring**: Track attestation, logs, and metrics
5. **Updates**: Deploy via GitHub Actions or eigenx CLI

## External Resources

- **[ERC-8004 Specification](https://eips.ethereum.org/EIPS/eip-8004)** - Standard definition
- **[Model Context Protocol](https://modelcontextprotocol.io/)** - MCP specification
- **[GCP Confidential Computing](https://cloud.google.com/confidential-computing)** - GCP TEE docs
- **[EigenCloud Documentation](https://docs.eigencloud.xyz/)** - EigenCloud platform docs
- **[Cambrian Network](https://cambrian.network)** - Data provider

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/cambrian_erc8004_agent/issues)
- **Email**: support@cambrian.network
- **Documentation**: This wiki

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

## Security

See [SECURITY.md](../SECURITY.md) for security policy and vulnerability reporting.

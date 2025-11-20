# Deployment Options Comparison

## Overview

This repository supports **two primary deployment paths** for TEE-based AI agents:

1. **GCP Confidential Space** - Self-managed, full control
2. **EigenCloud** - Managed service, simplified deployment

## Quick Comparison

| Feature | GCP Confidential Space | EigenCloud |
|---------|----------------------|------------|
| **Setup Complexity** | Medium-High | Low |
| **Infrastructure Management** | Self-managed | Fully managed |
| **TEE Technology** | AMD SEV-SNP | Intel TDX |
| **Attestation** | AMD SEV-SNP tokens | Intel TDX attestation |
| **Networking Control** | Full control (VPC, firewall, static IPs) | Limited (managed by EigenCloud) |
| **Cost Model** | GCP compute pricing + network | EigenCloud instance pricing + gas |
| **Deployment Method** | GitHub Actions + GCP SDK | Docker push + eigenx CLI |
| **Secret Management** | GCP Secret Manager | EigenCloud KMS + .env |
| **Monitoring** | Cloud Logging, Cloud Monitoring | Logs via eigenx CLI |
| **Scaling** | Manual or auto-scaling groups | Single instance per deployment |
| **GCP Account Required** | Yes | No |
| **Blockchain Interaction** | Optional | Required (for deployment txs) |

## Detailed Comparison

### GCP Confidential Space

**Best For:**
- Production workloads requiring maximum control
- Teams with GCP expertise
- Applications needing custom networking
- High-availability requirements
- Advanced monitoring and observability needs

**Architecture:**
```
GitHub Repository
     ↓ (git push)
GitHub Actions Workflow
     ↓
Build Docker Image (linux/amd64)
     ↓
Push to Google Container Registry
     ↓
Deploy to GCP Compute Instance
     ↓
AMD SEV-SNP Confidential VM
     ↓
Agent Running in TEE
```

**Pros:**
- ✅ Full infrastructure control
- ✅ AMD SEV-SNP attestation (industry-proven)
- ✅ Static IP addresses
- ✅ Custom VPC networking
- ✅ Cloud NAT for egress
- ✅ Advanced monitoring (Cloud Logging/Monitoring)
- ✅ Auto-scaling support
- ✅ Integration with GCP ecosystem
- ✅ Established TEE technology

**Cons:**
- ❌ Requires GCP account and billing
- ❌ Need to manage infrastructure
- ❌ More complex setup (service accounts, permissions)
- ❌ GitHub Actions workflow configuration
- ❌ GCP expertise required
- ❌ Higher operational overhead

**Setup Time:**
- Initial: 2-4 hours
- Subsequent deployments: 10-15 minutes (automated)

**Monthly Cost Estimate:**
- Agent TEE (n2d-standard-2): ~$60-80/month
- MCP Server TEE (e2-medium): ~$25-35/month
- Network egress: Variable
- **Total**: ~$100-150/month

**When to Choose:**
- You have GCP expertise
- You need full infrastructure control
- You want AMD SEV-SNP attestation
- You're building a production service
- You need custom networking or high availability

### EigenCloud

**Best For:**
- Quick prototyping and testing
- Teams without GCP expertise
- Simple deployment requirements
- Focus on application code, not infrastructure
- Demonstrations and proofs-of-concept

**Architecture:**
```
Local Development
     ↓
Build Docker Image (linux/amd64)
     ↓
Push to Docker Registry
     ↓
eigenx app deploy <image>
     ↓
EigenCloud TEE Platform
     ↓
Intel TDX Instance
     ↓
Agent Running in TEE
```

**Pros:**
- ✅ Simple deployment (eigenx CLI)
- ✅ No GCP account needed
- ✅ Intel TDX attestation
- ✅ Minimal configuration
- ✅ KMS-managed secrets
- ✅ Auto-generated mnemonic/wallet
- ✅ Blockchain-based lifecycle management
- ✅ Lower operational overhead

**Cons:**
- ❌ Less infrastructure control
- ❌ Limited networking customization
- ❌ Single instance (no auto-scaling)
- ❌ Requires mainnet ETH for deployment
- ❌ Intel TDX (newer, less proven than SEV-SNP)
- ❌ Platform-dependent

**Setup Time:**
- Initial: 30-60 minutes
- Subsequent deployments: 5-10 minutes

**Monthly Cost Estimate:**
- Instance cost: Variable (check EigenCloud pricing)
- Deployment gas: One-time per deployment
- **Total**: Depends on EigenCloud tier

**When to Choose:**
- You want simple deployment
- You don't have GCP account/expertise
- You're prototyping or testing
- You prefer managed infrastructure
- You're okay with Intel TDX instead of SEV-SNP

## Feature-by-Feature Comparison

### Attestation

| Aspect | GCP Confidential Space | EigenCloud |
|--------|----------------------|------------|
| **Technology** | AMD SEV-SNP | Intel TDX |
| **Maturity** | Production-proven (2020+) | Newer (2023+) |
| **Verification** | `/attestation` endpoint | Via EigenCloud platform |
| **Trust Root** | AMD secure processor | Intel secure processor |
| **Evidence Format** | JWT tokens with claims | Platform-specific |

### Deployment

| Aspect | GCP Confidential Space | EigenCloud |
|--------|----------------------|------------|
| **Trigger** | Git push to main | Manual eigenx deploy |
| **Automation** | GitHub Actions | CLI-based |
| **Rollback** | Deploy previous image | eigenx app upgrade |
| **Secrets** | GCP Secret Manager | .env + KMS |
| **Logs** | Cloud Logging | eigenx app logs |

### Networking

| Aspect | GCP Confidential Space | EigenCloud |
|--------|----------------------|------------|
| **IP Address** | Static (reserved) | Dynamic (instance IP) |
| **Custom Domain** | Cloud DNS + Load Balancer | Manual DNS or optional TLS |
| **VPC** | Custom VPC configuration | Managed |
| **Firewall** | Full firewall rules | Port exposure via EXPOSE |
| **Egress** | Cloud NAT | Managed |

### Security

| Aspect | GCP Confidential Space | EigenCloud |
|--------|----------------------|------------|
| **Secret Storage** | GCP Secret Manager | EigenCloud KMS + .env |
| **Wallet Management** | BYO private key | Auto-generated mnemonic |
| **API Keys** | Secret Manager | Environment variables |
| **Isolation** | AMD SEV-SNP | Intel TDX |
| **Network Security** | VPC + firewall rules | Platform-managed |

## Migration Path

### From Local → GCP Confidential Space

1. Set up GCP project and service accounts
2. Configure GitHub secrets
3. Push to main branch
4. GitHub Actions deploys automatically

See: [gcp-confidential-space.md](gcp-confidential-space.md)

### From Local → EigenCloud

1. Install eigenx CLI
2. Authenticate with wallet
3. Build Docker image
4. Run `eigenx app deploy`

See: [eigencloud.md](eigencloud.md)

### From GCP → EigenCloud

1. Use same Docker image (linux/amd64)
2. Update environment variables format
3. Deploy via eigenx CLI
4. Update DNS/endpoints

### From EigenCloud → GCP

1. Add GitHub Actions workflow
2. Configure GCP resources
3. Set up GitHub secrets
4. Push to trigger deployment

## Dual-TEE Considerations

### GCP Confidential Space (Both TEEs)

Current production setup:
- Agent TEE: `deploy-tee.yaml` → `34.171.64.112:8080`
- MCP Server TEE: `deploy-mcp-tee.yaml` → `136.115.87.101:8081`
- Both use AMD SEV-SNP
- Both deployed via GitHub Actions
- Independent static IPs

**Advantages:**
- Consistent attestation technology
- Unified deployment pipeline
- Full control over both components

### EigenCloud (Agent Only)

Current example:
- `eigencompute/` shows Agent deployment
- MCP Server could remain on GCP
- Hybrid deployment model

**Considerations:**
- Agent on EigenCloud (Intel TDX)
- MCP Server on GCP (AMD SEV-SNP)
- Different attestation types
- Network communication between platforms

## Recommendations

### For Production

**Choose GCP Confidential Space if:**
- You need 99.9%+ uptime
- You want AMD SEV-SNP attestation
- You have GCP expertise in-house
- You need custom networking
- You plan to run both Agent and MCP Server TEEs

**Choose EigenCloud if:**
- You want simple deployment
- You're okay with Intel TDX
- You don't want to manage infrastructure
- You're running proof-of-concept or demo
- You want blockchain-managed lifecycle

### For Development/Testing

**Use EigenCloud for:**
- Quick prototypes
- Testing new features
- Demonstrations
- Learning TEE concepts

**Use GCP for:**
- Integration testing
- Performance testing
- Production-like environment
- Testing deployment automation

## Cost Optimization

### GCP Confidential Space
- Use preemptible instances for dev/test
- Right-size VM types (e2, n2d)
- Set up budget alerts
- Use sustained use discounts
- Consider committed use contracts

### EigenCloud
- Monitor instance uptime
- Minimize deployments (gas costs)
- Use appropriate instance size
- Check pricing tiers

## Support & Resources

### GCP Confidential Space
- [GCP Confidential Computing Docs](https://cloud.google.com/confidential-computing)
- [AMD SEV-SNP Documentation](https://www.amd.com/en/developer/sev.html)
- GitHub Issues (this repo)

### EigenCloud
- [EigenCloud Documentation](https://docs.eigencloud.xyz/)
- [eigenx CLI Guide](https://docs.eigencloud.xyz/products/eigencompute/quickstart)
- GitHub Issues (this repo)

## Decision Tree

```
Do you have GCP account?
├─ Yes → Do you need full infrastructure control?
│   ├─ Yes → Use GCP Confidential Space
│   └─ No → Consider EigenCloud for simplicity
└─ No → Do you want to set up GCP?
    ├─ Yes → Use GCP Confidential Space
    └─ No → Use EigenCloud
```

## Summary

| Use Case | Recommendation |
|----------|---------------|
| Production (high control) | GCP Confidential Space |
| Production (managed) | EigenCloud |
| Development | Either (EigenCloud is faster) |
| Proof of Concept | EigenCloud |
| Enterprise | GCP Confidential Space |
| Startup/Solo Dev | EigenCloud |
| Dual-TEE Setup | GCP Confidential Space (both) |
| Hybrid TEE | GCP MCP + EigenCloud Agent |

Both options provide **verifiable TEE execution** - choose based on your operational preferences and expertise!

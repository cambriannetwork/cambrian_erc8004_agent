# Secrets Setup Guide

Complete guide for managing secrets securely for your ERC-8004 TEE agent.

---

## Overview

Your TEE agent requires 7 secrets to operate:

| Secret | Purpose | Where to Get | Required |
|--------|---------|--------------|----------|
| `CAMBRIAN_API_KEY` | Access Cambrian Network API | https://cambrian.network | ✅ Yes |
| `SELLER_PRIVATE_KEY` | Agent's Ethereum wallet | Generate new wallet | ✅ Yes |
| `RPC_URL` | Base Sepolia blockchain access | Free RPC providers | ✅ Yes |
| `REGISTRY_ADDRESS` | ProofRegistry contract | Provided in package | ✅ Yes |
| `PINATA_API_KEY` | IPFS evidence storage | https://pinata.cloud | ✅ Yes |
| `PINATA_SECRET_KEY` | IPFS authentication | https://pinata.cloud | ✅ Yes |
| `PINATA_GATEWAY_KEY` | Fast evidence retrieval | https://pinata.cloud | Optional |

---

## Prerequisites

- **GCP project** configured ([GCP_SETUP.md](GCP_SETUP.md))
- **gcloud CLI** authenticated
- **Base Sepolia ETH** for agent wallet

---

## Step-by-Step Setup

### 1. Cambrian API Key

**Get API key from Cambrian Network:**

1. Visit: https://cambrian.network
2. Sign up for an account
3. Navigate to API section
4. Copy your API key

**Store in Secret Manager:**

```bash
echo -n "YOUR_CAMBRIAN_API_KEY" | gcloud secrets create CAMBRIAN_API_KEY \
  --data-file=- \
  --replication-policy=automatic

echo "✅ CAMBRIAN_API_KEY stored"
```

---

### 2. Agent Wallet (Private Key)

**Option A: Generate New Wallet (Recommended)**

```bash
# Install ethers.js CLI (if not installed)
npm install -g ethers

# Generate new wallet
ethers-wallet create
```

This outputs:
```
Private Key: 0xabcdef1234567890...
Address: 0x1234567890abcdef...
```

**Important**: Save the private key securely!

**Option B: Use Existing Wallet**

If you have an existing Metamask or hardware wallet:
1. Export private key (NEVER share this!)
2. Use the private key (starts with `0x`)

**Fund the Wallet:**

Get Base Sepolia testnet ETH:
- Faucet: https://faucet.quicknode.com/base/sepolia
- Need at least 0.001 ETH for gas + stakes

**Store in Secret Manager:**

```bash
# NEVER type your actual private key in terminal history!
# Use a temporary file instead:
echo -n "0xYOUR_PRIVATE_KEY" > /tmp/wallet.key

# Store in Secret Manager
gcloud secrets create SELLER_PRIVATE_KEY \
  --data-file=/tmp/wallet.key \
  --replication-policy=automatic

# Securely delete temporary file
shred -u /tmp/wallet.key 2>/dev/null || rm /tmp/wallet.key

echo "✅ SELLER_PRIVATE_KEY stored"
```

**Verify wallet balance:**

```bash
# Using cast (from foundry)
cast balance YOUR_ADDRESS --rpc-url https://sepolia.base.org

# Or check on BaseScan
# https://sepolia.basescan.org/address/YOUR_ADDRESS
```

---

### 3. RPC URL

**Free RPC Options:**

1. **Public Base Sepolia** (rate limited):
   ```
   https://sepolia.base.org
   ```

2. **DRPC** (recommended, higher rate limit):
   - Sign up: https://drpc.org
   - Get API key
   - Format: `https://lb.drpc.org/base-sepolia/YOUR_KEY`

3. **Alchemy** (generous free tier):
   - Sign up: https://alchemy.com
   - Create Base Sepolia app
   - Format: `https://base-sepolia.g.alchemy.com/v2/YOUR_KEY`

**Store in Secret Manager:**

```bash
echo -n "https://sepolia.base.org" | gcloud secrets create RPC_URL \
  --data-file=- \
  --replication-policy=automatic

echo "✅ RPC_URL stored"
```

---

### 4. Registry Address

**ProofRegistry Contract** (already deployed on Base Sepolia):

```
Address: 0x497f2f7081673236af8B2924E673FdDB7fAeF889
```

This contract is provided in the package at `contracts/ProofRegistry-deployment.json`.

**Store in Secret Manager:**

```bash
echo -n "0x497f2f7081673236af8B2924E673FdDB7fAeF889" | gcloud secrets create REGISTRY_ADDRESS \
  --data-file=- \
  --replication-policy=automatic

echo "✅ REGISTRY_ADDRESS stored"
```

**Verify contract on BaseScan:**
https://sepolia.basescan.org/address/0x497f2f7081673236af8B2924E673FdDB7fAeF889

---

### 5. Pinata API Keys

**Sign up for Pinata:**

1. Visit: https://pinata.cloud
2. Create free account (1GB storage + 100GB bandwidth)
3. Go to: https://app.pinata.cloud/keys
4. Click "New Key"
5. Select permissions:
   - ✅ `pinFileToIPFS`
   - ✅ `pinJSONToIPFS`
6. Create key
7. **Copy both API Key and API Secret immediately** (shown only once!)

**Store in Secret Manager:**

```bash
# API Key
echo -n "YOUR_PINATA_API_KEY" | gcloud secrets create PINATA_API_KEY \
  --data-file=- \
  --replication-policy=automatic

# API Secret
echo -n "YOUR_PINATA_SECRET_KEY" | gcloud secrets create PINATA_SECRET_KEY \
  --data-file=- \
  --replication-policy=automatic

echo "✅ PINATA_API_KEY and PINATA_SECRET_KEY stored"
```

---

### 6. Pinata Gateway Key (Optional)

**For faster evidence retrieval:**

1. Go to: https://app.pinata.cloud/gateway
2. Create dedicated gateway
3. Copy gateway URL (e.g., `https://YOUR_NAME.mypinata.cloud`)
4. Get gateway key from security settings

**Store in Secret Manager:**

```bash
echo -n "YOUR_GATEWAY_KEY" | gcloud secrets create PINATA_GATEWAY_KEY \
  --data-file=- \
  --replication-policy=automatic

echo "✅ PINATA_GATEWAY_KEY stored"
```

If you skip this, the agent will use the public gateway (`https://ipfs.io`).

---

## Automated Setup

Use the provided script to set up all secrets interactively:

```bash
cd scripts/
chmod +x deploy-secrets.sh
./deploy-secrets.sh
```

The script will:
1. Prompt for each secret value
2. Validate format (where applicable)
3. Store securely in Secret Manager
4. Verify storage

---

## Verification

### List All Secrets

```bash
gcloud secrets list --format="table(name,createTime)"
```

Expected output:
```
NAME                   CREATE_TIME
CAMBRIAN_API_KEY       2025-10-01T10:00:00
SELLER_PRIVATE_KEY     2025-10-01T10:01:00
RPC_URL                2025-10-01T10:02:00
REGISTRY_ADDRESS       2025-10-01T10:03:00
PINATA_API_KEY         2025-10-01T10:04:00
PINATA_SECRET_KEY      2025-10-01T10:05:00
PINATA_GATEWAY_KEY     2025-10-01T10:06:00
```

### Test Secret Access

```bash
# Test reading a secret (non-sensitive example)
gcloud secrets versions access latest --secret="RPC_URL"
```

Should output: `https://sepolia.base.org` (or your custom RPC)

**Note**: NEVER print sensitive secrets like private keys!

---

## Security Best Practices

### ✅ DO

1. **Use unique wallets** - Create new wallet per agent
2. **Rotate keys regularly** - Update secrets every 90 days
3. **Use least privilege** - TEE service account only needs `secretAccessor` role
4. **Monitor access** - Enable audit logging for Secret Manager
5. **Test with small amounts** - Start with minimal ETH on testnet

### ❌ DON'T

1. **Never commit secrets** - Check `.gitignore` includes `.env*`
2. **Never share private keys** - Each agent should have unique wallet
3. **Never reuse production keys** - Use separate keys for testnet/mainnet
4. **Never log secrets** - Sanitize logs before debugging
5. **Never store secrets in code** - Always use Secret Manager

---

## Secret Rotation

### Rotating a Secret

```bash
# Create new version of secret
echo -n "NEW_SECRET_VALUE" | gcloud secrets versions add SECRET_NAME \
  --data-file=-

# Disable old version (optional)
gcloud secrets versions disable VERSION_ID --secret=SECRET_NAME

echo "✅ Secret rotated"
```

### When to Rotate

- **SELLER_PRIVATE_KEY**: If compromised, rotate immediately
- **CAMBRIAN_API_KEY**: Every 90 days
- **PINATA_API_KEY**: Every 90 days
- **RPC_URL**: When changing providers

### After Rotation

Restart TEE agent to pick up new secrets:

```bash
# Get instance name
gcloud compute instances list --filter="labels.workload=full-tee-agent"

# Reset instance (forces container restart)
gcloud compute instances reset INSTANCE_NAME --zone=YOUR_ZONE
```

---

## Troubleshooting

### Error: "Secret already exists"

**Cause**: Secret with same name already created

**Solution**:
```bash
# Update existing secret instead
echo -n "NEW_VALUE" | gcloud secrets versions add SECRET_NAME --data-file=-
```

### Error: "Permission denied accessing secret"

**Cause**: TEE service account missing `secretAccessor` role

**Solution**:
```bash
export PROJECT_ID=$(gcloud config get-value project)
export SA_EMAIL="erc8004-tee-sa@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"
```

### Error: "Insufficient funds" in agent logs

**Cause**: Agent wallet doesn't have enough Base Sepolia ETH

**Solution**:
1. Check balance: https://sepolia.basescan.org/address/YOUR_ADDRESS
2. Get more from faucet: https://faucet.quicknode.com/base/sepolia
3. Need minimum 0.001 ETH for stakes + gas

### Warning: "IPFS upload failed"

**Cause**: Invalid Pinata API keys

**Solution**:
```bash
# Test Pinata API keys
curl -X POST https://api.pinata.cloud/pinning/pinJSONToIPFS \
  -H "pinata_api_key: YOUR_KEY" \
  -H "pinata_secret_api_key: YOUR_SECRET" \
  -d '{"pinataContent":{"test":"data"}}'

# Should return: {"IpfsHash":"Qm...","PinSize":...}
```

---

## Cost

Secret Manager pricing (as of 2025):

- **Storage**: $0.06 per secret version per month
- **Access**: $0.03 per 10,000 accesses

**Estimated cost for this setup**:
- 7 secrets × $0.06 = $0.42/month storage
- ~1000 accesses/month × $0.03/10,000 = ~$0.003/month access
- **Total**: ~$0.50/month

---

## Mainnet Secrets

For production deployment to Base mainnet:

1. **Create separate secrets** with `_MAINNET` suffix:
   - `SELLER_PRIVATE_KEY_MAINNET`
   - `RPC_URL_MAINNET`
   - `REGISTRY_ADDRESS_MAINNET`

2. **Use separate wallet** with real ETH (≥0.01 ETH)

3. **Update workflow** to use mainnet secrets when deploying

4. **Never reuse testnet keys** on mainnet!

---

## Next Steps

After configuring secrets:
1. ✅ Secrets stored in Secret Manager
2. ✅ Agent wallet funded with Base Sepolia ETH
3. ➡️ Deploy agent: [README.md](../README.md#step-4-deploy-to-github)

---

## Additional Resources

- [Secret Manager Best Practices](https://cloud.google.com/secret-manager/docs/best-practices)
- [Base Sepolia Faucet](https://faucet.quicknode.com/base/sepolia)
- [Pinata Documentation](https://docs.pinata.cloud)
- [Ethers.js Wallet Docs](https://docs.ethers.org/v6/api/wallet/)

---

**Last Updated**: 2025-10-01

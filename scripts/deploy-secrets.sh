#!/usr/bin/env bash
#
# Secret Manager Deployment Script
# Deploys all required secrets for ERC-8004 TEE agent
#
# Usage: ./deploy-secrets.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ERC-8004 TEE Agent - Secrets Deployment                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI not found${NC}"
    exit 1
fi

# Get current project
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}❌ No GCP project configured${NC}"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo -e "Project: ${BLUE}$PROJECT_ID${NC}"
echo ""

# Function to create or update secret
create_or_update_secret() {
    local name=$1
    local value=$2
    local description=$3

    echo -n "  Storing $name... "

    # Check if secret exists
    if gcloud secrets describe "$name" &> /dev/null; then
        # Update existing secret
        echo -n "$value" | gcloud secrets versions add "$name" \
            --data-file=- &> /dev/null
        echo -e "${GREEN}✅ Updated${NC}"
    else
        # Create new secret
        echo -n "$value" | gcloud secrets create "$name" \
            --data-file=- \
            --replication-policy=automatic &> /dev/null
        echo -e "${GREEN}✅ Created${NC}"
    fi
}

# Secret 1: CAMBRIAN_API_KEY
echo -e "${YELLOW}1. Cambrian API Key${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Get your API key from: https://cambrian.network"
read -p "Enter CAMBRIAN_API_KEY: " CAMBRIAN_API_KEY

if [ -z "$CAMBRIAN_API_KEY" ]; then
    echo -e "${RED}❌ Cannot be empty${NC}"
    exit 1
fi

create_or_update_secret "CAMBRIAN_API_KEY" "$CAMBRIAN_API_KEY" "Cambrian Network API key"

# Secret 2: SELLER_PRIVATE_KEY
echo ""
echo -e "${YELLOW}2. Agent Wallet Private Key${NC}"
echo "────────────────────────────────────────────────────────────────"
echo -e "${RED}⚠️  WARNING: Never share your private key!${NC}"
echo ""
echo "Generate new wallet: ethers-wallet create"
echo "Or use existing wallet private key (starts with 0x)"
echo ""
read -sp "Enter SELLER_PRIVATE_KEY (hidden): " SELLER_PRIVATE_KEY
echo ""

if [ -z "$SELLER_PRIVATE_KEY" ]; then
    echo -e "${RED}❌ Cannot be empty${NC}"
    exit 1
fi

# Validate format
if [[ ! "$SELLER_PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo -e "${YELLOW}⚠️  Warning: Private key format may be invalid (should be 0x + 64 hex chars)${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

create_or_update_secret "SELLER_PRIVATE_KEY" "$SELLER_PRIVATE_KEY" "Agent wallet private key"

# Secret 3: RPC_URL
echo ""
echo -e "${YELLOW}3. Base Sepolia RPC URL${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Options:"
echo "  - https://sepolia.base.org (public, rate limited)"
echo "  - https://lb.drpc.org/base-sepolia/YOUR_KEY (recommended)"
echo "  - https://base-sepolia.g.alchemy.com/v2/YOUR_KEY"
echo ""
read -p "Enter RPC_URL [https://sepolia.base.org]: " RPC_URL
RPC_URL=${RPC_URL:-https://sepolia.base.org}

create_or_update_secret "RPC_URL" "$RPC_URL" "Base Sepolia RPC endpoint"

# Secret 4: REGISTRY_ADDRESS
echo ""
echo -e "${YELLOW}4. ProofRegistry Contract Address${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Using deployed contract: 0x497f2f7081673236af8B2924E673FdDB7fAeF889"
echo ""
read -p "Use this address? (Y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    read -p "Enter custom REGISTRY_ADDRESS: " REGISTRY_ADDRESS
else
    REGISTRY_ADDRESS="0x497f2f7081673236af8B2924E673FdDB7fAeF889"
fi

create_or_update_secret "REGISTRY_ADDRESS" "$REGISTRY_ADDRESS" "ProofRegistry contract address"

# Secret 5: PINATA_API_KEY
echo ""
echo -e "${YELLOW}5. Pinata API Key${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Sign up at: https://pinata.cloud (free tier available)"
echo "Get keys from: https://app.pinata.cloud/keys"
echo ""
read -p "Enter PINATA_API_KEY: " PINATA_API_KEY

if [ -z "$PINATA_API_KEY" ]; then
    echo -e "${RED}❌ Cannot be empty${NC}"
    exit 1
fi

create_or_update_secret "PINATA_API_KEY" "$PINATA_API_KEY" "Pinata API key for IPFS"

# Secret 6: PINATA_SECRET_KEY
echo ""
echo -e "${YELLOW}6. Pinata Secret Key${NC}"
echo "────────────────────────────────────────────────────────────────"
read -sp "Enter PINATA_SECRET_KEY (hidden): " PINATA_SECRET_KEY
echo ""

if [ -z "$PINATA_SECRET_KEY" ]; then
    echo -e "${RED}❌ Cannot be empty${NC}"
    exit 1
fi

create_or_update_secret "PINATA_SECRET_KEY" "$PINATA_SECRET_KEY" "Pinata secret key"

# Secret 7: PINATA_GATEWAY_KEY (Optional)
echo ""
echo -e "${YELLOW}7. Pinata Gateway Key (Optional)${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "For faster evidence retrieval. Leave empty to skip."
echo ""
read -p "Enter PINATA_GATEWAY_KEY (or press Enter to skip): " PINATA_GATEWAY_KEY

if [ -n "$PINATA_GATEWAY_KEY" ]; then
    create_or_update_secret "PINATA_GATEWAY_KEY" "$PINATA_GATEWAY_KEY" "Pinata gateway key"
    echo -e "${GREEN}✅ PINATA_GATEWAY_KEY stored${NC}"
else
    echo "  Skipped (will use public IPFS gateway)"
fi

# Verification
echo ""
echo -e "${YELLOW}Verification${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Listing all secrets..."
gcloud secrets list --format="table(name,createTime)" --filter="name:CAMBRIAN OR name:SELLER OR name:RPC OR name:REGISTRY OR name:PINATA"

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Secrets Deployment Complete!                                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Secrets stored in Secret Manager:"
echo "  ✅ CAMBRIAN_API_KEY"
echo "  ✅ SELLER_PRIVATE_KEY"
echo "  ✅ RPC_URL"
echo "  ✅ REGISTRY_ADDRESS"
echo "  ✅ PINATA_API_KEY"
echo "  ✅ PINATA_SECRET_KEY"
if [ -n "$PINATA_GATEWAY_KEY" ]; then
    echo "  ✅ PINATA_GATEWAY_KEY"
fi
echo ""
echo -e "${YELLOW}Important Checks:${NC}"
echo ""
echo "1. Verify agent wallet is funded:"
echo "   Get Base Sepolia ETH from: https://faucet.quicknode.com/base/sepolia"
echo ""
echo "2. Test Pinata API keys:"
echo '   curl -X POST https://api.pinata.cloud/pinning/pinJSONToIPFS \'
echo '     -H "pinata_api_key: YOUR_KEY" \'
echo '     -H "pinata_secret_api_key: YOUR_SECRET" \'
echo '     -d '"'"'{"pinataContent":{"test":"data"}}'"'"
echo ""
echo "3. Verify RPC endpoint:"
echo "   curl -X POST $RPC_URL -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Add GitHub Actions secrets (see README.md)"
echo "2. Push code to GitHub"
echo "3. Workflow will auto-deploy TEE agent"
echo ""
echo -e "${RED}⚠️  Security Reminder:${NC}"
echo "  - Never commit .env files"
echo "  - Never share private keys"
echo "  - Rotate keys every 90 days"
echo ""

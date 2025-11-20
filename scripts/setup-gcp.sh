#!/usr/bin/env bash
#
# GCP Confidential Space Setup Script
# Automates GCP project configuration for ERC-8004 TEE agent
#
# Usage: ./setup-gcp.sh
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ERC-8004 TEE Agent - GCP Setup Script                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
echo "Checking prerequisites..."
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI not found. Please install: https://cloud.google.com/sdk/docs/install${NC}"
    exit 1
fi
echo -e "${GREEN}✅ gcloud CLI found${NC}"

# Step 1: Get or create project
echo ""
echo -e "${YELLOW}Step 1: GCP Project Setup${NC}"
echo "────────────────────────────────────────────────────────────────"
read -p "Enter your GCP Project ID (or press Enter to create new): " PROJECT_ID

if [ -z "$PROJECT_ID" ]; then
    read -p "Enter new Project ID (must be globally unique): " PROJECT_ID
    if [ -z "$PROJECT_ID" ]; then
        echo -e "${RED}❌ Project ID cannot be empty${NC}"
        exit 1
    fi

    echo "Creating project: $PROJECT_ID..."
    gcloud projects create "$PROJECT_ID" \
        --name="ERC-8004 TEE Agent" \
        --set-as-default || {
            echo -e "${RED}❌ Failed to create project. May already exist or name taken.${NC}"
            exit 1
        }

    echo -e "${YELLOW}⚠️  Link billing account manually at: https://console.cloud.google.com/billing${NC}"
    echo "Press Enter when billing is linked..."
    read
fi

# Set project
gcloud config set project "$PROJECT_ID"
echo -e "${GREEN}✅ Project set: $PROJECT_ID${NC}"

# Step 2: Enable APIs
echo ""
echo -e "${YELLOW}Step 2: Enabling Required APIs${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "This may take 1-2 minutes..."

APIS=(
    "compute.googleapis.com"
    "secretmanager.googleapis.com"
    "containerregistry.googleapis.com"
    "iam.googleapis.com"
    "cloudresourcemanager.googleapis.com"
)

for api in "${APIS[@]}"; do
    echo "Enabling $api..."
    gcloud services enable "$api" --quiet
done

echo -e "${GREEN}✅ All APIs enabled${NC}"

# Step 3: Create TEE service account
echo ""
echo -e "${YELLOW}Step 3: Creating TEE Service Account${NC}"
echo "────────────────────────────────────────────────────────────────"

SA_NAME="erc8004-tee-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "$SA_EMAIL" &> /dev/null; then
    echo "Service account already exists: $SA_EMAIL"
else
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="ERC-8004 TEE Agent Service Account" \
        --description="Service account for TEE agent to access secrets"
    echo -e "${GREEN}✅ TEE service account created: $SA_EMAIL${NC}"
fi

# Grant permissions to TEE service account
echo "Granting permissions to TEE service account..."
ROLES=(
    "roles/secretmanager.secretAccessor"
    "roles/logging.logWriter"
    "roles/monitoring.metricWriter"
)

for role in "${ROLES[@]}"; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="$role" \
        --quiet > /dev/null
done

echo -e "${GREEN}✅ TEE service account permissions configured${NC}"

# Step 4: Create deployment service account
echo ""
echo -e "${YELLOW}Step 4: Creating Deployment Service Account${NC}"
echo "────────────────────────────────────────────────────────────────"

DEPLOY_SA_NAME="erc8004-deploy-sa"
DEPLOY_SA_EMAIL="${DEPLOY_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "$DEPLOY_SA_EMAIL" &> /dev/null; then
    echo "Service account already exists: $DEPLOY_SA_EMAIL"
else
    gcloud iam service-accounts create "$DEPLOY_SA_NAME" \
        --display-name="ERC-8004 Deployment Service Account" \
        --description="Service account for GitHub Actions to deploy TEE agent"
    echo -e "${GREEN}✅ Deployment service account created: $DEPLOY_SA_EMAIL${NC}"
fi

# Grant permissions to deployment service account
echo "Granting permissions to deployment service account..."
DEPLOY_ROLES=(
    "roles/compute.instanceAdmin.v1"
    "roles/iam.serviceAccountUser"
    "roles/storage.admin"
    "roles/viewer"
)

for role in "${DEPLOY_ROLES[@]}"; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${DEPLOY_SA_EMAIL}" \
        --role="$role" \
        --quiet > /dev/null
done

echo -e "${GREEN}✅ Deployment service account permissions configured${NC}"

# Step 5: Download deployment key
echo ""
echo -e "${YELLOW}Step 5: Download Deployment Service Account Key${NC}"
echo "────────────────────────────────────────────────────────────────"

KEY_FILE="${HOME}/erc8004-deploy-key.json"

if [ -f "$KEY_FILE" ]; then
    echo -e "${YELLOW}⚠️  Key file already exists: $KEY_FILE${NC}"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping key download."
        KEY_FILE=""
    fi
fi

if [ -n "$KEY_FILE" ]; then
    gcloud iam service-accounts keys create "$KEY_FILE" \
        --iam-account="$DEPLOY_SA_EMAIL"
    echo -e "${GREEN}✅ Service account key downloaded to: $KEY_FILE${NC}"
fi

# Step 6: Create firewall rule
echo ""
echo -e "${YELLOW}Step 6: Creating Firewall Rule${NC}"
echo "────────────────────────────────────────────────────────────────"

FIREWALL_RULE="allow-tee-agent-http"

if gcloud compute firewall-rules describe "$FIREWALL_RULE" &> /dev/null; then
    echo "Firewall rule already exists: $FIREWALL_RULE"
else
    gcloud compute firewall-rules create "$FIREWALL_RULE" \
        --direction=INGRESS \
        --priority=1000 \
        --network=default \
        --action=ALLOW \
        --rules=tcp:8080 \
        --source-ranges=0.0.0.0/0 \
        --target-tags=tee-vm,full-tee \
        --description="Allow HTTP access to TEE agent on port 8080"
    echo -e "${GREEN}✅ Firewall rule created${NC}"
fi

# Step 7: Set default zone
echo ""
echo -e "${YELLOW}Step 7: Set Default Zone${NC}"
echo "────────────────────────────────────────────────────────────────"
echo "Recommended zones for Confidential Computing:"
echo "  - us-central1-a (Iowa, USA)"
echo "  - us-central1-b (Iowa, USA)"
echo "  - europe-west4-a (Netherlands)"
echo ""
read -p "Enter zone [us-central1-a]: " GCP_ZONE
GCP_ZONE=${GCP_ZONE:-us-central1-a}

gcloud config set compute/zone "$GCP_ZONE"
echo -e "${GREEN}✅ Default zone set: $GCP_ZONE${NC}"

# Step 8: Verify setup
echo ""
echo -e "${YELLOW}Step 8: Verifying Setup${NC}"
echo "────────────────────────────────────────────────────────────────"

echo "Testing service account access..."
if gcloud iam service-accounts get-iam-policy "$SA_EMAIL" &> /dev/null; then
    echo -e "${GREEN}✅ TEE service account accessible${NC}"
fi

echo "Testing compute permissions..."
if gcloud compute instances list --limit=1 &> /dev/null; then
    echo -e "${GREEN}✅ Compute Engine permissions OK${NC}"
fi

echo "Testing secret manager..."
if gcloud secrets list --limit=1 &> /dev/null; then
    echo -e "${GREEN}✅ Secret Manager permissions OK${NC}"
fi

# Summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  GCP Setup Complete!                                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Configuration Summary:"
echo "────────────────────────────────────────────────────────────────"
echo "Project ID:          $PROJECT_ID"
echo "Zone:                $GCP_ZONE"
echo "TEE Service Account: $SA_EMAIL"
echo "Deploy Account:      $DEPLOY_SA_EMAIL"
if [ -n "$KEY_FILE" ]; then
    echo "Deploy Key File:     $KEY_FILE"
fi
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Add GitHub Secrets:"
echo "   - GCP_DEPLOY_SA: Contents of $KEY_FILE"
echo "   - GCP_PROJECT_ID: $PROJECT_ID"
echo "   - GCP_ZONE: $GCP_ZONE"
echo ""
echo "2. Configure secrets:"
echo "   ./scripts/deploy-secrets.sh"
echo ""
echo "3. Deploy agent:"
echo "   Push to GitHub → Workflow auto-deploys"
echo ""
if [ -n "$KEY_FILE" ]; then
    echo -e "${RED}⚠️  IMPORTANT: Delete the service account key after uploading to GitHub!${NC}"
    echo "   shred -u $KEY_FILE"
fi
echo ""

# GCP Confidential Space Setup Guide

Complete guide for setting up Google Cloud Platform to run your ERC-8004 TEE agent.

---

## Prerequisites

- **Google Cloud account** with billing enabled
- **gcloud CLI** installed ([installation guide](https://cloud.google.com/sdk/docs/install))
- **Project owner** or **editor** permissions

---

## Step 1: Create or Select GCP Project

### Option A: Create New Project

```bash
# Set your project ID (must be globally unique)
export PROJECT_ID="erc8004-tee-agent"

# Create project
gcloud projects create $PROJECT_ID \
  --name="ERC-8004 TEE Agent" \
  --set-as-default

# Link billing account (replace with your billing account ID)
gcloud beta billing projects link $PROJECT_ID \
  --billing-account=YOUR_BILLING_ACCOUNT_ID
```

### Option B: Use Existing Project

```bash
export PROJECT_ID="your-existing-project-id"
gcloud config set project $PROJECT_ID
```

---

## Step 2: Enable Required APIs

```bash
# Enable Compute Engine (for VM instances)
gcloud services enable compute.googleapis.com

# Enable Secret Manager (for credential storage)
gcloud services enable secretmanager.googleapis.com

# Enable Container Registry (for Docker images)
gcloud services enable containerregistry.googleapis.com

# Enable IAM (for service accounts)
gcloud services enable iam.googleapis.com

# Enable Resource Manager (for project management)
gcloud services enable cloudresourcemanager.googleapis.com

echo "✅ All required APIs enabled"
```

**Note**: API enablement can take 1-2 minutes.

---

## Step 3: Create Service Account for TEE

This service account will:
- Run inside the TEE VM
- Access Secret Manager for credentials
- Submit proofs to blockchain

```bash
# Create service account
gcloud iam service-accounts create erc8004-tee-sa \
  --display-name="ERC-8004 TEE Agent Service Account" \
  --description="Service account for TEE agent to access secrets and blockchain"

# Get service account email
export SA_EMAIL="erc8004-tee-sa@${PROJECT_ID}.iam.gserviceaccount.com"

echo "✅ Service account created: $SA_EMAIL"
```

### Grant Permissions to TEE Service Account

```bash
# Secret Manager Secret Accessor (read secrets)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor"

# Logging Writer (write logs)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/logging.logWriter"

# Monitoring Metric Writer (write metrics)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/monitoring.metricWriter"

echo "✅ TEE service account permissions configured"
```

---

## Step 4: Create Deployment Service Account (for GitHub Actions)

This service account will:
- Deploy VM instances from GitHub Actions
- Push Docker images to GCR
- Manage compute resources

```bash
# Create deployment service account
gcloud iam service-accounts create erc8004-deploy-sa \
  --display-name="ERC-8004 Deployment Service Account" \
  --description="Service account for GitHub Actions to deploy TEE agent"

# Get deployment service account email
export DEPLOY_SA_EMAIL="erc8004-deploy-sa@${PROJECT_ID}.iam.gserviceaccount.com"

echo "✅ Deployment service account created: $DEPLOY_SA_EMAIL"
```

### Grant Permissions to Deployment Service Account

```bash
# Compute Instance Admin (create/delete VMs)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${DEPLOY_SA_EMAIL}" \
  --role="roles/compute.instanceAdmin.v1"

# Service Account User (use TEE service account)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${DEPLOY_SA_EMAIL}" \
  --role="roles/iam.serviceAccountUser"

# Storage Admin (push Docker images to GCR)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${DEPLOY_SA_EMAIL}" \
  --role="roles/storage.admin"

# Viewer (read project metadata)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${DEPLOY_SA_EMAIL}" \
  --role="roles/viewer"

echo "✅ Deployment service account permissions configured"
```

---

## Step 5: Download Deployment Service Account Key

This key will be used as `GCP_DEPLOY_SA` GitHub Secret.

```bash
# Create and download key
gcloud iam service-accounts keys create ~/erc8004-deploy-key.json \
  --iam-account=$DEPLOY_SA_EMAIL

echo "✅ Service account key downloaded to: ~/erc8004-deploy-key.json"
echo ""
echo "⚠️  IMPORTANT: Keep this file secure!"
echo "   - Add it as GitHub Secret: GCP_DEPLOY_SA"
echo "   - Delete the local file after uploading to GitHub"
echo "   - Never commit this file to git"
```

---

## Step 6: Create Firewall Rules

Allow external access to TEE agent HTTP endpoints.

```bash
# Allow HTTP traffic on port 8080
gcloud compute firewall-rules create allow-tee-agent-http \
  --direction=INGRESS \
  --priority=1000 \
  --network=default \
  --action=ALLOW \
  --rules=tcp:8080 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=tee-vm,full-tee \
  --description="Allow HTTP access to TEE agent on port 8080"

echo "✅ Firewall rule created"
```

---

## Step 7: Set Default Zone

Choose a zone that supports Confidential Computing (N2D machines).

Recommended zones:
- `us-central1-a` (Iowa, USA)
- `us-central1-b` (Iowa, USA)
- `us-central1-c` (Iowa, USA)
- `europe-west4-a` (Netherlands)
- `europe-west4-b` (Netherlands)

```bash
# Set your preferred zone
export GCP_ZONE="us-central1-a"
gcloud config set compute/zone $GCP_ZONE

echo "✅ Default zone set to: $GCP_ZONE"
```

---

## Step 8: Verify Confidential Space Image

Check that the Confidential Space image is available in your zone.

```bash
gcloud compute images list \
  --project=confidential-space-images \
  --filter="name:confidential-space" \
  --format="table(name,family,status)"
```

Expected output:
```
NAME                        FAMILY               STATUS
confidential-space-250101   confidential-space   READY
```

---

## Step 9: GitHub Actions Configuration

Now configure GitHub repository secrets:

### Add GitHub Secrets

Go to your GitHub repository → Settings → Secrets and variables → Actions → New repository secret

Add these 3 secrets:

1. **Name**: `GCP_DEPLOY_SA`
   - **Value**: Contents of `~/erc8004-deploy-key.json` (entire JSON file)
   - Open file: `cat ~/erc8004-deploy-key.json`
   - Copy all text including `{` and `}`

2. **Name**: `GCP_PROJECT_ID`
   - **Value**: Your project ID (e.g., `erc8004-tee-agent`)

3. **Name**: `GCP_ZONE`
   - **Value**: Your deployment zone (e.g., `us-central1-a`)

---

## Step 10: Clean Up Local Files

After adding secrets to GitHub, remove the local service account key:

```bash
# Securely delete the key file
shred -u ~/erc8004-deploy-key.json 2>/dev/null || rm ~/erc8004-deploy-key.json

echo "✅ Local service account key deleted"
```

---

## Verification

Test that everything is configured correctly:

```bash
# Test service account access
gcloud iam service-accounts get-iam-policy $SA_EMAIL

# Test compute permissions
gcloud compute instances list --limit=1

# Test secret manager access
gcloud secrets list --limit=1

echo "✅ GCP setup complete!"
```

---

## Cost Estimation

### VM Costs (per month, us-central1):

- **n2d-standard-2** (2 vCPU, 8GB RAM): ~$50-70/month
- **15GB boot disk**: ~$2/month
- **External IP**: ~$3/month
- **Egress**: Variable (depends on traffic)

**Total**: ~$55-75/month per agent

### Cost Optimization Tips

1. **Stop VMs when not in use**:
   ```bash
   gcloud compute instances stop INSTANCE_NAME --zone=$GCP_ZONE
   ```

2. **Use preemptible VMs** for non-production:
   - Add `--preemptible` flag to instance creation
   - ~70% cost reduction
   - Can be terminated any time

3. **Use smaller machine types** for testing:
   - `e2-micro` (free tier eligible): 2 vCPU, 1GB RAM
   - Not Confidential Computing compatible, but good for testing

---

## Troubleshooting

### Error: "Permission denied"

**Cause**: Service account missing required permissions

**Solution**:
```bash
# Re-run IAM binding commands from Step 3 and Step 4
```

### Error: "Quota exceeded"

**Cause**: New GCP projects have limited quotas

**Solution**:
1. Go to: https://console.cloud.google.com/iam-admin/quotas
2. Search for "Compute Engine API"
3. Request quota increase for:
   - `CPUs` (need at least 2 for n2d-standard-2)
   - `In-use IP addresses` (need at least 1)

### Error: "Image not found: confidential-space-250101"

**Cause**: Image not available in your zone

**Solution**:
```bash
# Try a different zone
gcloud config set compute/zone us-central1-b

# Or wait for image propagation (can take 24 hours for new projects)
```

### Error: "Billing account not active"

**Cause**: Billing not enabled for project

**Solution**:
1. Go to: https://console.cloud.google.com/billing
2. Link a billing account to your project
3. Verify payment method is valid

---

## Next Steps

After completing GCP setup:
1. ✅ GCP project configured
2. ➡️ Configure secrets: [SECRETS_SETUP.md](SECRETS_SETUP.md)
3. ➡️ Deploy agent: [README.md](../README.md#step-4-deploy-to-github)

---

## Automated Setup Script

For convenience, you can use the automated setup script:

```bash
cd scripts/
chmod +x setup-gcp.sh
./setup-gcp.sh
```

This script automates Steps 1-8 above.

---

## Additional Resources

- [GCP Confidential Computing Docs](https://cloud.google.com/confidential-computing)
- [Confidential Space Documentation](https://cloud.google.com/confidential-computing/confidential-space/docs)
- [Service Account Best Practices](https://cloud.google.com/iam/docs/best-practices-service-accounts)
- [Secret Manager Documentation](https://cloud.google.com/secret-manager/docs)

---

**Last Updated**: 2025-10-01

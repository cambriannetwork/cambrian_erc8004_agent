# Deployment Updates Summary

**Date**: 2025-10-01
**Repo**: https://github.com/cambriannetwork/cambrian_erc8004_agent

---

## What Was Changed

### 1. Fixed File Paths

The GitHub Actions workflow was updated to reflect the new folder structure:

**Before** (old paths):
```
cambrian-defi-data-agent.js
ipfs-storage.js
package.json
deployment/confidential-space/**
```

**After** (new paths):
```
agent/cambrian-defi-data-agent.js
agent/ipfs-storage.js
agent/package.json
deployment/**
```

### 2. Added Static IP Support

**Before**: Instance got new random IP on each deployment
**After**: Creates/reuses a static IP address

**Benefits**:
- Stable endpoint URL
- No need to update DNS records
- Easier monitoring and access control

**Static IP Name**: `cambrian-tee-agent-ip`

### 3. Changed Deployment Strategy

**Before**: Created new instance with timestamped name (e.g., `erc8004-full-tee-20251001185135`)
**After**: Fixed instance name that gets updated on each deployment

**Instance Name**: `cambrian-tee-agent-prod`

**New Workflow**:
1. Check if instance exists → Delete it
2. Create/reuse static IP
3. Create new instance with same name and static IP
4. Deploy latest container

### 4. Removed npm Cache Dependency Path Issue

**Before**: Workflow failed with `package-lock.json` not found error
**After**: Correctly points to `agent/package-lock.json`

---

## Updated Workflow Configuration

```yaml
env:
  SERVICE_NAME: cambrian-agent-full-tee
  INSTANCE_NAME: cambrian-tee-agent-prod  # Fixed name
  STATIC_IP_NAME: cambrian-tee-agent-ip   # Static IP name
  CHAIN_ID: 84532  # Base Sepolia
```

---

## Deployment Flow

```
Push to main (agent/ or deployment/ changes)
  ↓
Build & Validate
  - Test Go compilation
  - Test Node.js syntax
  - Test Docker build
  ↓
Build Docker Image
  - Multi-stage build with source verification
  - Push to GCR
  ↓
Create/Get Static IP
  - If exists: reuse
  - If not: create new
  ↓
Delete Old Instance (if exists)
  - Clean slate for new deployment
  ↓
Deploy New Instance
  - Same name: cambrian-tee-agent-prod
  - Same IP: (static)
  - New container: latest build
  ↓
Health Check & Verification
  - Wait for agent to start
  - Test health endpoint
  - Generate test proof
  - Verify new features (HTTP logs, DNS, source hashes)
```

---

## What Stays the Same

✅ **Existing deployment will be overwritten** (not duplicated)
✅ **Same GCP project and resources**
✅ **Same secrets from Secret Manager**
✅ **Same service account** (`erc8004-tee-sa`)
✅ **Same security level** (MAXIMUM - Full TEE with AMD SEV)
✅ **Same contract addresses** (Base Sepolia)

---

## Static IP Details

Once created, the static IP will persist across deployments:

**To view**:
```bash
gcloud compute addresses list
```

**To get IP**:
```bash
gcloud compute addresses describe cambrian-tee-agent-ip \
  --region=us-central1 \
  --format='get(address)'
```

**Cost**: ~$3/month (reserved static IP)

---

## Current vs New Deployment

### Current Deployment (will be replaced)
- **Instance**: `erc8004-full-tee-20251001185135`
- **IP**: `34.59.117.186` (ephemeral)
- **Status**: Will be deleted on next deployment

### New Deployment (after workflow runs)
- **Instance**: `cambrian-tee-agent-prod` (fixed name)
- **IP**: `[Static IP]` (persistent, will be shown in workflow output)
- **Status**: Updates in-place on future deployments

---

## GitHub Actions Secrets (Already Configured)

✅ `GCP_DEPLOY_SA` - Service account JSON
✅ `GCP_PROJECT_ID` - Your GCP project ID
✅ `GCP_ZONE` - Deployment zone

---

## GCP Secret Manager Secrets (Already Configured)

The workflow fetches these from Secret Manager at runtime:

✅ `CAMBRIAN_API_KEY`
✅ `SELLER_PRIVATE_KEY`
✅ `RPC_URL`
✅ `REGISTRY_ADDRESS`
✅ `PINATA_API_KEY`
✅ `PINATA_SECRET_KEY`
✅ `PINATA_GATEWAY_KEY`

---

## How to Deploy

### Automatic Deployment

Push changes to `main` branch:

```bash
cd /Users/riccardoesclapon/Documents/github/cambrian_erc8004_agent

# Make your changes, then:
git add .
git commit -m "Update agent configuration"
git push origin main
```

The workflow will automatically:
1. Build new container
2. Delete old instance
3. Create new instance with static IP
4. Deploy and verify

### Manual Deployment

Trigger via GitHub Actions:
1. Go to: https://github.com/cambriannetwork/cambrian_erc8004_agent/actions
2. Click "Deploy Full TEE Agent"
3. Click "Run workflow"
4. Select branch: `main`
5. Click "Run workflow"

---

## Finding Your Static IP

After the workflow completes:

1. **Check GitHub Actions output**:
   - Go to: Actions → Latest run → "deploy-full-tee" job
   - Look for: `✅ Static IP created: X.X.X.X`

2. **Check GCP Console**:
   - Go to: https://console.cloud.google.com/networking/addresses
   - Find: `cambrian-tee-agent-ip`

3. **Use gcloud CLI**:
   ```bash
   gcloud compute addresses describe cambrian-tee-agent-ip \
     --region=us-central1 \
     --format='get(address)'
   ```

---

## Testing After Deployment

Once deployment completes, test with the static IP:

```bash
# Health check
curl http://STATIC_IP:8080/health

# Generate proof
curl -X POST http://STATIC_IP:8080/api/price-current \
  -H "Content-Type: application/json" \
  -d '{"token_address":"So11111111111111111111111111111111111111112"}'
```

---

## Rollback (if needed)

If something goes wrong:

1. **Rollback container**:
   ```bash
   # List previous images
   gcloud container images list-tags \
     gcr.io/PROJECT_ID/cambrian-agent-full-tee

   # Use specific tag
   # Update metadata with old image SHA
   ```

2. **Delete and recreate**:
   ```bash
   # Delete instance
   gcloud compute instances delete cambrian-tee-agent-prod \
     --zone=us-central1-a

   # Re-run workflow
   ```

3. **Keep static IP**: The static IP will persist even if instance is deleted

---

## Cost Impact

### Before
- VM: ~$50-70/month
- Ephemeral IP: $0/month (included)
- **Total**: ~$50-70/month

### After
- VM: ~$50-70/month (same)
- Static IP: ~$3/month
- **Total**: ~$53-73/month

**Difference**: +$3/month for static IP convenience

---

## Next Steps

1. ✅ Workflow file updated
2. ➡️ **Commit and push changes**
3. ➡️ **Monitor GitHub Actions**
4. ➡️ **Update documentation with static IP**
5. ➡️ **Test new deployment**

---

## Files Modified

- `.github/workflows/deploy-tee.yaml` - Updated all paths and added static IP logic

---

**Ready to deploy!**

Just commit and push to trigger the workflow.

#!/bin/bash
set -e

# Deploy DeFi Data Agent to Cloud Run
# Usage: ./scripts/deploy-cloud-run.sh

echo "🚀 Deploying Cambrian DeFi Data Agent to Cloud Run..."

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-cambrian-agents}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="erc8004-cambrian-defi-data"

# Check required environment variables
if [ -z "$GCP_PROJECT_ID" ]; then
  echo "❌ Error: GCP_PROJECT_ID environment variable not set"
  echo "   Set it with: export GCP_PROJECT_ID=your-project-id"
  exit 1
fi

# Confirm deployment
echo ""
echo "Configuration:"
echo "  Project: $PROJECT_ID"
echo "  Region: $REGION"
echo "  Service: $SERVICE_NAME"
echo ""
read -p "Continue with deployment? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Deployment cancelled"
  exit 0
fi

# Navigate to agent directory
cd "$(dirname "$0")/../agent"

echo ""
echo "📦 Step 1: Building application..."

# Create temporary Dockerfile
cat > Dockerfile.cloudrun <<'EOF'
FROM node:18-slim

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev --legacy-peer-deps --no-audit --no-fund

# Copy application code
COPY cambrian-defi-data-agent.js .
COPY ipfs-storage.js .

# Expose port
EXPOSE 8080

# Set environment variable for port
ENV PORT=8080
ENV NODE_ENV=production

# Start the agent
CMD ["node", "cambrian-defi-data-agent.js"]
EOF

echo ""
echo "🐳 Step 2: Building and deploying with Cloud Run..."

gcloud run deploy $SERVICE_NAME \
  --source . \
  --dockerfile Dockerfile.cloudrun \
  --region $REGION \
  --platform managed \
  --allow-unauthenticated \
  --memory 1Gi \
  --cpu 1 \
  --timeout 300 \
  --max-instances 10 \
  --min-instances 0 \
  --port 8080 \
  --set-env-vars="NODE_ENV=production,PORT=8080,BYPASS_PAYMENT=true" \
  --set-secrets="CAMBRIAN_API_KEY=CAMBRIAN_API_KEY:latest,AGENT_PRIVATE_KEY=CAMBRIAN_AGENT_PRIVATE_KEY:latest,BASE_SEPOLIA_RPC=BASE_SEPOLIA_RPC:latest,PINATA_API_KEY=PINATA_API_KEY:latest,PINATA_SECRET_KEY=PINATA_SECRET_KEY:latest"

# Clean up
rm -f Dockerfile.cloudrun

echo ""
echo "🧪 Step 3: Testing deployment..."

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
  --region $REGION \
  --format 'value(status.url)')

echo "   Service URL: $SERVICE_URL"

# Test health endpoint
echo "   Testing health endpoint..."
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health")

if [ "$HEALTH_STATUS" = "200" ]; then
  echo "   ✅ Health check passed"
else
  echo "   ❌ Health check failed (status: $HEALTH_STATUS)"
  exit 1
fi

echo ""
echo "✅ Deployment successful!"
echo ""
echo "📍 Service URL: $SERVICE_URL"
echo ""
echo "🔗 Endpoints:"
echo "   Health:        $SERVICE_URL/health"
echo "   Agent Card:    $SERVICE_URL/.well-known/agent-card.json"
echo "   Price Current: $SERVICE_URL/api/price-current"
echo "   Price Multi:   $SERVICE_URL/api/price-multi"
echo ""
echo "🧪 Test command:"
echo "   curl -X POST $SERVICE_URL/api/price-current \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"token_address\":\"So11111111111111111111111111111111111111112\"}'"
echo ""

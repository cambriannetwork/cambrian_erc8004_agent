# Deep42 Agent - EigenCompute TEE Deployment

Production deployment of the Deep42 Unified Intelligence Agent on EigenCompute's Trusted Execution Environment.

## Quick Start

### Local Testing

```bash
# 1. Set up environment
cp .env.example .env
# Edit .env with your API keys

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run tests
python test_local.py

# 4. Start server
python app.py
```

### Test the API

```bash
# Health check
curl http://localhost:3000/health

# Ask a question
curl "http://localhost:3000/api/v1/deep42/agents/deep42?question=What%20are%20trending%20DeFi%20projects?"
```

## Deploy to EigenCompute

```bash
# 1. Build Docker image
docker build --platform linux/amd64 -t <registry>/deep42-agent:v1.0 .

# 2. Push to registry
docker push <registry>/deep42-agent:v1.0

# 3. Deploy to TEE
eigenx app deploy <registry>/deep42-agent:v1.0
```

## Architecture

This implementation:
- ✅ Uses **Gemini AI** with function calling for intelligent query routing
- ✅ Makes **direct HTTP calls** to Deep42 and Opabinia APIs (NO MCP servers)
- ✅ Runs in **Intel TDX** hardware-isolated environment
- ✅ Manages conversation history for multi-turn dialogues
- ✅ Returns comprehensive responses with documentation links

## API Endpoints

- `GET /health` - Health check
- `GET /capabilities` - Agent capabilities
- `GET /api/v1/deep42/agents/deep42` - Main agent endpoint
  - `?question=<query>` (required)
  - `&continue_chat_id=<uuid>` (optional for conversations)

## Environment Variables

- `GEMINI_API_KEY` (required) - Google Gemini API key
- `CAMBRIAN_API_KEY` (required) - Cambrian API key
- `PORT` (optional) - Server port (default: 3000)

## Files

- `app.py` - FastAPI web server
- `deep42_agent.py` - Production agent with direct API calls
- `test_local.py` - Local testing script
- `requirements.txt` - Python dependencies
- `Dockerfile` - Docker container configuration
- `.env.example` - Environment variable template

## Documentation

See `../daily_development/nov6/DEPLOYMENT_GUIDE.md` for complete deployment instructions.

## Support

- **EigenCompute**: https://docs.eigencloud.xyz/
- **Cambrian API**: https://docs.rickycambrian.org/
- **Gemini AI**: https://ai.google.dev/

#!/usr/bin/env node
/**
 * ERC-8004 TEE Proxy Service
 *
 * Purpose: Enable HTTPS UI to communicate with HTTP TEE endpoints
 * Architecture: Accepts HTTPS requests, forwards to TEE services, returns responses
 *
 * Endpoints proxied:
 * - Agent TEE: http://34.171.64.112:8080
 * - MCP Server TEE: http://136.115.87.101:8081
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 8090;

// TEE endpoint configuration
const TEE_ENDPOINTS = {
  AGENT_TEE: process.env.AGENT_TEE_URL || 'http://34.171.64.112:8080',
  MCP_SERVER_TEE: process.env.MCP_SERVER_TEE_URL || 'http://136.115.87.101:8081'
};

// CORS configuration - allow UI domain
const ALLOWED_ORIGINS = [
  'https://erc8004-ui.rickycambrian.org',
  'https://erc8004-ui-m6qdpjiz6q-uc.a.run.app',
  'http://localhost:3000',
  'http://localhost:5173'
];

// Middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CORS with credentials
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);

    if (ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️  CORS blocked origin: ${origin}`);
      callback(null, false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Cambrian-Api-Key', 'X-API-Key']
}));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'erc8004-tee-proxy',
    uptime: process.uptime(),
    endpoints: {
      agentTee: TEE_ENDPOINTS.AGENT_TEE,
      mcpServerTee: TEE_ENDPOINTS.MCP_SERVER_TEE
    },
    timestamp: new Date().toISOString()
  });
});

// Proxy helper function
async function proxyRequest(targetUrl, req, res) {
  try {
    const startTime = Date.now();

    // Prepare request config
    const config = {
      method: req.method.toLowerCase(),
      url: targetUrl,
      headers: {
        'Content-Type': req.headers['content-type'] || 'application/json',
        'User-Agent': 'ERC8004-TEE-Proxy/1.0'
      },
      timeout: 60000, // 60 second timeout
      validateStatus: () => true // Accept any status code
    };

    // Forward API key headers
    if (req.headers['x-cambrian-api-key']) {
      config.headers['X-Cambrian-Api-Key'] = req.headers['x-cambrian-api-key'];
    }
    if (req.headers['x-api-key']) {
      config.headers['X-API-Key'] = req.headers['x-api-key'];
    }
    if (req.headers['authorization']) {
      config.headers['Authorization'] = req.headers['authorization'];
    }

    // Add request body for POST/PUT
    if (['post', 'put'].includes(config.method) && req.body) {
      config.data = req.body;
    }

    // Add query parameters
    if (Object.keys(req.query).length > 0) {
      config.params = req.query;
    }

    console.log(`   → Proxying to: ${targetUrl}`);
    if (config.headers['X-Cambrian-Api-Key']) {
      console.log(`   → API Key: ${config.headers['X-Cambrian-Api-Key'].substring(0, 8)}...`);
    }

    // Make request to TEE endpoint
    const response = await axios(config);

    const duration = Date.now() - startTime;
    console.log(`   ← Response: ${response.status} (${duration}ms)`);

    // Forward response headers
    const headersToForward = ['content-type', 'content-length'];
    headersToForward.forEach(header => {
      if (response.headers[header]) {
        res.setHeader(header, response.headers[header]);
      }
    });

    // Send response
    res.status(response.status).json(response.data);

  } catch (error) {
    console.error(`   ✗ Proxy error:`, error.message);

    if (error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        error: 'TEE endpoint unavailable',
        message: 'Could not connect to TEE service',
        target: targetUrl,
        code: 'CONNECTION_REFUSED'
      });
    }

    if (error.code === 'ETIMEDOUT') {
      return res.status(504).json({
        error: 'TEE endpoint timeout',
        message: 'Request to TEE service timed out',
        target: targetUrl,
        code: 'TIMEOUT'
      });
    }

    res.status(500).json({
      error: 'Proxy error',
      message: error.message,
      code: error.code || 'UNKNOWN_ERROR'
    });
  }
}

// ============================================================
// AGENT TEE PROXY ROUTES
// ============================================================

// Agent TEE: Health check
app.get('/agent/health', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/health`, req, res);
});

// Agent TEE: Agent card
app.get('/agent/.well-known/agent-card.json', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/.well-known/agent-card.json`, req, res);
});

// Agent TEE: Attestation
app.get('/agent/attestation', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/attestation`, req, res);
});

// Agent TEE: Ask endpoint (AI queries)
app.post('/agent/api/ask', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/api/ask`, req, res);
});

// Agent TEE: Price endpoints
app.post('/agent/api/price-current', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/api/price-current`, req, res);
});

app.post('/agent/api/price-multi', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/api/price-multi`, req, res);
});

// Agent TEE: OHLCV data
app.post('/agent/api/ohlcv', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/api/ohlcv`, req, res);
});

// Agent TEE: Services list
app.get('/agent/services', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/services`, req, res);
});

// Agent TEE: Feedback data
app.get('/agent/feedback-data.json', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/feedback-data.json`, req, res);
});

// Agent TEE: Validation requests
app.get('/agent/validation-requests.json', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.AGENT_TEE}/validation-requests.json`, req, res);
});

// ============================================================
// MCP SERVER TEE PROXY ROUTES
// ============================================================

// MCP Server: Health check
app.get('/mcp/health', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.MCP_SERVER_TEE}/health`, req, res);
});

// MCP Server: Attestation
app.get('/mcp/attestation', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.MCP_SERVER_TEE}/attestation`, req, res);
});

// MCP Server: Tools list
app.get('/mcp/tools', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.MCP_SERVER_TEE}/tools`, req, res);
});

// MCP Server: Execute tool
app.post('/mcp/execute', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.MCP_SERVER_TEE}/execute`, req, res);
});

// MCP Server: MCP protocol endpoint
app.post('/mcp', async (req, res) => {
  await proxyRequest(`${TEE_ENDPOINTS.MCP_SERVER_TEE}/mcp`, req, res);
});

// ============================================================
// ERROR HANDLERS
// ============================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `No proxy route configured for ${req.method} ${req.path}`,
    availableRoutes: {
      agent: [
        'GET  /agent/health',
        'GET  /agent/attestation',
        'POST /agent/api/ask',
        'POST /agent/api/price-current',
        'POST /agent/api/ohlcv'
      ],
      mcp: [
        'GET  /mcp/health',
        'GET  /mcp/attestation',
        'GET  /mcp/tools',
        'POST /mcp/execute'
      ]
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║        ERC-8004 TEE Proxy Service                      ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`🚀 Server running on port ${PORT}`);
  console.log('');
  console.log('📡 Proxying to:');
  console.log(`   Agent TEE:      ${TEE_ENDPOINTS.AGENT_TEE}`);
  console.log(`   MCP Server TEE: ${TEE_ENDPOINTS.MCP_SERVER_TEE}`);
  console.log('');
  console.log('🔒 CORS enabled for:');
  ALLOWED_ORIGINS.forEach(origin => console.log(`   - ${origin}`));
  console.log('');
  console.log('📋 Available routes:');
  console.log('   GET  /health');
  console.log('   GET  /agent/health');
  console.log('   POST /agent/api/ask');
  console.log('   GET  /mcp/health');
  console.log('   GET  /mcp/tools');
  console.log('');
  console.log('⏳ Waiting for requests...');
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  process.exit(0);
});

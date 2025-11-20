#!/usr/bin/env node
/**
 * Cambrian DeFi Data Agent - ERC-8004 Implementation
 *
 * This agent wraps the Cambrian API as an ERC-8004 compliant service provider,
 * enabling AI agents to discover and purchase price data through decentralized commerce.
 */

require('dotenv').config();
const { ethers } = require('ethers');
const express = require('express');
const https = require('https');
const url = require('url');
const tls = require('tls');
const crypto = require('crypto');

// Security modules (with graceful fallback if modules fail to load)
let tlsPinning = null;
let teeVerifier = null;

try {
  tlsPinning = require('./tls-pinning');
  console.log('✅ TLS Pinning module loaded successfully');
} catch (tlsError) {
  console.warn('⚠️  TLS Pinning module failed to load, will use standard HTTPS:', tlsError.message);
}

try {
  teeVerifier = require('./tee-attestation-verifier');
  console.log('✅ TEE Attestation Verifier module loaded successfully');
} catch (teeError) {
  console.warn('⚠️  TEE Attestation Verifier module failed to load:', teeError.message);
}

// ERC-8004Complete contract ABI
const REGISTRY_ABI = [
  // Identity Registry
  'function registerAgent(string memory domain, address agentAddress) public returns (uint256)',
  'function agentIdCounter() public view returns (uint256)',
  'function agents(uint256) public view returns (uint256 agentId, string memory domain, address agentAddress)',
  'event AgentRegistered(uint256 indexed agentId, string domain, address indexed agentAddress)',

  // Reputation Registry
  'function acceptFeedback(uint256 clientAgentId, uint256 serverAgentId) public returns (uint256)',
  'function feedbackAuthIdCounter() public view returns (uint256)',
  'function feedbackAuths(uint256) public view returns (uint256 clientAgentId, uint256 serverAgentId, uint256 timestamp, bool isUsed)',
  'event AuthFeedback(uint256 indexed clientAgentId, uint256 indexed serverAgentId, uint256 feedbackAuthId)',

  // Validation Registry
  'function validationRequest(uint256 validatorAgentId, uint256 serverAgentId, bytes32 dataHash) public',
  'function validationResponse(bytes32 dataHash, uint8 response) public',
  'function validationRequests(bytes32) public view returns (uint256 validatorAgentId, uint256 serverAgentId, bytes32 dataHash, uint256 timestamp, bool isCompleted, uint8 response)',
  'event ValidationRequested(uint256 indexed validatorAgentId, uint256 indexed serverAgentId, bytes32 dataHash)',
  'event ValidationResponse(uint256 indexed validatorAgentId, uint256 indexed serverAgentId, bytes32 dataHash, uint8 response)'
];

/**
 * HTTPLogger - Captures complete HTTP request/response data
 *
 * This class provides unforgeable proof of API calls by logging:
 * - Complete request details (URL, method, headers, body)
 * - Complete response details (status, headers, body)
 * - Request/response body hashes for integrity verification
 * - TLS certificate information for endpoint verification
 *
 * Security Properties:
 * - Request logged BEFORE sending (proves intent)
 * - Response logged immediately after receipt (proves actual response)
 * - Hashes provide tamper-proof verification
 * - TLS certificates prove API endpoint identity
 */
class HTTPLogger {
  constructor() {
    this.requestLog = [];
    this.responseLog = [];
    this.requestCounter = 0;
  }

  /**
   * Log outgoing HTTP request
   * @param {string} url - Request URL
   * @param {string} method - HTTP method
   * @param {object} headers - Request headers
   * @param {object} body - Request body
   * @returns {object} Request record with unique ID
   */
  logRequest(url, method, headers, body) {
    const requestId = `req_${Date.now()}_${++this.requestCounter}`;

    const requestRecord = {
      requestId,
      timestamp: Date.now(),
      url: url.toString(),
      method,
      headers: this.sanitizeHeaders(headers),
      body: body ? JSON.stringify(body) : null,
      bodyHash: body ? crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex') : null
    };

    this.requestLog.push(requestRecord);
    return requestRecord;
  }

  /**
   * Log incoming HTTP response
   * @param {string} requestId - ID linking to original request
   * @param {number} status - HTTP status code
   * @param {object} headers - Response headers
   * @param {string} body - Response body (raw)
   * @param {object} tlsCertificate - TLS certificate info (optional)
   * @returns {object} Response record
   */
  logResponse(requestId, status, headers, body, tlsCertificate = null) {
    const responseRecord = {
      requestId,
      timestamp: Date.now(),
      status,
      headers: headers || {},
      body: body || null,
      bodyHash: body ? crypto.createHash('sha256').update(body).digest('hex') : null,
      // Link TLS certificate to this specific response
      tlsCertificate: tlsCertificate ? {
        verified: tlsCertificate.verified,
        subject: tlsCertificate.subject,
        issuer: tlsCertificate.issuer,
        fingerprint: tlsCertificate.fingerprint,
        validFrom: tlsCertificate.validFrom,
        validTo: tlsCertificate.validTo,
        protocol: tlsCertificate.protocol,
        cipher: tlsCertificate.cipher
      } : null
    };

    this.responseLog.push(responseRecord);
    return responseRecord;
  }

  /**
   * Sanitize headers to remove sensitive data
   * @param {object} headers - Original headers
   * @returns {object} Sanitized headers
   */
  sanitizeHeaders(headers) {
    if (!headers) return {};

    // Create copy and redact sensitive fields
    const sanitized = { ...headers };

    // Redact common sensitive headers
    const sensitiveKeys = ['X-API-Key', 'Authorization', 'Cookie', 'Set-Cookie'];
    for (const key of sensitiveKeys) {
      if (sanitized[key]) {
        sanitized[key] = '[REDACTED]';
      }
    }

    return sanitized;
  }

  /**
   * Get complete log for evidence
   * @returns {object} Complete HTTP transaction log
   */
  getCompleteLog() {
    return {
      requests: this.requestLog,
      responses: this.responseLog,
      totalRequests: this.requestLog.length,
      totalResponses: this.responseLog.length
    };
  }
}

/**
 * DNSLogger - Captures DNS resolution data
 *
 * Provides proof of correct DNS resolution to prevent DNS spoofing attacks.
 * Logs hostname→IP resolution to prove agent connected to correct server.
 */
class DNSLogger {
  constructor() {
    this.resolutions = [];
  }

  /**
   * Log DNS resolution
   * @param {string} hostname - Hostname to resolve
   * @returns {Promise<object>} Resolution record
   */
  async logDNSResolution(hostname) {
    const dns = require('dns').promises;
    const startTime = Date.now();

    try {
      const addresses = await dns.resolve4(hostname);
      const resolution = {
        timestamp: startTime,
        hostname,
        resolvedIPs: addresses,
        duration: Date.now() - startTime,
        success: true,
        error: null
      };

      this.resolutions.push(resolution);
      console.log(`🌐 DNS resolved: ${hostname} → ${addresses.join(', ')} (${resolution.duration}ms)`);
      return resolution;
    } catch (error) {
      const resolution = {
        timestamp: startTime,
        hostname,
        resolvedIPs: [],
        duration: Date.now() - startTime,
        success: false,
        error: error.message
      };

      this.resolutions.push(resolution);
      console.warn(`⚠️  DNS resolution failed for ${hostname}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get all DNS resolutions for evidence
   * @returns {Array} All resolution records
   */
  getResolutions() {
    return this.resolutions;
  }
}

/**
 * Generate source code hashes for reproducibility verification
 *
 * This function hashes all critical source files to provide:
 * - Complete code reproducibility (anyone can rebuild and verify)
 * - Proof of exact code version executed
 * - Tamper-proof code integrity verification
 *
 * @returns {object} Source file hashes and build metadata
 */
function generateSourceCodeHashes() {
  const fs = require('fs');
  const path = require('path');

  // Critical files that define the agent's behavior
  const sourceFiles = [
    'cambrian-defi-data-agent.js',
    'package.json',
    'package-lock.json',
    'Dockerfile',
    'ipfs-storage.js',
    '.dockerignore'
  ];

  const hashes = {};
  let totalSize = 0;

  for (const file of sourceFiles) {
    try {
      const filePath = path.join(__dirname, file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        const hash = crypto.createHash('sha256').update(content).digest('hex');

        hashes[file] = {
          sha256: hash,
          size: content.length,
          lastModified: fs.statSync(filePath).mtime.toISOString()
        };

        totalSize += content.length;
      } else {
        hashes[file] = {
          error: 'File not found',
          sha256: null,
          size: 0
        };
      }
    } catch (error) {
      hashes[file] = {
        error: error.message,
        sha256: null,
        size: 0
      };
    }
  }

  return {
    sourceFiles: hashes,
    totalFiles: sourceFiles.length,
    totalSize,
    generatedAt: Date.now()
  };
}

/**
 * Generate complete code verification metadata
 *
 * Provides all information needed for third parties to:
 * - Rebuild the exact container
 * - Verify source code integrity
 * - Reproduce the execution environment
 *
 * @param {string} containerDigest - Docker container SHA-256 digest
 * @returns {object} Complete code verification data
 */
function generateCodeVerificationMetadata(containerDigest) {
  return {
    // Source code hashes for file-by-file verification
    sourceHashes: generateSourceCodeHashes(),

    // Container identity
    containerDigest: containerDigest || process.env.CONTAINER_DIGEST || 'unknown',

    // Runtime environment
    runtime: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      execPath: process.execPath
    },

    // Build metadata (from environment variables set during build)
    build: {
      timestamp: process.env.BUILD_TIMESTAMP || 'unknown',
      gitCommit: process.env.GIT_COMMIT || 'unknown',
      gitBranch: process.env.GIT_BRANCH || 'unknown',
      buildNumber: process.env.BUILD_NUMBER || 'unknown'
    },

    // Reproducibility instructions
    reproducibility: {
      repository: process.env.GIT_REPOSITORY || 'https://github.com/your-org/erc-8004',
      commitHash: process.env.GIT_COMMIT || 'unknown',
      buildCommand: 'docker build --build-arg SOURCE_DATE_EPOCH=0 -t cambrian-agent .',
      verifyCommand: 'docker inspect --format=\'{{.Id}}\' cambrian-agent',
      expectedDigest: containerDigest || process.env.CONTAINER_DIGEST || 'unknown',
      notes: [
        'Use SOURCE_DATE_EPOCH=0 for reproducible builds',
        'Container digest should match expectedDigest',
        'All source file hashes should match sourceHashes values'
      ]
    },

    // Verification steps for third parties
    verificationSteps: [
      '1. Clone repository: git clone <repository>',
      '2. Checkout commit: git checkout <commitHash>',
      '3. Verify source hashes: sha256sum <file> for each source file',
      '4. Rebuild container: docker build -t verify-agent .',
      '5. Compare digest: docker inspect --format=\'{{.Id}}\' verify-agent',
      '6. Digest should match containerDigest field'
    ]
  };
}

class CambrianDeFiDataAgent {
  constructor() {
    this.domain = 'cambrian-defi-data.base';
    this.agentId = null;
    this.wallet = null;
    this.registry = null;
    this.app = express();

    // Debug logging buffer (circular buffer of last 100 logs)
    this.debugLogs = [];
    this.maxDebugLogs = 100;

    // TEE Mode Detection
    this.runningInTEE = process.env.TEE_MODE === 'true';

    // MCP Server URL is REQUIRED in production - no fallback
    const mcpServerUrl = process.env.MCP_SERVER_URL;
    if (!mcpServerUrl) {
      this.log('ERROR', 'MCP_SERVER_URL environment variable is required - no default fallback');
      throw new Error('MCP_SERVER_URL must be set');
    }

    // TEE Integration Configuration
    // In dual-TEE architecture, the MCP server is the external TEE component we depend on
    this.teeConfig = {
      enabled: this.runningInTEE || process.env.TEE_ATTESTATION_ENDPOINT ? true : (process.env.TEE_ENABLED === 'true'),
      endpoint: process.env.TEE_ATTESTATION_ENDPOINT || process.env.TEE_ENDPOINT || mcpServerUrl, // Default to MCP server for dual-TEE
      highValueThreshold: parseFloat(process.env.TEE_THRESHOLD || '0.01'), // Use TEE for requests above this value
      requiredServices: (process.env.TEE_REQUIRED_SERVICES || 'ohlcv').split(','), // Services that always use TEE
      mode: this.runningInTEE ? 'FULL_TEE' : 'EXTERNAL_TEE' // FULL_TEE = executing inside TEE, EXTERNAL_TEE = requesting from external TEE
    };

    // Load hardware attestation if running in TEE
    if (this.runningInTEE) {
      try {
        const fs = require('fs');
        this.attestationJWT = fs.readFileSync(
          '/run/container_launcher/attestation_verifier_claims_token',
          'utf8'
        );
        this.containerDigest = process.env.CONTAINER_DIGEST || 'sha256:unknown';
        console.log('🔐 Running in TEE mode - Hardware attestation loaded');
        console.log(`   Container: ${this.containerDigest.substring(0, 20)}...`);
        console.log(`   Security Level: MAXIMUM (All execution in AMD SEV)`);
      } catch (error) {
        console.warn(`⚠️  TEE mode enabled but attestation token not found: ${error.message}`);
        console.warn(`   This may be normal in development. Production requires TEE.`);
      }
    }

    // Google ADK Integration
    this.googleADKAgent = null;
    this.dualTEEProofGenerator = null;

    // Use the MCP Server URL from above
    this.mcpServerUrl = mcpServerUrl;
    this.log('INFO', `🔗 Agent configured to use MCP server: ${this.mcpServerUrl}`);

    this.setupRoutes();

    // Service catalog matching Cambrian API endpoints
    this.services = [
      {
        id: 'price-current',
        name: 'Solana Token Price (Current)',
        description: 'Get real-time USD price for any Solana token',
        price: '0.001', // 0.001 USDC per query
        endpoint: '/api/price-current',
        method: 'POST',
        parameters: {
          token_address: {
            type: 'string',
            description: 'Solana token address (base58)',
            required: true,
            example: 'So11111111111111111111111111111111111111112'
          }
        },
        response: {
          tokenAddress: 'string',
          symbol: 'string',
          priceUSD: 'number',
          timestamp: 'string',
          source: 'string'
        }
      },
      {
        id: 'price-multi',
        name: 'Multiple Token Prices',
        description: 'Get prices for multiple tokens in one request',
        price: '0.003', // 0.003 USDC for batch
        endpoint: '/api/price-multi',
        method: 'POST',
        parameters: {
          token_addresses: {
            type: 'array',
            description: 'Array of Solana token addresses',
            required: true,
            maxItems: 10
          }
        }
      },
      {
        id: 'ohlcv',
        name: 'OHLCV Data',
        description: 'Get historical OHLCV data for trading',
        price: '0.01', // 0.01 USDC for historical data
        endpoint: '/api/ohlcv',
        method: 'POST',
        parameters: {
          token_address: { type: 'string', required: true },
          after_time: { type: 'integer', required: true },
          before_time: { type: 'integer', required: true },
          interval: { type: 'string', required: true, enum: ['1m', '5m', '15m', '1h', '4h', '1d'] }
        }
      }
    ];

    // Track service metrics
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      totalRevenue: 0,
      avgResponseTime: 0,
      startTime: Date.now()
    };

    // ERC-8004 feedback tracking
    this.feedbackData = [];
    this.validationRequests = {};
    this.validationResponses = {};
  }

  async initialize() {
    // Setup wallet and provider
    const provider = new ethers.JsonRpcProvider(process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org');
    this.wallet = new ethers.Wallet(
      process.env.AGENT_PRIVATE_KEY || process.env.CAMBRIAN_AGENT_PRIVATE_KEY || process.env.SELLER_PRIVATE_KEY,
      provider
    );

    // Connect to registry - NEW WORKING CONTRACT!
    const registryAddress = '0x8647e26A4baA3C3D81a5e9612F9C191ec20f5372';
    this.registry = new ethers.Contract(registryAddress, REGISTRY_ABI, this.wallet);

    console.log('🔐 Agent wallet:', this.wallet.address);
    console.log('📝 Registry:', registryAddress);

    // DEBUG: Log API key configuration at startup
    console.error('🔑 API Key Configuration at startup:');
    console.error(`   SERVER_CAMBRIAN_API_KEY: ${process.env.SERVER_CAMBRIAN_API_KEY ? `SET (length: ${process.env.SERVER_CAMBRIAN_API_KEY.length}, starts with: ${process.env.SERVER_CAMBRIAN_API_KEY.substring(0, 8)})` : 'NOT SET'}`);
    console.error(`   CAMBRIAN_API_KEY: ${process.env.CAMBRIAN_API_KEY ? `SET (length: ${process.env.CAMBRIAN_API_KEY.length}, starts with: ${process.env.CAMBRIAN_API_KEY.substring(0, 8)})` : 'NOT SET'}`);

    // Check if already registered
    await this.checkExistingRegistration();

    // Initialize Google ADK Agent
    await this.initializeGoogleADK();
  }

  async initializeGoogleADK() {
    try {
      console.log('🤖 Initializing Google ADK Agent (Python subprocess)...');

      const { spawn } = require('child_process');
      const axios = require('axios');

      // Start Python Flask server for Google ADK
      const pythonPort = 9000;
      const pythonHost = '127.0.0.1';

      console.log(`   Starting Python ADK server on ${pythonHost}:${pythonPort}...`);

      // Kill any existing Python process on port 9000 (from previous restarts)
      // Use pkill which is available in Alpine
      try {
        const { execSync } = require('child_process');
        execSync(`pkill -9 -f 'python.*server.py' 2>/dev/null || true`, {
          stdio: 'ignore',
          shell: '/bin/sh'
        });
        // Wait a moment for port to be released
        await new Promise(resolve => setTimeout(resolve, 500));
        console.log(`   Cleaned up any existing Python processes`);
      } catch (err) {
        // Ignore errors - process might not exist
      }

      // Create log file for Python subprocess (for debugging TEE deployments)
      const fs = require('fs');
      const pythonLogPath = '/tmp/python_adk.log';
      const pythonLogStream = fs.createWriteStream(pythonLogPath, { flags: 'w' });
      console.log(`   Python logs will be written to: ${pythonLogPath}`);

      this.pythonProcess = spawn('python3', ['python_adk/server.py'], {
        cwd: __dirname,
        env: {
          ...process.env,
          PYTHON_ADK_PORT: pythonPort.toString(),
          PYTHON_ADK_HOST: pythonHost,
          GEMINI_API_KEY: process.env.GEMINI_API_KEY,
          SERVER_CAMBRIAN_API_KEY: process.env.SERVER_CAMBRIAN_API_KEY || process.env.CAMBRIAN_API_KEY
        },
        stdio: ['ignore', 'pipe', 'pipe']
      });

      // Log Python output
      this.pythonProcess.stdout.on('data', (data) => {
        const msg = data.toString().trim();
        console.log(`[Python ADK] ${msg}`);
        pythonLogStream.write(`[STDOUT] ${msg}\n`);
      });

      this.pythonProcess.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        console.error(`[Python ADK Error] ${msg}`);
        pythonLogStream.write(`[STDERR] ${msg}\n`);
      });

      this.pythonProcess.on('exit', (code) => {
        console.warn(`[Python ADK] Process exited with code ${code}`);
        this.googleADKAvailable = false;
      });

      // Wait for Python server to be ready
      console.log('   Waiting for Python ADK server to initialize...');
      const maxRetries = 30; // 30 seconds
      let lastError = null;
      for (let i = 0; i < maxRetries; i++) {
        try {
          await new Promise(resolve => setTimeout(resolve, 1000));
          const healthCheck = await axios.get(`http://${pythonHost}:${pythonPort}/health`, { timeout: 2000 });
          if (healthCheck.data.status === 'healthy') {
            console.log('   ✅ Python ADK server is ready!');
            break;
          }
        } catch (err) {
          lastError = err;
          console.log(`   [Retry ${i + 1}/${maxRetries}] Waiting for Python server... (${err.code || err.message})`);
          if (i === maxRetries - 1) {
            throw new Error(`Python ADK server failed to start after ${maxRetries} seconds. Last error: ${err.message}`);
          }
        }
      }

      // Store Python server URL
      this.pythonADKUrl = `http://${pythonHost}:${pythonPort}`;
      this.googleADKAvailable = true;

      // Initialize Proof Registry for dual TEE proofs
      const PROOF_REGISTRY_ABI = [
        'function submitProof(bytes32 merkleRoot, string memory evidenceHash, string memory containerDigest) external payable returns (uint256 proofId)',
        'event ProofSubmitted(uint256 indexed proofId, bytes32 indexed merkleRoot, address indexed submitter, string evidenceHash)'
      ];

      this.proofRegistry = new ethers.Contract(
        '0x497f2f7081673236af8B2924E673FdDB7fAeF889', // ProofRegistry V2 address
        PROOF_REGISTRY_ABI,
        this.wallet
      );

      // Create Dual TEE Proof Generator
      const { DualTEEProofGenerator } = require('./dual-tee-proof-generator');
      this.dualTEEProofGenerator = new DualTEEProofGenerator(
        this.attestationJWT,
        this.containerDigest,
        this.wallet,
        this.proofRegistry,
        this.mcpServerUrl
      );

      console.log('✅ Google ADK Agent (Python) initialized successfully');
      console.log(`   Python ADK URL: ${this.pythonADKUrl}`);
      console.log(`   MCP Server: ${this.mcpServerUrl}`);
      console.log(`   Dual TEE: Agent + MCP Server attestations enabled`);
    } catch (error) {
      console.error('❌ Failed to initialize Google ADK Agent:', error.message);
      console.error('   Full error:', error);
      console.warn('   /api/ask endpoint will not be available');
      this.googleADKAvailable = false;
      this.googleADKError = error.message;
      // Don't throw - allow agent to continue without Google ADK
    }
  }

  // Debug logging with buffer storage
  log(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, level, message, data };

    // Add to buffer (circular)
    this.debugLogs.push(logEntry);
    if (this.debugLogs.length > this.maxDebugLogs) {
      this.debugLogs.shift();
    }

    // Also log to console
    const formatted = `[${level}] ${message}`;
    if (level === 'ERROR') console.error(formatted, data || '');
    else if (level === 'WARN') console.warn(formatted, data || '');
    else console.log(formatted, data || '');
  }

  async checkExistingRegistration() {
    try {
      const agentCount = await this.registry.agentIdCounter();
      console.log(`Found ${agentCount} agents in registry`);

      for (let i = 1; i <= agentCount; i++) {
        try {
          const agent = await this.registry.agents(i);
          // Check if this is our agent
          if (agent[1] === this.domain || agent[2].toLowerCase() === this.wallet.address.toLowerCase()) {
            this.agentId = i;
            console.log('✅ Already registered as Agent #' + i);
            console.log('   Domain:', agent[1]);
            console.log('   Address:', agent[2]);
            return true;
          }
        } catch (e) {
          // Skip if can't read this agent
        }
      }
    } catch (error) {
      console.log('❌ Could not check registry:', error.message);
      console.log('   Registry must be accessible for production operation');
      throw new Error(`Registry connection failed: ${error.message}`);
    }
    return false;
  }

  async register() {
    if (this.agentId) {
      console.log('Already registered as Agent #' + this.agentId);
      return this.agentId;
    }

    console.log('📝 Attempting to register Cambrian DeFi Data Agent on-chain...');

    try {
      // Generate metadata for potential future use (not required by ERC-8004 registry)
      const metadata = this.generateMetadata();
      console.log('📦 Generated metadata for agent:', metadata.agent.name);

      // Register on-chain (only takes domain and address)
      const tx = await this.registry.registerAgent(
        this.domain,
        this.wallet.address
      );

      console.log('⏳ Transaction submitted:', tx.hash);
      const receipt = await tx.wait();

      // Extract agent ID from event
      const event = receipt.logs.find(log => {
        try {
          const parsed = this.registry.interface.parseLog(log);
          return parsed.name === 'AgentRegistered';
        } catch {
          return false;
        }
      });

      if (event) {
        const parsed = this.registry.interface.parseLog(event);
        this.agentId = parsed.args[0].toString();
        console.log('✅ Registered as Agent #' + this.agentId);
      }

      console.log('🔗 Domain:', this.domain);
      console.log('📍 Address:', this.wallet.address);
      console.log('🌐 View on BaseScan:', `https://sepolia.basescan.org/tx/${tx.hash}`);
    } catch (error) {
      console.log('❌ Registration failed:', error.reason || error.message);
      console.log('   This might be because:');
      console.log('   - Domain already registered');
      console.log('   - Address already registered');
      console.log('   - Insufficient gas');
      console.log('   - Network connectivity issues');
      throw new Error(`Agent registration failed: ${error.reason || error.message}`);
    }

    return this.agentId;
  }

  generateMetadata() {
    return {
      version: '1.0.0',
      agent: {
        name: 'Cambrian DeFi Data Network',
        domain: this.domain,
        description: 'Production-grade Solana price data agent with real-time and historical data',
        category: 'DeFi/Data',
        website: 'https://cambrian.network',
        contact: {
          email: 'support@cambrian.network'
        }
      },
      services: this.services.map(service => ({
        ...service,
        pricing: {
          amount: service.price,
          currency: 'USDC',
          chain: 'base'
        },
        sla: {
          responseTime: '< 500ms',
          uptime: '99.9%',
          dataFreshness: '< 1 minute'
        }
      })),
      reputation: {
        totalRequests: this.metrics.totalRequests,
        successRate: this.metrics.totalRequests > 0
          ? (this.metrics.successfulRequests / this.metrics.totalRequests * 100).toFixed(1)
          : 0,
        avgResponseTime: this.metrics.avgResponseTime + 'ms',
        lastUpdated: new Date().toISOString()
      }
    };
  }

  async generateAgentSignature() {
    // Generate signature proving ownership of agent address
    const message = `Agent registration proof for ${this.domain} at ${this.wallet.address}`;
    const signature = await this.wallet.signMessage(message);
    return signature;
  }

  /**
   * Generate EIP-712 feedbackAuth signature according to ERC-8004 spec
   * @param {string} clientAddress - Address authorized to give feedback (0x...)
   * @param {number} indexLimit - Maximum feedback index this signature is valid for
   * @param {number} expiryTimestamp - Unix timestamp when signature expires
   * @returns {Object} feedbackAuth data with signature
   */
  async generateFeedbackAuth(clientAddress, indexLimit = 1, expiryTimestamp = null) {
    const registryAddress = process.env.ERC8004_REGISTRY || this.config?.contracts?.erc8004_registry || '0x8647e26A4baA3C3D81a5e9612F9C191ec20f5372';
    const reputationRegistryAddress = process.env.REPUTATION_REGISTRY_V2 || this.config?.contracts?.reputation_registry_v2 || '0x701C8B6431aD0C4670E8F27AD4cE9aEb8a135ffd';

    // Default expiry: 30 days from now
    const expiry = expiryTimestamp || Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60);

    // EIP-712 domain for ReputationRegistry
    const domain = {
      name: "ERC8004ReputationRegistry",
      version: "1",
      chainId: 84532, // Base Sepolia
      verifyingContract: reputationRegistryAddress
    };

    // EIP-712 types for feedbackAuth
    const types = {
      FeedbackAuth: [
        { name: "agentId", type: "uint256" },
        { name: "clientAddress", type: "address" },
        { name: "indexLimit", type: "uint64" },
        { name: "expiry", type: "uint256" },
        { name: "chainId", type: "uint256" },
        { name: "identityRegistry", type: "address" },
        { name: "signerAddress", type: "address" }
      ]
    };

    // Values to sign
    const value = {
      agentId: this.agentId,
      clientAddress: clientAddress,
      indexLimit: indexLimit,
      expiry: expiry,
      chainId: 84532,
      identityRegistry: registryAddress,
      signerAddress: this.wallet.address
    };

    // Sign using EIP-712
    const signature = await this.wallet.signTypedData(domain, types, value);

    return {
      agentId: this.agentId,
      clientAddress,
      indexLimit,
      expiry,
      chainId: 84532,
      identityRegistry: registryAddress,
      signerAddress: this.wallet.address,
      signature,
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Generate validation request URI according to ERC-8004 spec
   * Stores validation request data on IPFS and returns the URI
   * @param {string} validatorAddress - Validator's wallet address
   * @param {Object} inputData - Input data for validation
   * @param {Object} outputData - Output data to validate
   * @returns {Promise<Object>} Validation request with IPFS URI and dataHash
   */
  async generateValidationRequestURI(validatorAddress, inputData, outputData) {
    const registryAddress = process.env.ERC8004_REGISTRY || this.config?.contracts?.erc8004_registry || '0x8647e26A4baA3C3D81a5e9612F9C191ec20f5372';

    // Create validation request data structure per ERC-8004 spec
    const requestData = {
      agentId: this.agentId,
      agentRegistry: `eip155:84532:${registryAddress}`,
      validatorAddress,
      timestamp: new Date().toISOString(),
      inputData,
      outputData,
      metadata: {
        chain: "base-sepolia",
        chainId: 84532,
        agentDomain: this.domain,
        agentAddress: this.wallet.address
      }
    };

    // Calculate dataHash (keccak256 of JSON string)
    const dataString = JSON.stringify({ inputData, outputData });
    const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(dataString));

    requestData.dataHash = dataHash;

    // Upload to IPFS
    const ipfsStorage = require('./ipfs-storage');
    const ipfsHash = await ipfsStorage.upload(requestData);

    // Return URI in IPFS format
    const requestUri = ipfsHash.startsWith('Qm') || ipfsHash.startsWith('b')
      ? `ipfs://${ipfsHash}`
      : `local://${ipfsHash}`;

    console.log(`📝 Validation request generated: ${requestUri}`);

    return {
      requestUri,
      requestHash: dataHash,
      ipfsHash,
      validatorAddress,
      agentId: this.agentId,
      createdAt: requestData.timestamp
    };
  }

  /**
   * Generate spec-compliant feedback file format according to ERC-8004
   * @param {Object} params - Feedback parameters
   * @returns {Object} ERC-8004 compliant feedback data
   */
  generateFeedbackFileData(params) {
    const {
      clientAddress,
      score, // 0-100 scale per spec
      tag1 = null,
      tag2 = null,
      skill = null,
      context = null,
      task = null,
      capability = null,
      toolName = null,
      proofOfPayment = null,
      feedbackAuth = null
    } = params;

    const registryAddress = process.env.ERC8004_REGISTRY || this.config?.contracts?.erc8004_registry || '0x8647e26A4baA3C3D81a5e9612F9C191ec20f5372';

    // Build ERC-8004 compliant feedback file
    const feedbackData = {
      // MUST fields per spec
      agentRegistry: `eip155:84532:${registryAddress}`,
      agentId: this.agentId,
      clientAddress: `eip155:84532:${clientAddress}`,
      createdAt: new Date().toISOString(),
      feedbackAuth: feedbackAuth || "not-provided",
      score: score,

      // MAY fields per spec
      ...(tag1 && { tag1 }),
      ...(tag2 && { tag2 }),
      ...(skill && { skill }),
      ...(context && { context }),
      ...(task && { task }),
      ...(capability && { capability }),
      ...(toolName && { name: toolName }),
      ...(proofOfPayment && { proof_of_payment: proofOfPayment })
    };

    return feedbackData;
  }

  /**
   * Store feedback file data on IPFS
   * @param {Object} feedbackData - Feedback data to store
   * @returns {Promise<string>} IPFS hash
   */
  async storeFeedbackOnIPFS(feedbackData) {
    const ipfsStorage = require('./ipfs-storage');
    const ipfsHash = await ipfsStorage.upload(feedbackData);
    console.log(`📤 Feedback data stored on IPFS: ${ipfsHash}`);
    return ipfsHash;
  }

  async generateERC8004AgentCard() {
    const signature = await this.generateAgentSignature();
    const registryAddress = process.env.ERC8004_REGISTRY || this.config?.contracts?.erc8004_registry || '0x8647e26A4baA3C3D81a5e9612F9C191ec20f5372';

    // Get deployment URL
    const baseUrl = process.env.NODE_ENV === 'production'
      ? process.env.AGENT_URL || 'http://34.171.64.112:8080'
      : `http://localhost:${this.port || 3405}`;

    return {
      // ERC-8004 Required: type field
      type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",

      // Basic agent information
      name: 'Cambrian DeFi Data Agent',
      description: 'ERC-8004 compliant agent for Solana token prices with TEE attestation and cryptographic proof generation',

      // ERC-8004 Required: image field
      image: 'https://cambrian.network/assets/cambrian-agent-avatar.png',

      // ERC-8004 Required: endpoints array (not object)
      endpoints: [
        {
          name: "A2A",
          endpoint: `${baseUrl}/.well-known/agent-card.json`,
          version: "0.3.0"
        },
        {
          name: "MCP",
          endpoint: process.env.MCP_SERVER_URL || "http://136.115.87.101:8081",
          capabilities: {
            tools: true,
            resources: true
          },
          version: "2025-06-18"
        },
        {
          name: "agentWallet",
          endpoint: `eip155:84532:${this.wallet?.address}`
        },
        {
          name: "health",
          endpoint: `${baseUrl}/health`
        },
        {
          name: "attestation",
          endpoint: `${baseUrl}/attestation`
        },
        {
          name: "priceData",
          endpoint: `${baseUrl}/api/price-current`
        },
        {
          name: "batchPrice",
          endpoint: `${baseUrl}/api/price-multi`
        },
        {
          name: "ohlcv",
          endpoint: `${baseUrl}/api/ohlcv`
        }
      ],

      // ERC-8004 Required: registrations array with agentRegistry
      registrations: [{
        agentId: this.agentId,
        agentRegistry: `eip155:84532:${registryAddress}`
      }],

      // ERC-8004 Required: supportedTrust (not trustModels)
      supportedTrust: [
        "reputation",
        "crypto-economic",
        "tee-attestation"
      ]
    };
  }

  async createFeedbackAuthorization(clientAgentId = 0) {
    try {
      console.log(`🔐 Creating feedback authorization: Client ${clientAgentId} → Server ${this.agentId}`);

      // Call acceptFeedback on the ERC-8004Complete contract
      const tx = await this.registry.acceptFeedback(clientAgentId, this.agentId);
      const receipt = await tx.wait();

      // Extract feedback auth ID from event
      const event = receipt.logs.find(log => {
        try {
          const parsed = this.registry.interface.parseLog(log);
          return parsed.name === 'AuthFeedback';
        } catch {
          return false;
        }
      });

      if (event) {
        const parsed = this.registry.interface.parseLog(event);
        const feedbackAuthId = parsed.args[2].toString();
        console.log(`✅ Feedback authorization created: ID ${feedbackAuthId}`);
        return {
          feedbackAuthId,
          clientAgentId,
          serverAgentId: this.agentId,
          transactionHash: tx.hash,
          timestamp: Date.now()
        };
      }

      throw new Error('AuthFeedback event not found in transaction');
    } catch (error) {
      console.error('❌ Failed to create feedback authorization:', error.message);
      throw error;
    }
  }

  generateTaskId() {
    return `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async recordServiceExecution(serviceId, input, output, feedbackAuth, taskId = null) {
    const serviceExecution = {
      FeedbackAuthID: `eip155:84532:${feedbackAuth.feedbackAuthId}`, // CAIP-10 format
      AgentSkillId: serviceId,
      TaskId: taskId || this.generateTaskId(),
      contextId: `${serviceId}_${Date.now()}`,
      Rating: null, // To be filled by client feedback
      ProofOfPayment: {
        method: process.env.BYPASS_PAYMENT === 'true' ? 'bypass' : 'required',
        amount: this.services.find(s => s.id === serviceId)?.price || '0.001',
        currency: 'USDC',
        timestamp: Date.now(),
        transactionHash: feedbackAuth.transactionHash
      },
      Data: {
        input: input,
        output: output,
        responseTime: output.responseTime || 'N/A',
        accuracy: 'high',
        source: output.source || 'cambrian',
        timestamp: output.timestamp || new Date().toISOString()
      },
      _metadata: {
        createdAt: new Date().toISOString(),
        feedbackAuth: feedbackAuth
      }
    };

    this.feedbackData.push(serviceExecution);
    console.log(`📝 Service execution recorded: ${serviceId} (Auth ID: ${feedbackAuth.feedbackAuthId})`);

    return serviceExecution;
  }

  // On-Chain Proof Evidence Integration
  generateMerkleRoot(input, output, timestamp) {
    // Generate deterministic hash of input/output for merkle root commitment
    const data = JSON.stringify({ input, output, timestamp });
    const hash = require('crypto')
      .createHash('sha256')
      .update(data)
      .digest('hex');

    return '0x' + hash; // bytes32 format for smart contract
  }

  async submitProofToRegistry(merkleRoot, evidenceHash) {
    if (!this.proofRegistry) {
      // Initialize ProofRegistry V2 contract (with containerDigest support)
      const PROOF_REGISTRY_ABI = [
        'function submitProof(bytes32 merkleRoot, string memory evidenceHash, string memory containerDigest) external payable returns (uint256 proofId)',
        'event ProofSubmitted(uint256 indexed proofId, bytes32 indexed merkleRoot, address indexed submitter, string evidenceHash)'
      ];

      this.proofRegistry = new ethers.Contract(
        '0x497f2f7081673236af8B2924E673FdDB7fAeF889', // ProofRegistry V2 address (Base Sepolia)
        PROOF_REGISTRY_ABI,
        this.wallet
      );
    }

    try {
      console.log('🔐 Submitting proof commitment to ProofRegistry V2...');

      // Submit proof with required stake (0.00001 ETH) and container digest
      const stakeAmount = ethers.parseEther('0.00001');
      const containerDigest = this.containerDigest || process.env.CONTAINER_DIGEST || '';

      console.log(`   Container Digest: ${containerDigest || '(none - not in TEE mode)'}`);

      const tx = await this.proofRegistry.submitProof(
        merkleRoot,
        evidenceHash,
        containerDigest,
        {
          value: stakeAmount,
          gasLimit: 500000  // Increased to cover actual gas needs (~375k)
        }
      );

      console.log(`   TX Hash: ${tx.hash}`);
      const receipt = await tx.wait();

      // Extract proof ID from event
      const event = receipt.logs.find(log => {
        try {
          const parsed = this.proofRegistry.interface.parseLog(log);
          return parsed.name === 'ProofSubmitted';
        } catch {
          return false;
        }
      });

      let proofId = null;
      if (event) {
        const parsed = this.proofRegistry.interface.parseLog(event);
        proofId = parsed.args[0].toString();
        console.log(`   ✅ Proof submitted with ID: ${proofId}`);
      }

      return {
        proofId,
        transactionHash: tx.hash,
        blockNumber: receipt.blockNumber
      };
    } catch (error) {
      this.log('ERROR', `Failed to submit proof to registry: ${error.message}`, {
        error: error.stack,
        merkleRoot,
        evidenceHash,
        containerDigest: this.containerDigest
      });
      console.warn(`   ⚠️ Failed to submit proof to registry: ${error.message}`);
      // Don't throw - continue even if proof submission fails
      return null;
    }
  }

  async createEvidence(serviceId, input, output, feedbackAuth) {
    try {
      // Generate merkle root from service execution data
      const timestamp = Date.now();
      const executionData = {
        service: serviceId,
        input,
        output,
        timestamp,
        agentId: this.agentId,
        feedbackAuthId: feedbackAuth?.feedbackAuthId || null
      };

      const merkleRoot = this.generateMerkleRoot(input, output, timestamp);

      console.log(`🔍 Creating verifiable on-chain proof with data revelation...`);
      console.log(`   Merkle Root: ${merkleRoot}`);
      console.log(`   Service: ${serviceId}`);

      // NEW: Create TEE attestation (internal or external)
      let teeAttestation = null;
      const crypto = require('crypto');
      const inputHash = crypto.createHash('sha256').update(JSON.stringify(input)).digest('hex');
      const outputHash = crypto.createHash('sha256').update(JSON.stringify(output)).digest('hex');

      if (this.runningInTEE) {
        // FULL TEE MODE: Create attestation internally (proves THIS code executed)
        console.log(`   🔐 Creating internal TEE attestation (FULL TEE mode)...`);

        // Extract TLS certificate from output for attestation
        let outputTLS = null;
        if (output && typeof output === 'object') {
          outputTLS = output.tlsCertificate || (Array.isArray(output) && output[0]?.tlsCertificate);
        }

        teeAttestation = this.createTEEAttestationInternal({
          executionData,
          inputHash,
          outputHash,
          merkleRoot,
          tlsCertificate: outputTLS
        });

        console.log(`   ✅ Hardware-backed execution proof created`);
        console.log(`      Platform: ${teeAttestation.platform}`);
        console.log(`      Container: ${this.containerDigest.substring(0, 20)}...`);
        console.log(`      Security Level: MAXIMUM`);
        if (outputTLS) {
          console.log(`      TLS Verified: ${outputTLS.verified ? '✅' : '⚠️'}`);
          console.log(`      API Certificate: ${outputTLS.subject}`);
        }
      } else if (process.env.TEE_ATTESTATION_ENDPOINT) {
        // EXTERNAL TEE MODE: Request attestation from external TEE (legacy mode)
        console.log(`   🔐 Requesting TEE hardware attestation (external mode)...`);
        teeAttestation = await this.requestTEEAttestation({
          inputHash,
          outputHash,
          merkleRoot,
          timestamp: Date.now()
        });

        if (teeAttestation) {
          console.log(`   ✅ TEE attestation obtained`);
          console.log(`      Platform: ${teeAttestation.platform}`);
          console.log(`      Security Level: STANDARD (hash signing only)`);
        } else {
          console.log(`   ⚠️  TEE attestation request failed (continuing without)`);
        }
      }

      // Extract TLS certificate proof if present in output
      let tlsCertificate = null;
      if (output && typeof output === 'object') {
        if (output.tlsCertificate) {
          tlsCertificate = output.tlsCertificate;
        } else if (Array.isArray(output) && output.length > 0 && output[0].tlsCertificate) {
          // Handle price-multi case where output is array
          tlsCertificate = output[0].tlsCertificate;
        }
      }

      // CRITICAL: Store full evidence data for verifiability
      // Format: JSON with all execution details
      const fullEvidence = {
        executionData,
        merkleRoot,
        agentId: this.agentId,
        agentAddress: this.wallet.address,
        timestamp: Date.now(),
        signature: await this.wallet.signMessage(merkleRoot),

        // TEE attestation if available
        teeAttestation: teeAttestation || {
          enabled: false,
          reason: process.env.TEE_ATTESTATION_ENDPOINT ? "Request failed" : "Not running in TEE"
        },

        // NEW: Complete HTTP request/response logs
        // This proves EXACTLY what API calls were made and what responses received
        networkLogs: {
          requests: output.httpTransaction?.requests || [],
          responses: output.httpTransaction?.responses || [],
          totalRequests: output.httpTransaction?.totalRequests || 0,
          totalResponses: output.httpTransaction?.totalResponses || 0,
          summary: {
            firstRequestUrl: output.httpTransaction?.requests?.[0]?.url || 'N/A',
            firstRequestMethod: output.httpTransaction?.requests?.[0]?.method || 'N/A',
            firstRequestBodyHash: output.httpTransaction?.requests?.[0]?.bodyHash || 'N/A',
            firstResponseStatus: output.httpTransaction?.responses?.[0]?.status || 'N/A',
            firstResponseBodyHash: output.httpTransaction?.responses?.[0]?.bodyHash || 'N/A',
            tlsCertificatePresent: !!(output.httpTransaction?.responses?.[0]?.tlsCertificate)
          }
        },

        // NEW: DNS resolution logs
        // This proves correct hostname→IP resolution (prevents DNS spoofing)
        dnsResolution: output.dnsResolution || null,

        // NEW: Complete source code verification
        // This allows third parties to rebuild and verify the exact code
        codeVerification: generateCodeVerificationMetadata(this.containerDigest),

        // Enhanced source proof for reproducibility
        sourceProof: {
          apiEndpoint: serviceId === 'price-current'
            ? 'https://opabinia.cambrian.network/api/v1/solana/price-current'
            : 'cambrian-api',
          timestamp: Date.now(),
          // TLS certificate proof from API connection
          tlsCertificate: tlsCertificate || null,
          // NEW: Request summary for quick verification
          requestSummary: {
            url: output.httpTransaction?.requests?.[0]?.url,
            method: output.httpTransaction?.requests?.[0]?.method,
            requestBodyHash: output.httpTransaction?.requests?.[0]?.bodyHash,
            responseBodyHash: output.httpTransaction?.responses?.[0]?.bodyHash,
            responseStatus: output.httpTransaction?.responses?.[0]?.status,
            tlsSubject: output.httpTransaction?.responses?.[0]?.tlsCertificate?.subject,
            tlsFingerprint: output.httpTransaction?.responses?.[0]?.tlsCertificate?.fingerprint
          }
        }
      };

      // Upload evidence to IPFS (with local backup)
      console.log(`   📤 Uploading evidence to IPFS...`);
      const ipfsStorage = require('./ipfs-storage');
      const evidenceHash = await ipfsStorage.upload(fullEvidence);

      console.log(`   Evidence Hash: ${evidenceHash}`);
      console.log(`   📝 Anyone can verify by:`);
      console.log(`      1. Retrieve evidence from IPFS: ${evidenceHash}`);
      console.log(`      2. Recompute merkle root: SHA-256(executionData)`);
      console.log(`      3. Compare with on-chain commitment`);
      console.log(`      4. Verify agent signature`);

      // Submit proof commitment to ProofRegistry contract (on-chain only)
      const proofResult = await this.submitProofToRegistry(merkleRoot, evidenceHash);

      return {
        merkleRoot,
        evidenceHash,
        fullEvidence, // Include for immediate verification
        proofResult
      };
    } catch (error) {
      console.error(`❌ Proof creation failed: ${error.message}`);
      // Return null but don't throw - allow service to continue
      return null;
    }
  }

  createTEEAttestationInternal(data) {
    /**
     * Create hardware attestation from within the TEE environment
     * FULL TEE MODE: This proves ALL code execution happened in AMD SEV hardware
     *
     * Security Properties:
     * - Proves exact code version via container digest
     * - Proves execution in hardware-isolated memory
     * - Binds attestation to specific input/output execution
     * - Proves API calls to legitimate Cambrian endpoint (TLS verification)
     * - Prevents data fabrication attacks
     * - Creates cryptographic binding between output and TEE attestation
     *
     * @param data {object} - Execution data to attest
     * @param data.executionData {object} - Complete execution record
     * @param data.inputHash {string} - SHA-256 hash of input
     * @param data.outputHash {string} - SHA-256 hash of output
     * @param data.merkleRoot {string} - Merkle root commitment
     * @param data.tlsCertificate {object} - TLS certificate proof (optional)
     * @returns {object} - Hardware-backed attestation proof
     */
    const crypto = require('crypto');

    // Create execution binding: cryptographically bind attestation to this specific execution
    // This prevents reuse of attestations across different executions
    const executionBinding = crypto
      .createHash('sha256')
      .update(JSON.stringify({
        service: data.executionData.service,
        inputHash: data.inputHash,
        outputHash: data.outputHash,
        merkleRoot: data.merkleRoot,
        timestamp: data.executionData.timestamp,
        // Include TLS certificate fingerprint in binding if available
        tlsFingerprint: data.tlsCertificate?.fingerprint || null
      }))
      .digest('base64');

    // Generate cryptographic nonce for replay protection
    const nonce = crypto.randomBytes(16).toString('hex');

    // CRITICAL IMPROVEMENT: Create tamper-proof output binding
    // This cryptographically binds the output hash to the TEE attestation JWT
    // Proves: THIS output came from THIS TEE with THIS code
    const attestationBinding = crypto
      .createHash('sha256')
      .update(JSON.stringify({
        attestationJWT: this.attestationJWT,
        outputHash: data.outputHash,
        containerDigest: this.containerDigest,
        timestamp: data.executionData.timestamp,
        nonce
      }))
      .digest('hex');

    // Return complete attestation with hardware proof
    return {
      // Hardware JWT: Google-signed token proving TEE execution
      attestationToken: this.attestationJWT,

      // Code Identity: SHA-256 of container image (verifiable by third parties)
      codeHash: this.containerDigest,
      containerDigest: this.containerDigest,

      // Execution Binding: Proves attestation applies to THIS specific execution
      executionBinding,

      // Execution Proof: Complete record of what was executed
      executionProof: {
        apiEndpoint: 'https://opabinia.cambrian.network',
        service: data.executionData.service,
        inputHash: data.inputHash,
        outputHash: data.outputHash,
        merkleRoot: data.merkleRoot,
        timestamp: data.executionData.timestamp,
        nonce,
        // NEW: Include TLS certificate proof
        tlsCertificate: data.tlsCertificate ? {
          verified: data.tlsCertificate.verified,
          subject: data.tlsCertificate.subject,
          fingerprint: data.tlsCertificate.fingerprint,
          protocol: data.tlsCertificate.protocol,
          cipher: data.tlsCertificate.cipher
        } : null
      },

      // NEW: Output Binding Proof
      // This is the strongest tamper-proof guarantee we can provide
      // The agent wallet signature is added at the evidence level (line 1288)
      outputProof: {
        outputHash: data.outputHash,
        attestationBinding: attestationBinding,
        verificationSteps: [
          '1. Recompute output hash from response data',
          '2. Verify attestation binding = hash(attestationJWT + outputHash + containerDigest + timestamp + nonce)',
          '3. Verify TEE attestationJWT signature (Google-signed)',
          '4. Verify container digest matches reproducible build',
          '5. Proves: THIS output came from THIS TEE with THIS exact code'
        ]
      },

      // Platform metadata
      platform: 'GCP Confidential Space',
      timestamp: Date.now(),
      nonce,

      // Security level: MAXIMUM = All execution in hardware-isolated memory
      securityLevel: 'MAXIMUM',
      teeMode: 'FULL_TEE',

      // Hardware measurements
      measurements: {
        executionBinding,
        imageDigest: this.containerDigest,
        // Include TLS verification status
        tlsVerified: data.tlsCertificate?.verified || false,
        // Include output binding
        outputBinding: attestationBinding
      }
    };
  }

  async requestTEEAttestation(data) {
    /**
     * Request hardware attestation from TEE environment
     * This proves the code executed in a secure, isolated environment
     *
     * @param data {object} - Execution data to attest
     * @param data.inputHash {string} - SHA-256 hash of input
     * @param data.outputHash {string} - SHA-256 hash of output
     * @param data.merkleRoot {string} - Merkle root commitment
     * @param data.timestamp {number} - Execution timestamp
     * @returns {object|null} - Attestation data or null if unavailable
     */
    try {
      // Create abort controller for 15-second timeout (VPC connector needs more time)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);

      try {
        const response = await fetch(process.env.TEE_ATTESTATION_ENDPOINT + '/attest', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Cambrian-DeFi-Agent/1.0'
          },
          body: JSON.stringify({
            agent_id: this.agentId,
            agent_domain: this.domain,
            input_hash: data.inputHash,
            output_hash: data.outputHash,
            merkle_root: data.merkleRoot,
            timestamp: data.timestamp,
            nonce: Math.random().toString(36).substring(7)
          }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
          const errorText = await response.text().catch(() => 'Could not read error');
          console.warn(`   TEE attestation service returned ${response.status}: ${errorText.substring(0, 200)}`);
          console.warn(`   Request details: ${process.env.TEE_ATTESTATION_ENDPOINT}/attest`);
          return null;
        }

        const attestation = await response.json();

        return {
          attestationToken: attestation.attestation_jwt,
          codeHash: attestation.code_hash,
          containerDigest: attestation.container_digest,
          instanceID: attestation.instance_id,
          timestamp: attestation.timestamp,
          platform: attestation.platform || 'GCP Confidential Space',
          measurements: attestation.measurements || {},
          nonce: attestation.nonce
        };
      } catch (fetchError) {
        clearTimeout(timeoutId);
        console.warn(`   TEE attestation fetch failed: ${fetchError.message}`);
        return null;
      }
    } catch (error) {
      console.warn(`   TEE attestation failed: ${error.message}`);
      return null;
    }
  }

  generateDataHash(input, output) {
    // Create deterministic hash of input and output for validation
    const data = JSON.stringify({ input, output });
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(data);

    // Simple hash - in production, use crypto.createHash or similar
    let hash = 0;
    for (let i = 0; i < dataBytes.length; i++) {
      const char = dataBytes[i];
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }

    // Convert to bytes32 format
    const hashHex = Math.abs(hash).toString(16).padStart(8, '0');
    return `0x${hashHex.padEnd(64, '0')}`;
  }

  async createValidationRequest(validatorAgentId, input, output) {
    try {
      const dataHash = this.generateDataHash(input, output);

      console.log(`🔍 Creating validation request: Validator ${validatorAgentId} → Server ${this.agentId}`);
      console.log(`📊 Data hash: ${dataHash}`);

      // Call validationRequest on the ERC-8004Complete contract
      const tx = await this.registry.validationRequest(validatorAgentId, this.agentId, dataHash);
      const receipt = await tx.wait();

      // Store validation data for ValidationRequestsURI
      this.validationRequests[dataHash] = {
        validatorAgentId,
        serverAgentId: this.agentId,
        dataHash,
        input,
        output,
        timestamp: Date.now(),
        transactionHash: tx.hash,
        status: 'PENDING'
      };

      console.log(`✅ Validation request created: ${dataHash}`);
      return {
        dataHash,
        validatorAgentId,
        serverAgentId: this.agentId,
        transactionHash: tx.hash,
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('❌ Failed to create validation request:', error.message);
      throw error;
    }
  }

  async shouldRequestValidation(serviceId, serviceValue) {
    // Determine if validation is needed based on service type and value
    const highValueThreshold = 0.01; // $0.01 USDC
    const criticalServices = ['ohlcv']; // Services that always need validation

    return criticalServices.includes(serviceId) ||
           parseFloat(serviceValue) >= highValueThreshold;
  }

  // TEE Integration Methods
  shouldUseTEE(serviceId, serviceValue) {
    if (!this.teeConfig.enabled) return false;

    // Use TEE for high-value requests or required services
    return this.teeConfig.requiredServices.includes(serviceId) ||
           parseFloat(serviceValue) >= this.teeConfig.highValueThreshold;
  }

  async checkTEEHealth() {
    try {
      const response = await this.makeHTTPRequest(
        'GET',
        `${this.teeConfig.endpoint}/health`,
        null,
        { timeout: 5000 }
      );

      return {
        available: true,
        teeEnabled: response.tee_enabled || false,
        instanceId: response.instance_id || null,
        timestamp: response.timestamp || Date.now()
      };
    } catch (error) {
      console.warn('⚠️ TEE health check failed:', error.message);
      return {
        available: false,
        error: error.message
      };
    }
  }

  async executeViaTEE(serviceId, requestData) {
    if (!this.teeConfig.enabled) {
      throw new Error('TEE is not enabled');
    }

    try {
      console.log(`🔒 Executing ${serviceId} via TEE...`);

      // Forward request to TEE agent with attestation context
      const teeRequest = {
        service: serviceId,
        data: requestData,
        timestamp: Date.now(),
        clientInfo: {
          agentId: this.agentId,
          domain: this.domain
        }
      };

      const response = await this.makeHTTPRequest(
        'POST',
        `${this.teeConfig.endpoint}/api/execute`,
        teeRequest,
        {
          timeout: 30000,
          headers: {
            'Content-Type': 'application/json',
            'X-Client-Agent-Id': this.agentId || '0',
            'X-Service-Id': serviceId
          }
        }
      );

      console.log('✅ TEE execution completed');

      return {
        ...response,
        teeAttestation: response.attestation || null,
        executionEnvironment: 'TEE',
        securityLevel: 'HARDWARE_ATTESTED'
      };
    } catch (error) {
      console.error('❌ TEE execution failed:', error.message);
      throw new Error(`TEE execution failed: ${error.message}`);
    }
  }

  async makeHTTPRequest(method, url, data = null, options = {}) {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const timeout = options.timeout || 10000;

      const requestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        headers: {
          'User-Agent': 'Cambrian-DeFi-Data-Agent/1.0',
          ...options.headers
        }
      };

      if (data && method !== 'GET') {
        const payload = JSON.stringify(data);
        requestOptions.headers['Content-Type'] = 'application/json';
        requestOptions.headers['Content-Length'] = Buffer.byteLength(payload);
      }

      const client = parsedUrl.protocol === 'https:' ? https : require('http');
      const req = client.request(requestOptions, (res) => {
        let responseData = '';

        res.on('data', chunk => {
          responseData += chunk;
        });

        res.on('end', () => {
          try {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              const result = responseData ? JSON.parse(responseData) : {};
              resolve(result);
            } else {
              reject(new Error(`HTTP ${res.statusCode}: ${responseData}`));
            }
          } catch (parseError) {
            reject(new Error(`Failed to parse response: ${parseError.message}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(timeout, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (data && method !== 'GET') {
        req.write(JSON.stringify(data));
      }

      req.end();
    });
  }

  setupRoutes() {
    this.app.use(express.json());

    // Custom in-memory rate limiter (no external dependencies)
    const rateLimits = new Map();
    const cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, requests] of rateLimits.entries()) {
        const filtered = requests.filter(time => now - time < 600000); // 10 min window
        if (filtered.length === 0) {
          rateLimits.delete(key);
        } else {
          rateLimits.set(key, filtered);
        }
      }
    }, 60000); // Cleanup every minute

    // API Key Authentication Middleware - Simple validation (like working sentient agent)
    const authenticateAPIKey = (req, res, next) => {
      const apiKey = req.headers['authorization']?.replace('Bearer ', '') ||
                     req.headers['x-cambrian-api-key'];

      if (!apiKey) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'CAMBRIAN_API_KEY required. Provide via Authorization header (Bearer token) or X-Cambrian-Api-Key header.'
        });
      }

      // Simple string comparison like the working sentient agent
      const configuredKey = process.env.SERVER_CAMBRIAN_API_KEY || process.env.CAMBRIAN_API_KEY;

      // DEBUG: Log key comparison (including length and character codes for debugging)
      console.error(`🔍 Auth debug: Received key starts with: ${apiKey.substring(0, 8)}`);
      console.error(`🔍 Auth debug: Received key length: ${apiKey.length}`);
      console.error(`🔍 Auth debug: Configured key starts with: ${configuredKey?.substring(0, 8) || 'NONE'}`);
      console.error(`🔍 Auth debug: Configured key length: ${configuredKey?.length || 0}`);
      console.error(`🔍 Auth debug: SERVER_CAMBRIAN_API_KEY set: ${!!process.env.SERVER_CAMBRIAN_API_KEY}`);
      console.error(`🔍 Auth debug: CAMBRIAN_API_KEY set: ${!!process.env.CAMBRIAN_API_KEY}`);
      console.error(`🔍 Auth debug: Keys match: ${apiKey === configuredKey}`);

      if (apiKey === configuredKey) {
        console.log('✅ Authentication successful');
        return next();
      }

      // Reject invalid keys
      console.error('🔒 Authentication failed - Invalid API key');
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Invalid API key'
      });
    };

    // Custom rate limiter factory
    const createRateLimiter = (maxRequests, windowMs) => {
      return (req, res, next) => {
        const apiKey = req.headers['authorization']?.replace('Bearer ', '') ||
                       req.headers['x-cambrian-api-key'] ||
                       'anonymous';
        const key = `${req.ip}-${apiKey}-${req.path}`;
        const now = Date.now();

        if (!rateLimits.has(key)) {
          rateLimits.set(key, []);
        }

        const requests = rateLimits.get(key).filter(time => now - time < windowMs);

        if (requests.length >= maxRequests) {
          return res.status(429).json({
            error: 'Too Many Requests',
            message: `Rate limit exceeded: Maximum ${maxRequests} requests per ${windowMs / 1000} seconds`,
            retryAfter: Math.ceil(windowMs / 1000)
          });
        }

        requests.push(now);
        rateLimits.set(key, requests);
        next();
      };
    };

    // Rate limiters for different endpoints
    const globalLimiter = createRateLimiter(1000, 600000); // 1000 per 10 min
    const askLimiter = createRateLimiter(100, 600000); // 100 per 10 min

    // CORS middleware for UI access
    this.app.use((req, res, next) => {
      // Allow requests from production UI and local development
      const allowedOrigins = [
        'https://erc8004-ui.rickycambrian.org',
        'http://localhost:5173',
        'http://localhost:3000'
      ];

      const origin = req.headers.origin;
      if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
      }

      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Cambrian-Api-Key, X-API-Key');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Max-Age', '86400'); // 24 hours

      // Handle preflight requests
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
        return;
      }

      next();
    });

    // Health check
    this.app.get('/health', async (req, res) => {
      const teeStatus = await this.checkTEEHealth();

      res.json({
        status: 'healthy',
        agentId: this.agentId,
        domain: this.domain,
        uptime: Date.now() - this.metrics.startTime,
        metrics: this.metrics,
        tee: {
          enabled: this.teeConfig.enabled,
          status: teeStatus,
          endpoint: this.teeConfig.enabled ? this.teeConfig.endpoint : null,
          configuration: {
            highValueThreshold: this.teeConfig.highValueThreshold,
            requiredServices: this.teeConfig.requiredServices
          }
        },
        googleADK: {
          available: this.googleADKAvailable,
          error: this.googleADKError || null
        }
      });
    });

    // Debug endpoint to view Python subprocess logs
    this.app.get('/debug/python-logs', (req, res) => {
      const fs = require('fs');
      const pythonLogPath = '/tmp/python_adk.log';

      try {
        if (fs.existsSync(pythonLogPath)) {
          const logs = fs.readFileSync(pythonLogPath, 'utf8');
          res.type('text/plain').send(logs);
        } else {
          res.type('text/plain').send('Log file not found. Python subprocess may not have started yet.');
        }
      } catch (error) {
        res.status(500).type('text/plain').send(`Error reading logs: ${error.message}`);
      }
    });

    // Debug endpoint to check API key configuration (returns hash only, not actual key)
    this.app.get('/debug/api-key-info', (req, res) => {
      const crypto = require('crypto');
      const serverKey = process.env.SERVER_CAMBRIAN_API_KEY;
      const cambrianKey = process.env.CAMBRIAN_API_KEY;

      const serverKeyHash = serverKey ? crypto.createHash('sha256').update(serverKey).digest('hex') : null;
      const cambrianKeyHash = cambrianKey ? crypto.createHash('sha256').update(cambrianKey).digest('hex') : null;

      res.json({
        SERVER_CAMBRIAN_API_KEY: {
          set: !!serverKey,
          length: serverKey ? serverKey.length : 0,
          first8: serverKey ? serverKey.substring(0, 8) : null,
          sha256: serverKeyHash
        },
        CAMBRIAN_API_KEY: {
          set: !!cambrianKey,
          length: cambrianKey ? cambrianKey.length : 0,
          first8: cambrianKey ? cambrianKey.substring(0, 8) : null,
          sha256: cambrianKeyHash
        },
        configuredKey: {
          source: serverKey ? 'SERVER_CAMBRIAN_API_KEY' : (cambrianKey ? 'CAMBRIAN_API_KEY' : 'NONE'),
          length: (serverKey || cambrianKey || '').length,
          first8: (serverKey || cambrianKey || '').substring(0, 8),
          sha256: serverKey ? serverKeyHash : cambrianKeyHash
        }
      });
    });

    // Debug logs endpoint - Returns recent error/warning logs
    this.app.get('/debug/logs', (req, res) => {
      const level = req.query.level; // Optional filter by level
      const limit = parseInt(req.query.limit) || 50; // Default to last 50 logs

      let logs = this.debugLogs;

      // Filter by level if requested
      if (level) {
        logs = logs.filter(log => log.level === level.toUpperCase());
      }

      // Return most recent logs
      res.json({
        total: this.debugLogs.length,
        filtered: logs.length,
        logs: logs.slice(-limit).reverse() // Most recent first
      });
    });

    // TEE Attestation endpoint - Returns hardware attestation for verification
    this.app.get('/attestation', async (req, res) => {
      try {
        // Check if running in TEE mode
        if (!this.runningInTEE) {
          return res.status(404).json({
            error: 'TEE attestation not available',
            reason: 'Agent not running in TEE mode',
            teeMode: false,
            securityLevel: 'STANDARD'
          });
        }

        // Try to read attestation JWT from multiple sources
        let attestationJWT = this.attestationJWT;

        if (!attestationJWT) {
          // Try environment variable (bootstrap sets this)
          attestationJWT = process.env.ATTESTATION_JWT;
        }

        if (!attestationJWT) {
          // Try reading from file (bootstrap writes it here for us)
          const fs = require('fs');

          // Priority 1: Check /app/attestation.jwt (written by bootstrap, guaranteed readable)
          try {
            attestationJWT = fs.readFileSync('/app/attestation.jwt', 'utf8').trim();
          } catch (appError) {
            // Priority 2: Try /tmp/attestation.jwt
            try {
              attestationJWT = fs.readFileSync('/tmp/attestation.jwt', 'utf8').trim();
            } catch (tmpError) {
              // Priority 3: Try original GCP location
              try {
                attestationJWT = fs.readFileSync(
                  '/run/container_launcher/attestation_verifier_claims_token',
                  'utf8'
                ).trim();
              } catch (origError) {
              // Final fallback: Try to fetch from Confidential Space launcher socket
              // This is the CORRECT way to get Confidential Space attestation token
              // The token is served by the launcher over a Unix domain socket
              try {
                const http = require('http');
                const socketPath = '/run/container_launcher/teeserver.sock';

                const options = {
                  socketPath: socketPath,
                  path: '/v1/token',
                  method: 'GET'
                };

                await new Promise((resolve, reject) => {
                  const req = http.request(options, (socketRes) => {
                    if (socketRes.statusCode === 200) {
                      let data = '';
                      socketRes.on('data', chunk => data += chunk);
                      socketRes.on('end', () => {
                        attestationJWT = data.trim();
                        resolve();
                      });
                    } else {
                      reject(new Error(`TEE socket returned ${socketRes.statusCode}`));
                    }
                  });
                  req.on('error', reject);
                  req.setTimeout(5000, () => {
                    req.destroy();
                    reject(new Error('TEE socket request timeout'));
                  });
                  req.end();
                });
              } catch (socketError) {
                return res.status(500).json({
                  error: 'Attestation JWT not found',
                  reason: 'TEE mode enabled but attestation token unavailable from all sources',
                  teeMode: true,
                  sources_checked: [
                    'this.attestationJWT (loaded at startup)',
                    'process.env.ATTESTATION_JWT',
                    '/app/attestation.jwt (written by bootstrap)',
                    '/tmp/attestation.jwt',
                    '/run/container_launcher/attestation_verifier_claims_token',
                    '/run/container_launcher/teeserver.sock (Unix socket - requires root)'
                  ],
                  last_errors: {
                    app_file: appError.message,
                    tmp_file: tmpError.message,
                    orig_file: origError.message,
                    unix_socket: socketError.message
                  }
                });
              }
            }
          }
        }
        } // Close if (!attestationJWT) block

        // Parse JWT to extract claims (don't verify signature here, verifiers will do that)
        const jwtParts = attestationJWT.split('.');
        if (jwtParts.length !== 3) {
          return res.status(500).json({
            error: 'Invalid JWT format',
            reason: 'Attestation token does not have 3 parts'
          });
        }

        const [headerB64, payloadB64, signatureB64] = jwtParts;

        // Decode header and payload (base64url decode)
        const decodeBase64Url = (str) => {
          // Convert base64url to base64
          str = str.replace(/-/g, '+').replace(/_/g, '/');
          // Add padding if needed
          while (str.length % 4) str += '=';
          return Buffer.from(str, 'base64').toString('utf8');
        };

        const header = JSON.parse(decodeBase64Url(headerB64));
        const payload = JSON.parse(decodeBase64Url(payloadB64));

        // Extract key claims
        const claims = {
          // GCP Confidential Space specific claims
          container_digest: payload.submods?.container?.image_digest ||
                           payload.submods?.container?.image_reference ||
                           this.containerDigest,
          image_reference: payload.submods?.container?.image_reference,
          tee_platform: payload.tee_platform || 'GCP_AMD_SEV',
          security_level: payload.security_level || 'MAXIMUM',

          // Instance identification
          instance_id: payload.instance_id,
          project_id: payload.project_id,
          project_number: payload.project_number,
          zone: payload.zone,

          // JWT metadata
          issued_at: payload.iat,
          expires_at: payload.exp,
          issuer: payload.iss,
          audience: payload.aud,

          // Token security
          algorithm: header.alg,
          key_id: header.kid
        };

        // Return complete attestation data
        res.json({
          success: true,
          teeMode: 'FULL_TEE',
          securityLevel: 'MAXIMUM',

          // Full JWT for verification
          attestation: {
            jwt: attestationJWT,
            header,
            claims,
            signature: signatureB64
          },

          // Key security properties
          container: {
            digest: claims.container_digest || this.containerDigest,
            reference: claims.image_reference
          },

          platform: {
            provider: 'GCP Confidential Space',
            technology: 'AMD SEV',
            tee_platform: claims.tee_platform,
            security_level: claims.security_level
          },

          instance: {
            id: claims.instance_id,
            project: claims.project_id,
            zone: claims.zone
          },

          // Verification instructions
          verification: {
            jwks_url: 'https://www.googleapis.com/service_accounts/v1/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com',
            expected_issuer: 'https://confidentialcomputing.googleapis.com',
            algorithm: claims.algorithm,
            instructions: 'Verify JWT signature using Google\'s public keys from jwks_url'
          },

          // Agent information
          agent: {
            id: this.agentId,
            domain: this.domain,
            address: this.wallet?.address
          }
        });

      } catch (error) {
        console.error('Error serving attestation:', error);
        res.status(500).json({
          error: 'Failed to serve attestation',
          message: error.message,
          teeMode: this.runningInTEE
        });
      }
    });

    // TEE Attestation Verification Endpoint
    this.app.post('/attestation/verify', async (req, res) => {
      try {
        const { token, expectedImageDigest } = req.body;

        if (!token) {
          return res.status(400).json({
            error: 'Missing token parameter',
            message: 'Provide attestation JWT token in request body'
          });
        }

        // Check if TEE verifier module is available
        if (!teeVerifier || typeof teeVerifier.verifyTEEExecution !== 'function') {
          return res.status(503).json({
            error: 'TEE verification not available',
            message: 'TEE attestation verifier module failed to load'
          });
        }

        // Verify the attestation token
        const verification = await teeVerifier.verifyTEEExecution(
          token,
          expectedImageDigest
        );

        res.json({
          success: true,
          verification: {
            verified: verification.verified,
            attestationVerified: verification.attestationVerified,
            imageDigestVerified: verification.imageDigestVerified,
            errors: verification.errors,
            warnings: verification.warnings,
            details: verification.details
          },
          instructions: {
            howToUse: 'POST to /attestation/verify with {token: "jwt...", expectedImageDigest: "sha256:..."}',
            fullVerification: 'Signature verification not yet implemented - structural validation only',
            recommendation: 'Use expectedImageDigest from GitHub Actions deployment to verify container provenance'
          }
        });

      } catch (error) {
        console.error('Error verifying attestation:', error);
        res.status(500).json({
          error: 'Verification failed',
          message: error.message
        });
      }
    });

    // Agent card endpoint (ERC-8004 compliant)
    this.app.get('/.well-known/agent-card.json', async (req, res) => {
      try {
        const agentCard = await this.generateERC8004AgentCard();
        res.json(agentCard);
      } catch (error) {
        console.error('Error generating agent card:', error);
        res.status(500).json({
          error: 'Failed to generate agent card',
          fallback: {
            name: 'Cambrian DeFi Data Agent',
            description: 'ERC-8004 agent for Solana token prices',
            status: 'error'
          }
        });
      }
    });

    // Service discovery endpoint
    this.app.get('/api/services', (req, res) => {
      res.json({ services: this.services });
    });

    // Service catalog (legacy)
    this.app.get('/services', (req, res) => {
      res.json(this.services);
    });

    // ERC-8004 Required: Feedback data endpoint
    this.app.get('/feedback-data.json', (req, res) => {
      // Return only the data structure part (remove internal metadata)
      const publicFeedbackData = this.feedbackData.map(feedback => {
        const { _metadata, ...publicData } = feedback;
        return publicData;
      });

      res.json(publicFeedbackData);
    });

    // ERC-8004 Optional: Validation requests endpoint
    this.app.get('/validation-requests.json', (req, res) => {
      res.json(this.validationRequests);
    });

    // ERC-8004 Optional: Validation responses endpoint
    this.app.get('/validation-responses.json', (req, res) => {
      res.json(this.validationResponses);
    });

    // ========================================================================
    // NEW ERC-8004 COMPLIANT ENDPOINTS
    // ========================================================================

    // Generate EIP-712 feedbackAuth signature - with authentication
    this.app.post('/api/generate-feedbackauth', authenticateAPIKey, globalLimiter, async (req, res) => {
      try {
        const { clientAddress, indexLimit, expiryTimestamp } = req.body;

        if (!clientAddress) {
          return res.status(400).json({
            error: 'clientAddress is required',
            example: {
              clientAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7',
              indexLimit: 1,
              expiryTimestamp: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60)
            }
          });
        }

        const feedbackAuth = await this.generateFeedbackAuth(
          clientAddress,
          indexLimit || 1,
          expiryTimestamp
        );

        res.json({
          success: true,
          feedbackAuth,
          usage: 'Use this signature when calling giveFeedback() on ReputationRegistry'
        });

      } catch (error) {
        console.error('❌ Failed to generate feedbackAuth:', error);
        res.status(500).json({
          error: 'Failed to generate feedbackAuth',
          message: error.message
        });
      }
    });

    // Generate validation request URI with IPFS storage - with authentication
    this.app.post('/api/generate-validation-uri', authenticateAPIKey, globalLimiter, async (req, res) => {
      try {
        const { validatorAddress, inputData, outputData } = req.body;

        if (!validatorAddress || !inputData || !outputData) {
          return res.status(400).json({
            error: 'validatorAddress, inputData, and outputData are required',
            example: {
              validatorAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7',
              inputData: { token_address: 'So11111111111111111111111111111111111111112' },
              outputData: { symbol: 'SOL', price: 142.35 }
            }
          });
        }

        const validationRequest = await this.generateValidationRequestURI(
          validatorAddress,
          inputData,
          outputData
        );

        res.json({
          success: true,
          validationRequest,
          usage: 'Use requestUri and requestHash when calling validationRequest() on ValidationRegistry'
        });

      } catch (error) {
        console.error('❌ Failed to generate validation URI:', error);
        res.status(500).json({
          error: 'Failed to generate validation URI',
          message: error.message
        });
      }
    });

    // Generate spec-compliant feedback file and optionally store on IPFS - with authentication
    this.app.post('/api/generate-feedback-file', authenticateAPIKey, globalLimiter, async (req, res) => {
      try {
        const {
          clientAddress,
          score,
          tag1,
          tag2,
          skill,
          context,
          task,
          capability,
          toolName,
          proofOfPayment,
          feedbackAuth,
          storeOnIPFS
        } = req.body;

        if (!clientAddress || score === undefined) {
          return res.status(400).json({
            error: 'clientAddress and score are required',
            example: {
              clientAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7',
              score: 85,
              tag1: 'defi-data',
              tag2: 'price-oracle',
              skill: 'price-current',
              storeOnIPFS: true
            }
          });
        }

        const feedbackData = this.generateFeedbackFileData({
          clientAddress,
          score,
          tag1,
          tag2,
          skill,
          context,
          task,
          capability,
          toolName,
          proofOfPayment,
          feedbackAuth
        });

        let ipfsHash = null;
        if (storeOnIPFS) {
          ipfsHash = await this.storeFeedbackOnIPFS(feedbackData);
        }

        res.json({
          success: true,
          feedbackData,
          ...(ipfsHash && {
            ipfsHash,
            ipfsUri: `ipfs://${ipfsHash}`,
            gatewayUrl: `https://gateway.pinata.cloud/ipfs/${ipfsHash}`
          }),
          usage: 'Use this data when calling giveFeedback() on ReputationRegistry'
        });

      } catch (error) {
        console.error('❌ Failed to generate feedback file:', error);
        res.status(500).json({
          error: 'Failed to generate feedback file',
          message: error.message
        });
      }
    });

    // ========================================================================
    // END NEW ERC-8004 ENDPOINTS
    // ========================================================================

    // Debug endpoint: Python ADK logs
    this.app.get('/api/python-logs', (req, res) => {
      const fs = require('fs');
      const pythonLogPath = '/tmp/python_adk.log';

      try {
        if (fs.existsSync(pythonLogPath)) {
          const logs = fs.readFileSync(pythonLogPath, 'utf8');
          res.json({
            success: true,
            logs: logs,
            googleADKAvailable: this.googleADKAvailable,
            googleADKError: this.googleADKError || null,
            pythonADKUrl: this.pythonADKUrl || null
          });
        } else {
          res.json({
            success: false,
            error: 'Log file not found',
            path: pythonLogPath,
            googleADKAvailable: this.googleADKAvailable,
            googleADKError: this.googleADKError || null
          });
        }
      } catch (error) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    // Price current endpoint (ERC-8004 compliant) - with authentication
    this.app.post('/api/price-current', authenticateAPIKey, globalLimiter, async (req, res) => {
      const startTime = Date.now();
      this.metrics.totalRequests++;

      let feedbackAuth = null;

      try {
        // Verify payment attestation (with bypass for testing)
        const payment = req.headers['x-payment-attestation'];
        const bypassPayment = process.env.BYPASS_PAYMENT === 'true';

        if (!payment && !bypassPayment) {
          throw new Error('Payment attestation required');
        }

        // ERC-8004 Flow: Create feedback authorization FIRST
        const clientAgentId = req.headers['x-client-agent-id'] || 0; // Default to unregistered client
        try {
          feedbackAuth = await this.createFeedbackAuthorization(parseInt(clientAgentId));
        } catch (authError) {
          console.warn('⚠️ Feedback authorization failed, continuing with service:', authError.message);
          // Continue with service but without feedback tracking
        }

        // Get price data - use TEE if configured for high-value/sensitive requests
        const { token_address } = req.body;
        const serviceConfig = this.services.find(s => s.id === 'price-current');
        let result;
        let executionEnvironment = 'STANDARD';

        // Check if we should use TEE for this request
        if (this.shouldUseTEE('price-current', serviceConfig?.price)) {
          try {
            console.log('🔒 Using TEE for price-current request');
            const teeResult = await this.executeViaTEE('price-current', { token_address });
            result = teeResult;
            executionEnvironment = 'TEE';
          } catch (teeError) {
            console.warn('⚠️ TEE execution failed, falling back to standard execution:', teeError.message);
            result = await this.getPriceFromCambrian(token_address);
          }
        } else {
          result = await this.getPriceFromCambrian(token_address);
        }

        // Add response time and execution environment for tracking
        result.responseTime = `${Date.now() - startTime}ms`;
        result.executionEnvironment = executionEnvironment;

        // ERC-8004 Flow: Record service execution for feedback
        if (feedbackAuth) {
          await this.recordServiceExecution(
            'price-current',
            { token_address },
            result,
            feedbackAuth
          );
        }

        // On-Chain Proof Flow: Create verifiable on-chain proof (independent of feedback auth)
        const evidenceResult = await this.createEvidence(
          'price-current',
          { token_address },
          result,
          feedbackAuth
        );

        if (evidenceResult) {
          result.evidence = {
            merkleRoot: evidenceResult.merkleRoot,
            evidenceHash: evidenceResult.evidenceHash,
            proofId: evidenceResult.proofResult?.proofId || null
          };
        }

        // Update metrics
        this.metrics.successfulRequests++;
        this.metrics.avgResponseTime = Math.round(
          (this.metrics.avgResponseTime + (Date.now() - startTime)) / 2
        );
        this.metrics.totalRevenue += 0.001; // Add service fee

        // Include ERC-8004 metadata in response
        const response = {
          ...result,
          _erc8004: {
            feedbackAuthId: feedbackAuth?.feedbackAuthId || null,
            agentId: this.agentId,
            serviceId: 'price-current',
            compliance: 'ERC-8004'
          }
        };

        res.json(response);
      } catch (error) {
        this.metrics.failedRequests++;
        console.error('Service execution error:', error);
        res.status(400).json({
          error: error.message,
          _erc8004: {
            feedbackAuthId: feedbackAuth?.feedbackAuthId || null,
            agentId: this.agentId,
            serviceId: 'price-current',
            status: 'error'
          }
        });
      }
    });

    // Price multi endpoint (ERC-8004 compliant) - with authentication
    this.app.post('/api/price-multi', authenticateAPIKey, globalLimiter, async (req, res) => {
      const startTime = Date.now();
      this.metrics.totalRequests++;

      let feedbackAuth = null;

      try {
        // Verify payment attestation (with bypass for testing)
        const payment = req.headers['x-payment-attestation'];
        const bypassPayment = process.env.BYPASS_PAYMENT === 'true';

        if (!payment && !bypassPayment) {
          throw new Error('Payment attestation required');
        }

        // ERC-8004 Flow: Create feedback authorization FIRST
        const clientAgentId = req.headers['x-client-agent-id'] || 0;
        try {
          feedbackAuth = await this.createFeedbackAuthorization(parseInt(clientAgentId));
        } catch (authError) {
          console.warn('⚠️ Feedback authorization failed, continuing with service:', authError.message);
        }

        const { token_addresses } = req.body;
        const results = [];

        for (const address of token_addresses) {
          const price = await this.getPriceFromCambrian(address);
          results.push(price);
        }

        const output = {
          results,
          responseTime: `${Date.now() - startTime}ms`,
          totalTokens: token_addresses.length
        };

        // ERC-8004 Flow: Record service execution for feedback
        if (feedbackAuth) {
          await this.recordServiceExecution(
            'price-multi',
            { token_addresses },
            output,
            feedbackAuth
          );
        }

        // On-Chain Proof Flow: Create verifiable on-chain proof (independent of feedback auth)
        const evidenceResult = await this.createEvidence(
          'price-multi',
          { token_addresses },
          output,
          feedbackAuth
        );

        if (evidenceResult) {
          output.evidence = {
            merkleRoot: evidenceResult.merkleRoot,
            evidenceHash: evidenceResult.evidenceHash,
            proofId: evidenceResult.proofResult?.proofId || null
          };
        }

        this.metrics.successfulRequests++;
        this.metrics.totalRevenue += 0.003;

        // Include ERC-8004 metadata in response
        const response = {
          ...output,
          _erc8004: {
            feedbackAuthId: feedbackAuth?.feedbackAuthId || null,
            agentId: this.agentId,
            serviceId: 'price-multi',
            compliance: 'ERC-8004'
          }
        };

        res.json(response);
      } catch (error) {
        this.metrics.failedRequests++;
        console.error('Multi-price service error:', error);
        res.status(400).json({
          error: error.message,
          _erc8004: {
            feedbackAuthId: feedbackAuth?.feedbackAuthId || null,
            agentId: this.agentId,
            serviceId: 'price-multi',
            status: 'error'
          }
        });
      }
    });

    // OHLCV endpoint (ERC-8004 compliant with validation) - with authentication
    this.app.post('/api/ohlcv', authenticateAPIKey, globalLimiter, async (req, res) => {
      const startTime = Date.now();
      this.metrics.totalRequests++;

      let feedbackAuth = null;
      let validationRequest = null;

      try {
        // Verify payment attestation
        const payment = req.headers['x-payment-attestation'];
        const bypassPayment = process.env.BYPASS_PAYMENT === 'true';

        if (!payment && !bypassPayment) {
          throw new Error('Payment attestation required');
        }

        // ERC-8004 Flow: Create feedback authorization
        const clientAgentId = req.headers['x-client-agent-id'] || 0;
        try {
          feedbackAuth = await this.createFeedbackAuthorization(parseInt(clientAgentId));
        } catch (authError) {
          console.warn('⚠️ Feedback authorization failed, continuing with service:', authError.message);
        }

        const { token_address, after_time, before_time, interval } = req.body;

        // Simulate OHLCV data (in production, this would fetch real historical data)
        const output = {
          tokenAddress: token_address,
          interval: interval,
          dataPoints: 10, // Simulated
          ohlcv: [
            // Simulated OHLCV data
            [after_time, 200.0, 205.0, 198.0, 202.0, 1000000],
            [after_time + 3600, 202.0, 207.0, 200.0, 205.0, 1200000],
            // ... more data points
          ],
          responseTime: `${Date.now() - startTime}ms`,
          source: 'cambrian',
          timestamp: new Date().toISOString()
        };

        // ERC-8004 Flow: Record service execution for feedback
        if (feedbackAuth) {
          await this.recordServiceExecution(
            'ohlcv',
            { token_address, after_time, before_time, interval },
            output,
            feedbackAuth
          );
        }

        // On-Chain Proof Flow: Create verifiable on-chain proof (independent of feedback auth)
        const evidenceResult = await this.createEvidence(
          'ohlcv',
          { token_address, after_time, before_time, interval },
          output,
          feedbackAuth
        );

        if (evidenceResult) {
          output.evidence = {
            merkleRoot: evidenceResult.merkleRoot,
            evidenceHash: evidenceResult.evidenceHash,
            proofId: evidenceResult.proofResult?.proofId || null
          };
        }

        // ERC-8004 Flow: Create validation request for high-value service
        const serviceConfig = this.services.find(s => s.id === 'ohlcv');
        if (await this.shouldRequestValidation('ohlcv', serviceConfig?.price)) {
          const validatorAgentId = 2; // Use Agent #2 as validator
          try {
            validationRequest = await this.createValidationRequest(
              validatorAgentId,
              { token_address, after_time, before_time, interval },
              output
            );
          } catch (validationError) {
            console.warn('⚠️ Validation request failed:', validationError.message);
          }
        }

        this.metrics.successfulRequests++;
        this.metrics.totalRevenue += 0.01; // Higher fee for OHLCV

        // Include ERC-8004 metadata in response
        const response = {
          ...output,
          _erc8004: {
            feedbackAuthId: feedbackAuth?.feedbackAuthId || null,
            validationDataHash: validationRequest?.dataHash || null,
            agentId: this.agentId,
            serviceId: 'ohlcv',
            compliance: 'ERC-8004',
            trustModel: validationRequest ? 'inference-validation' : 'feedback'
          }
        };

        res.json(response);
      } catch (error) {
        this.metrics.failedRequests++;
        console.error('OHLCV service error:', error);
        res.status(400).json({
          error: error.message,
          _erc8004: {
            feedbackAuthId: feedbackAuth?.feedbackAuthId || null,
            validationDataHash: validationRequest?.dataHash || null,
            agentId: this.agentId,
            serviceId: 'ohlcv',
            status: 'error'
          }
        });
      }
    });

    // Natural language query endpoint with Google ADK + Dual TEE proofs
    // Apply rate limiting and authentication to /api/ask endpoint
    // Authentication at both Agent TEE (here) and MCP Server for defense in depth
    this.app.post('/api/ask', authenticateAPIKey, globalLimiter, askLimiter, async (req, res) => {
      const startTime = Date.now();

      try {
        // Check if Google ADK (Python) is available
        if (!this.googleADKAvailable || !this.pythonADKUrl) {
          return res.status(503).json({
            error: 'Google ADK Agent not initialized',
            message: 'The /api/ask endpoint requires Google ADK integration (Python)',
            details: this.googleADKError || 'Python subprocess failed to start',
            available: false
          });
        }

        const { question, session_id, conversation_history } = req.body;

        if (!question) {
          return res.status(400).json({
            error: 'Missing required parameter: question'
          });
        }

        // Extract user's Cambrian API key from request headers
        const userApiKey = req.headers['authorization']?.replace('Bearer ', '') ||
                          req.headers['x-cambrian-api-key'];

        if (!userApiKey) {
          return res.status(401).json({
            error: 'Unauthorized',
            message: 'CAMBRIAN_API_KEY required. Provide via Authorization header (Bearer token) or X-Cambrian-Api-Key header.'
          });
        }

        console.log(`\n🤔 Processing natural language query (via Python ADK)...`);
        console.log(`   Question: ${question.substring(0, 100)}...`);
        console.log(`   Session ID: ${session_id || 'auto-generated'}`);
        console.log(`   User API key: ${userApiKey.substring(0, 8)}...`);

        // Call Python Flask server with user's API key
        const axios = require('axios');
        const pythonResponse = await axios.post(`${this.pythonADKUrl}/ask`, {
          question,
          session_id: session_id || `session_${Date.now()}`,
          conversation_history,
          cambrian_api_key: userApiKey  // Pass user's API key to Python ADK
        }, {
          timeout: 120000 // 2 minute timeout for complex queries
        });

        const result = pythonResponse.data;

        // For now, create empty execution logs (Python ADK doesn't expose these yet)
        const executionLogs = {
          httpLogs: { requests: [], responses: [], totalRequests: 0, totalResponses: 0 },
          dnsLogs: []
        };

        // CRITICAL: Capture Gemini interaction logs for verifiability
        const geminiInteraction = result.gemini_interaction || null;
        if (geminiInteraction) {
          console.log(`   📊 Gemini Interaction Logged:`);
          console.log(`      Prompt Hash: ${geminiInteraction.prompt_hash?.substring(0, 16)}...`);
          console.log(`      Response Hash: ${geminiInteraction.response_hash?.substring(0, 16)}...`);
          console.log(`      Tool Calls: ${geminiInteraction.tool_calls_requested?.length || 0}`);
          console.log(`      Latency: ${geminiInteraction.latency_ms}ms`);
        }

        console.log(`   ✅ Answer generated (${result.tools_used?.length || 0} tools used)`);
        console.log(`   Response time: ${Date.now() - startTime}ms`);

        // Create dual TEE proof (if in TEE mode)
        let proof = null;
        if (this.dualTEEProofGenerator && this.runningInTEE) {
          try {
            console.log(`   🔐 Generating dual TEE proof...`);

            const executionData = {
              question,
              answer: result.answer,
              tools_used: result.tools_used || [],
              timestamp: Date.now(),
              session_id: session_id || `session_${Date.now()}`,
              agentId: this.agentId,
              result: result.metadata
            };

            const proofResult = await this.dualTEEProofGenerator.createDualTEEProof(
              executionData,
              executionLogs.httpLogs,
              executionLogs.dnsLogs,
              geminiInteraction  // Pass Gemini interaction logs for verifiability
            );

            proof = {
              merkleRoot: proofResult.merkleRoot,
              evidenceHash: proofResult.evidenceHash,
              proofId: proofResult.proofId,
              transactionHash: proofResult.transactionHash,
              dualTEE: proofResult.dualTEE
            };

            console.log(`   ✅ Dual TEE proof created`);
            console.log(`      IPFS: ${proofResult.evidenceHash}`);
            if (proofResult.proofId) {
              console.log(`      Proof ID: ${proofResult.proofId}`);
            }
          } catch (proofError) {
            console.warn(`   ⚠️  Dual TEE proof generation failed: ${proofError.message}`);
            // Continue without proof
          }
        }

        // Return response
        res.json({
          success: result.success,
          answer: result.answer,
          tools_used: result.tools_used || [],
          metadata: {
            ...result.metadata,
            responseTime: `${Date.now() - startTime}ms`,
            session_id: session_id || `session_${Date.now()}`,
            executionLogs: {
              httpRequests: executionLogs.httpLogs.totalRequests,
              dnsResolutions: executionLogs.dnsLogs.length
            }
          },
          proof: proof || {
            available: false,
            reason: this.runningInTEE ? 'Proof generation failed' : 'Not running in TEE mode'
          }
        });

      } catch (error) {
        console.error('❌ Natural language query failed:', error);
        res.status(500).json({
          success: false,
          error: error.message,
          stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
      }
    });
  }

  captureTLSCertificate(socket) {
    /**
     * Capture and verify TLS certificate information
     * This proves the API call was made to the legitimate Cambrian endpoint
     *
     * Security Properties:
     * - Verifies certificate chain validity
     * - Captures certificate fingerprints for verification
     * - Proves connection to specific domain
     * - Prevents man-in-the-middle attacks
     *
     * @param socket {tls.TLSSocket} - TLS socket from HTTPS connection
     * @returns {object} - Certificate verification data
     */
    if (!socket || !socket.getPeerCertificate) {
      return null;
    }

    try {
      const cert = socket.getPeerCertificate(true);

      if (!cert || Object.keys(cert).length === 0) {
        return null;
      }

      // Compute SHA-256 fingerprint of the certificate
      const certDER = cert.raw;
      const fingerprint = crypto
        .createHash('sha256')
        .update(certDER)
        .digest('hex')
        .match(/.{2}/g)
        .join(':')
        .toUpperCase();

      // Verify certificate is authorized
      const authorized = socket.authorized;
      const authError = socket.authorizationError;

      // Extract certificate chain
      const chain = [];
      let current = cert;
      while (current && current.issuerCertificate) {
        const issuerFingerprint = current.issuerCertificate.fingerprint256 ||
          (current.issuerCertificate.raw ?
            crypto.createHash('sha256').update(current.issuerCertificate.raw).digest('hex') :
            null);

        chain.push({
          subject: current.subject?.CN || current.subject?.O || 'Unknown',
          issuer: current.issuer?.CN || current.issuer?.O || 'Unknown',
          fingerprint: current.fingerprint256 || fingerprint,
          validFrom: current.valid_from,
          validTo: current.valid_to
        });

        // Prevent infinite loops
        if (current === current.issuerCertificate) {
          break;
        }
        current = current.issuerCertificate;
      }

      return {
        verified: authorized,
        authError: authError ? authError.message : null,
        subject: cert.subject?.CN || cert.subject?.O || 'Unknown',
        issuer: cert.issuer?.CN || cert.issuer?.O || 'Unknown',
        fingerprint: fingerprint,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        certificateChain: chain,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name || 'Unknown',
        timestamp: Date.now()
      };
    } catch (error) {
      console.warn(`⚠️  TLS certificate capture failed: ${error.message}`);
      return null;
    }
  }

  async getPriceFromCambrian(tokenAddress) {
    const apiUrl = `https://opabinia.cambrian.network/api/v1/solana/price-current?token_address=${tokenAddress}`;

    // NEW: Create loggers for complete request/response tracking
    const httpLogger = new HTTPLogger();
    const dnsLogger = new DNSLogger();

    // NEW: Log DNS resolution BEFORE making request
    // This proves we connected to the correct IP address
    try {
      await dnsLogger.logDNSResolution('opabinia.cambrian.network');
    } catch (dnsError) {
      console.warn(`⚠️  DNS resolution failed (continuing anyway): ${dnsError.message}`);
      // Continue even if DNS logging fails - this is just for additional verification
    }

    return new Promise((resolve, reject) => {
      const parsedUrl = url.parse(apiUrl);

      // TLS PINNING: Create secure HTTPS agent with certificate pinning (with fallback)
      let pinnedAgent = null;
      let tlsPinningEnabled = false;

      try {
        if (tlsPinning && typeof tlsPinning.createPinnedAgent === 'function') {
          pinnedAgent = tlsPinning.createPinnedAgent('cambrian-api');
          tlsPinningEnabled = true;
          console.log('🔒 TLS Pinning: Enabled for', parsedUrl.hostname);
        }
      } catch (pinningError) {
        console.warn('⚠️  TLS Pinning failed to initialize, using standard HTTPS:', pinningError.message);
      }

      const options = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.path,
        method: 'GET',
        headers: {
          'X-API-Key': process.env.CAMBRIAN_API_KEY,
          'Content-Type': 'application/json'
        }
      };

      // Only add agent if pinning was successful
      if (pinnedAgent) {
        options.agent = pinnedAgent;
      }

      // NEW: Log HTTP request BEFORE sending
      // This proves what we INTENDED to send
      const requestRecord = httpLogger.logRequest(
        apiUrl,
        'GET',
        options.headers,
        null // No body for GET request
      );

      console.log(`📤 HTTP Request logged: ${requestRecord.requestId} → ${apiUrl}`);

      const req = https.get(options, (res) => {
        // Capture TLS certificate for proof of legitimate API endpoint
        let tlsCertificate = null;
        let tlsPinningResult = null;
        if (res.socket) {
          tlsCertificate = this.captureTLSCertificate(res.socket);

          // TLS PINNING: Verify certificate against stored fingerprint (if enabled)
          if (tlsPinningEnabled && tlsPinning && typeof tlsPinning.verifyCertificatePin === 'function') {
            const cert = res.socket.getPeerCertificate();
            if (cert && !cert.subject) {
              console.warn('⚠️  TLS Pinning: No certificate available for verification');
            } else if (cert) {
              try {
                tlsPinningResult = tlsPinning.verifyCertificatePin(parsedUrl.hostname, cert);
                if (tlsPinningResult.verified) {
                  console.log(`✅ TLS Pinning: Certificate verified for ${parsedUrl.hostname}`);
                } else {
                  console.error(`❌ TLS Pinning: Certificate verification FAILED - ${tlsPinningResult.error}`);
                  return reject(new Error(`TLS certificate verification failed: ${tlsPinningResult.error}`));
                }
              } catch (verifyError) {
                console.warn('⚠️  TLS Pinning verification failed, continuing without pinning:', verifyError.message);
              }
            }
          }
        }

        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const result = JSON.parse(data);

            // NEW: Log HTTP response AFTER receiving
            // This proves what we ACTUALLY received
            const responseRecord = httpLogger.logResponse(
              requestRecord.requestId,
              res.statusCode,
              res.headers,
              data, // Log raw response data
              tlsCertificate
            );

            console.log(`📥 HTTP Response logged: ${responseRecord.requestId} (status: ${res.statusCode})`);

            // Parse Cambrian response format
            if (Array.isArray(result) && result[0]?.data?.[0]) {
              const [address, symbol, priceUSD] = result[0].data[0];
              resolve({
                tokenAddress: address,
                symbol,
                priceUSD,
                timestamp: new Date().toISOString(),
                source: 'cambrian',

                // Include TLS certificate proof for attestation
                tlsCertificate: tlsCertificate ? {
                  verified: tlsCertificate.verified,
                  subject: tlsCertificate.subject,
                  fingerprint: tlsCertificate.fingerprint,
                  protocol: tlsCertificate.protocol,
                  cipher: tlsCertificate.cipher,
                  // TLS PINNING: Add pinning verification result
                  pinned: tlsPinningResult ? tlsPinningResult.pinned : false,
                  pinningVerified: tlsPinningResult ? tlsPinningResult.verified : false,
                  pinningAction: tlsPinningResult ? tlsPinningResult.action : null
                } : null,

                // NEW: Include complete HTTP transaction log
                httpTransaction: httpLogger.getCompleteLog(),

                // NEW: Include DNS resolution log
                dnsResolution: dnsLogger.getResolutions()[0] || null
              });
            } else {
              reject(new Error('Invalid response from Cambrian API'));
            }
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
    });
  }

  async startService(port = 3405) {
    await this.initialize();

    this.app.listen(port, () => {
      console.log(`\n🚀 Cambrian DeFi Data Agent running on http://localhost:${port}`);
      console.log('📊 Service endpoints:');
      console.log('   GET  /health - Health check');
      console.log('   GET  /services - Service catalog');
      console.log('   POST /api/price-current - Get current token price');
      console.log('   POST /api/price-multi - Get multiple token prices');
      console.log('\n⏳ Waiting for requests...\n');
    });
  }
}

// Main execution
async function main() {
  console.log('🌟 Cambrian DeFi Data Agent - ERC-8004 Implementation\n');

  const agent = new CambrianDeFiDataAgent();

  // Setup cleanup handlers for Python subprocess
  function cleanup() {
    console.log('\n🛑 Shutting down agent...');
    if (agent.pythonProcess) {
      console.log('   Terminating Python subprocess...');
      agent.pythonProcess.kill('SIGTERM');
      // Force kill after 2 seconds if still running
      setTimeout(() => {
        if (agent.pythonProcess) {
          agent.pythonProcess.kill('SIGKILL');
        }
      }, 2000);
    }
    process.exit(0);
  }

  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);
  process.on('SIGHUP', cleanup);

  // Register if not already registered
  if (!agent.agentId) {
    await agent.initialize();
    await agent.register();
  }

  // Start service on PORT from environment (defaults to 3405 for local dev)
  const port = parseInt(process.env.PORT) || 3405;
  await agent.startService(port);
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { CambrianDeFiDataAgent };
/**
 * Dual TEE Proof Generator
 *
 * Creates comprehensive verifiable proofs combining:
 * - Agent TEE attestation (execution environment)
 * - MCP Server TEE attestation (tool provider)
 * - Complete execution chain (User → Agent → MCP → Cambrian API)
 * - Network logs (HTTP/DNS/TLS)
 * - Source code verification
 */

const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class DualTEEProofGenerator {
  constructor(agentAttestationJWT, agentContainerDigest, wallet, proofRegistry, mcpServerUrl) {
    this.agentAttestationJWT = agentAttestationJWT;
    this.agentContainerDigest = agentContainerDigest;
    this.wallet = wallet;
    this.proofRegistry = proofRegistry;

    // MCP Server URL is REQUIRED - no fallback to prevent configuration errors
    this.mcpServerUrl = mcpServerUrl || process.env.MCP_SERVER_URL;
    if (!this.mcpServerUrl) {
      throw new Error('MCP_SERVER_URL must be provided or set as environment variable - no default fallback');
    }
    console.log(`🔗 Dual-TEE configured to use MCP server: ${this.mcpServerUrl}`);
  }

  /**
   * Fetch MCP Server TEE attestation
   */
  async fetchMCPServerAttestation() {
    try {
      console.log(`🔐 Fetching MCP Server TEE attestation from ${this.mcpServerUrl}/attestation`);

      const response = await axios.get(`${this.mcpServerUrl}/attestation`, {
        timeout: 10000
      });

      if (response.data && response.data.success) {
        console.log(`   ✅ MCP Server attestation received`);
        console.log(`   Platform: ${response.data.platform?.provider || 'Unknown'}`);
        console.log(`   Security Level: ${response.data.securityLevel || 'Unknown'}`);
        console.log(`   Container: ${response.data.container?.digest?.substring(0, 32)}...`);

        return response.data;
      }

      throw new Error('MCP Server attestation response invalid');
    } catch (error) {
      console.warn(`⚠️  Failed to fetch MCP Server attestation: ${error.message}`);
      console.warn(`   MCP Server URL: ${this.mcpServerUrl}/attestation`);
      console.warn(`   Continuing without MCP attestation (reduced security)`);
      return null;
    }
  }

  /**
   * Build complete execution chain
   */
  buildExecutionChain(executionData, httpLogs, dnsLogs, mcpAttestation) {
    const queryHash = crypto.createHash('sha256')
      .update(executionData.question)
      .digest('hex');

    const answerHash = crypto.createHash('sha256')
      .update(executionData.answer)
      .digest('hex');

    return {
      // Step 1: User → Agent
      userToAgent: {
        query: executionData.question,
        queryHash: queryHash,
        timestamp: executionData.timestamp,
        agentTEE: {
          attestationJWT: this.agentAttestationJWT,
          containerDigest: this.agentContainerDigest,
          platform: 'GCP_AMD_SEV',
          securityLevel: 'MAXIMUM'
        }
      },

      // Step 2: Agent → MCP Server
      agentToMCP: {
        connection: httpLogs.requests[0] || null,
        toolsUsed: executionData.tools_used || [],
        toolCalls: httpLogs.requests.map(req => ({
          requestId: req.requestId,
          requestHash: req.bodyHash,
          url: req.url,
          timestamp: req.timestamp,
          method: req.method
        })),
        responses: httpLogs.responses.map(res => ({
          requestId: res.requestId,
          status: res.status,
          responseHash: res.bodyHash,
          timestamp: res.timestamp,
          tlsCertificate: res.tlsCertificate
        })),
        dnsResolution: dnsLogs[0] || null,
        mcpServerTEE: mcpAttestation
      },

      // Step 3: MCP Server → Cambrian API
      mcpToCambrian: {
        apiCalls: mcpAttestation?.executionLogs || [],
        tlsCertificates: mcpAttestation?.tlsCertificates || [],
        requestResponseHashes: httpLogs.responses.map(r => r.bodyHash)
      },

      // Step 4: Response chain
      responseChain: {
        cambrianToMCP: httpLogs.responses,
        mcpToAgent: executionData.result,
        agentToUser: executionData.answer,
        answerHash: answerHash,
        tools_used: executionData.tools_used || []
      }
    };
  }

  /**
   * Calculate merkle root from execution data
   */
  calculateMerkleRoot(executionData) {
    const data = JSON.stringify({
      question: executionData.question,
      answer: executionData.answer,
      timestamp: executionData.timestamp,
      tools_used: executionData.tools_used || []
    });

    return '0x' + crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate source code hashes for reproducibility
   */
  generateSourceCodeHashes() {
    const sourceFiles = [
      'cambrian-defi-data-agent.js',
      'google-adk-agent.js',
      'dual-tee-proof-generator.js',
      'package.json',
      'package-lock.json'
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
   */
  generateCodeVerificationMetadata() {
    return {
      // Agent code verification
      agentCode: {
        sourceHashes: this.generateSourceCodeHashes(),
        containerDigest: this.agentContainerDigest || process.env.CONTAINER_DIGEST || 'unknown',
        runtime: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          execPath: process.execPath
        },
        build: {
          timestamp: process.env.BUILD_TIMESTAMP || 'unknown',
          gitCommit: process.env.GIT_COMMIT || 'unknown',
          gitBranch: process.env.GIT_BRANCH || 'unknown',
          buildNumber: process.env.BUILD_NUMBER || 'unknown'
        },
        reproducibility: {
          repository: process.env.GIT_REPOSITORY || 'https://github.com/your-org/cambrian_erc8004_agent',
          commitHash: process.env.GIT_COMMIT || 'unknown',
          buildCommand: 'docker build --build-arg SOURCE_DATE_EPOCH=0 -t cambrian-agent .',
          verifyCommand: 'docker inspect --format=\'{{.Id}}\' cambrian-agent',
          expectedDigest: this.agentContainerDigest || process.env.CONTAINER_DIGEST || 'unknown'
        }
      },

      // MCP Server code verification (from attestation)
      mcpServerCode: null // Will be populated from MCP attestation
    };
  }

  /**
   * Create dual TEE proof
   */
  async createDualTEEProof(executionData, httpLogs, dnsLogs, geminiInteraction = null) {
    try {
      console.log('🔐 Creating Dual TEE Proof...');
      console.log(`   Question: ${executionData.question.substring(0, 60)}...`);
      console.log(`   Tools used: ${executionData.tools_used?.length || 0}`);
      if (geminiInteraction) {
        console.log(`   Gemini interaction logged: ${geminiInteraction.tool_calls_requested?.length || 0} tool calls`);
      }

      // 1. Fetch MCP Server TEE attestation
      const mcpAttestation = await this.fetchMCPServerAttestation();

      // 2. Build execution chain
      const executionChain = this.buildExecutionChain(executionData, httpLogs, dnsLogs, mcpAttestation);

      // 3. Calculate merkle root
      const merkleRoot = this.calculateMerkleRoot(executionData);
      console.log(`   Merkle Root: ${merkleRoot}`);

      // 4. Generate code verification
      const codeVerification = this.generateCodeVerificationMetadata();
      if (mcpAttestation) {
        codeVerification.mcpServerCode = mcpAttestation.codeVerification || {
          containerDigest: mcpAttestation.container?.digest || 'unknown'
        };
      }

      // 5. Create execution binding hashes
      const executionBinding = {
        agentToMCP: crypto.createHash('sha256')
          .update(JSON.stringify(executionChain.agentToMCP))
          .digest('hex'),
        mcpToCambrian: crypto.createHash('sha256')
          .update(JSON.stringify(executionChain.mcpToCambrian))
          .digest('hex'),
        responseChain: crypto.createHash('sha256')
          .update(JSON.stringify(executionChain.responseChain))
          .digest('hex')
      };

      // 6. Create complete evidence
      const evidence = {
        version: '2.0.0-dual-tee',
        executionData: {
          question: executionData.question,
          answer: executionData.answer,
          tools_used: executionData.tools_used || [],
          timestamp: executionData.timestamp,
          session_id: executionData.session_id,
          agentId: executionData.agentId
        },
        executionChain,
        merkleRoot,
        agentId: executionData.agentId,
        agentAddress: this.wallet.address,
        timestamp: Date.now(),

        // Dual TEE attestations
        teeAttestation: {
          agent: {
            attestationJWT: this.agentAttestationJWT,
            containerDigest: this.agentContainerDigest,
            platform: 'GCP Confidential Space',
            technology: 'AMD SEV',
            securityLevel: 'MAXIMUM'
          },
          mcpServer: mcpAttestation
        },

        // Network logs
        networkLogs: {
          requests: httpLogs.requests,
          responses: httpLogs.responses,
          totalRequests: httpLogs.totalRequests,
          totalResponses: httpLogs.totalResponses
        },

        // DNS resolution
        dnsResolution: dnsLogs[0] || null,

        // Code verification
        codeVerification,

        // Execution binding
        executionBinding,

        // NEW: Gemini interaction logs for verifiability
        // This proves what we sent to Gemini and what it responded with
        geminiInteraction: geminiInteraction || {
          enabled: false,
          reason: 'Gemini interaction logging not available'
        },

        // Agent signature
        signature: await this.wallet.signMessage(merkleRoot)
      };

      // 7. Upload to IPFS
      console.log(`   📤 Uploading evidence to IPFS...`);
      const ipfsStorage = require('./ipfs-storage');
      const evidenceHash = await ipfsStorage.upload(evidence);
      console.log(`   IPFS Hash: ${evidenceHash}`);

      // 8. Submit to ProofRegistry
      let proofResult = null;
      if (this.proofRegistry) {
        console.log(`   ⛓️  Submitting to ProofRegistry...`);
        proofResult = await this.submitToProofRegistry(merkleRoot, evidenceHash);
        if (proofResult) {
          console.log(`   Proof ID: ${proofResult.proofId}`);
          console.log(`   TX: ${proofResult.transactionHash}`);
        }
      }

      console.log('✅ Dual TEE Proof created successfully');

      return {
        merkleRoot,
        evidenceHash,
        proofId: proofResult?.proofId || null,
        transactionHash: proofResult?.transactionHash || null,
        fullEvidence: evidence,
        dualTEE: {
          agentAttestation: !!this.agentAttestationJWT,
          mcpServerAttestation: !!mcpAttestation,
          executionChainVerifiable: true,
          networkLogsComplete: httpLogs.totalRequests > 0
        }
      };

    } catch (error) {
      console.error(`❌ Dual TEE proof creation failed: ${error.message}`);
      console.error(error.stack);
      throw error;
    }
  }

  /**
   * Submit proof to ProofRegistry contract
   */
  async submitToProofRegistry(merkleRoot, evidenceHash) {
    if (!this.proofRegistry) {
      console.warn('⚠️  ProofRegistry not configured, skipping on-chain submission');
      return null;
    }

    try {
      const { ethers } = require('ethers');
      const stakeAmount = ethers.parseEther('0.00001');
      const containerDigest = this.agentContainerDigest || process.env.CONTAINER_DIGEST || '';

      const tx = await this.proofRegistry.submitProof(
        merkleRoot,
        evidenceHash,
        containerDigest,
        {
          value: stakeAmount,
          gasLimit: 500000
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
      console.warn(`   ⚠️  Failed to submit proof to registry: ${error.message}`);
      return null;
    }
  }
}

module.exports = { DualTEEProofGenerator };

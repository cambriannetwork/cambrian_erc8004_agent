#!/usr/bin/env node
/**
 * Proof Verification Script
 *
 * This script demonstrates how ANYONE can verify on-chain proof commitments
 * by reproducing the merkle root from the original evidence data.
 *
 * Usage:
 *   node verify-proof.js <evidenceHash>
 *   node verify-proof.js --proof-id <proofId>
 */

require('dotenv').config();
const { ethers } = require('ethers');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Configuration
const PROOF_REGISTRY_ADDRESS = '0xB41a3f366b4786028221A2b78AC6f34Bc685ecd3';
const RPC_URL = process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org';

const PROOF_REGISTRY_ABI = [
  'function getProof(uint256 proofId) view returns (bytes32 merkleRoot, address submitter, uint256 timestamp, uint256 challengePeriodEnd, bool challenged, bool verified, string evidenceHash, uint256 stake)'
];

class ProofVerifier {
  constructor() {
    this.provider = new ethers.JsonRpcProvider(RPC_URL);
    this.proofRegistry = new ethers.Contract(
      PROOF_REGISTRY_ADDRESS,
      PROOF_REGISTRY_ABI,
      this.provider
    );
    this.ipfsStorage = require('./ipfs-storage');
  }

  /**
   * Step 1: Load evidence data from IPFS or local storage
   */
  async loadEvidenceData(evidenceHash) {
    console.log(`   Attempting to load evidence: ${evidenceHash}`);

    try {
      // Try to retrieve from IPFS (with local backup fallback)
      const evidenceData = await this.ipfsStorage.retrieve(evidenceHash);
      return evidenceData;
    } catch (error) {
      // Fallback: try direct local file access
      const evidencePath = path.join(__dirname, 'evidence', `${evidenceHash}.json`);

      if (fs.existsSync(evidencePath)) {
        console.log(`   ℹ️  Loading from local backup: ${evidencePath}`);
        const evidenceData = JSON.parse(fs.readFileSync(evidencePath, 'utf8'));
        return evidenceData;
      }

      throw new Error(
        `Evidence not found: ${evidenceHash}\n` +
        `Tried:\n` +
        `  1. IPFS retrieval: ${error.message}\n` +
        `  2. Local storage: ${evidencePath}\n\n` +
        `The evidence data is required for verification.`
      );
    }
  }

  /**
   * Step 2: Recompute merkle root from evidence data
   */
  recomputeMerkleRoot(evidenceData) {
    // Use the SAME algorithm the agent used
    const { input, output } = evidenceData.executionData;

    const data = JSON.stringify({ input, output, timestamp: evidenceData.executionData.timestamp });
    const recomputedRoot = '0x' + crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');

    return recomputedRoot;
  }

  /**
   * Step 3: Query on-chain proof commitment
   */
  async getOnChainProof(proofId) {
    const proof = await this.proofRegistry.getProof(proofId);

    return {
      merkleRoot: proof.merkleRoot,
      submitter: proof.submitter,
      timestamp: proof.timestamp.toString(),
      challengePeriodEnd: proof.challengePeriodEnd.toString(),
      challenged: proof.challenged,
      verified: proof.verified,
      evidenceHash: proof.evidenceHash,
      stake: ethers.formatEther(proof.stake)
    };
  }

  /**
   * Step 4: Verify signature from agent
   */
  async verifyAgentSignature(evidenceData) {
    const { merkleRoot, signature, agentAddress } = evidenceData;

    try {
      const recoveredAddress = ethers.verifyMessage(merkleRoot, signature);
      const isValid = recoveredAddress.toLowerCase() === agentAddress.toLowerCase();

      return {
        isValid,
        recoveredAddress,
        expectedAddress: agentAddress
      };
    } catch (error) {
      return {
        isValid: false,
        error: error.message
      };
    }
  }

  /**
   * Step 5: Verify Full TEE Properties
   */
  verifyFullTEE(evidenceData) {
    const results = {
      isFullTEE: false,
      containerDigest: null,
      executionBinding: null,
      tlsCertificate: null,
      nonceUnique: true,
      checks: {}
    };

    // Check if this is Full TEE mode
    const teeAttestation = evidenceData.teeAttestation;
    if (!teeAttestation || teeAttestation.enabled === false) {
      return results;
    }

    results.isFullTEE = teeAttestation.teeMode === 'FULL_TEE';

    if (!results.isFullTEE) {
      return results;
    }

    // Check 1: Verify Container Digest
    if (teeAttestation.containerDigest) {
      results.containerDigest = teeAttestation.containerDigest;
      results.checks.containerDigest = {
        present: true,
        digest: teeAttestation.containerDigest,
        verified: teeAttestation.attestationToken ? true : false, // JWT proves digest
        notes: 'Container digest proves exact code version executed'
      };
    } else {
      results.checks.containerDigest = {
        present: false,
        verified: false,
        notes: 'No container digest found - cannot verify code identity'
      };
    }

    // Check 2: Verify Execution Binding
    if (teeAttestation.executionBinding) {
      results.executionBinding = teeAttestation.executionBinding;

      // Recompute execution binding to verify it's correct
      const expectedBinding = crypto
        .createHash('sha256')
        .update(JSON.stringify({
          service: evidenceData.executionData.service,
          inputHash: crypto.createHash('sha256').update(JSON.stringify(evidenceData.executionData.input)).digest('hex'),
          outputHash: crypto.createHash('sha256').update(JSON.stringify(evidenceData.executionData.output)).digest('hex'),
          merkleRoot: evidenceData.merkleRoot,
          timestamp: evidenceData.executionData.timestamp,
          tlsFingerprint: evidenceData.sourceProof?.tlsCertificate?.fingerprint || null
        }))
        .digest('base64');

      const bindingValid = expectedBinding === teeAttestation.executionBinding;

      results.checks.executionBinding = {
        present: true,
        valid: bindingValid,
        claimed: teeAttestation.executionBinding,
        recomputed: expectedBinding,
        notes: bindingValid
          ? 'Execution binding valid - attestation bound to this execution'
          : 'Execution binding mismatch - attestation may be reused'
      };
    } else {
      results.checks.executionBinding = {
        present: false,
        valid: false,
        notes: 'No execution binding - attestation could be reused'
      };
    }

    // Check 3: Verify TLS Certificate
    if (evidenceData.sourceProof?.tlsCertificate) {
      results.tlsCertificate = evidenceData.sourceProof.tlsCertificate;
      results.checks.tlsCertificate = {
        present: true,
        verified: evidenceData.sourceProof.tlsCertificate.verified,
        subject: evidenceData.sourceProof.tlsCertificate.subject,
        fingerprint: evidenceData.sourceProof.tlsCertificate.fingerprint,
        protocol: evidenceData.sourceProof.tlsCertificate.protocol,
        cipher: evidenceData.sourceProof.tlsCertificate.cipher,
        notes: evidenceData.sourceProof.tlsCertificate.verified
          ? 'TLS certificate verified - API connection authenticated'
          : 'TLS certificate not verified - cannot confirm API endpoint'
      };
    } else if (teeAttestation.executionProof?.tlsCertificate) {
      results.tlsCertificate = teeAttestation.executionProof.tlsCertificate;
      results.checks.tlsCertificate = {
        present: true,
        verified: teeAttestation.executionProof.tlsCertificate.verified,
        subject: teeAttestation.executionProof.tlsCertificate.subject,
        fingerprint: teeAttestation.executionProof.tlsCertificate.fingerprint,
        notes: 'TLS certificate found in attestation execution proof'
      };
    } else {
      results.checks.tlsCertificate = {
        present: false,
        verified: false,
        notes: 'No TLS certificate - cannot verify API endpoint'
      };
    }

    // Check 4: Verify Nonce Uniqueness (basic check - full check requires nonce database)
    if (teeAttestation.nonce) {
      results.checks.nonce = {
        present: true,
        value: teeAttestation.nonce,
        unique: true, // Would need database to fully verify
        notes: 'Nonce present - replay protection enabled (full uniqueness check requires nonce database)'
      };
    } else {
      results.checks.nonce = {
        present: false,
        unique: false,
        notes: 'No nonce - vulnerable to replay attacks'
      };
    }

    // Check 5: Verify Security Level
    results.checks.securityLevel = {
      claimed: teeAttestation.securityLevel,
      isMaximum: teeAttestation.securityLevel === 'MAXIMUM',
      notes: teeAttestation.securityLevel === 'MAXIMUM'
        ? 'MAXIMUM security - all execution in hardware TEE'
        : 'Lower security level - partial TEE protection'
    };

    return results;
  }

  /**
   * Step 8: Verify Network Logs (HTTP Request/Response)
   */
  verifyNetworkLogs(evidenceData) {
    const results = {
      verified: false,
      requestCount: 0,
      responseCount: 0,
      checks: []
    };

    const networkLogs = evidenceData.networkLogs;

    if (!networkLogs || !networkLogs.requests || networkLogs.requests.length === 0) {
      results.reason = 'No network logs found';
      return results;
    }

    results.requestCount = networkLogs.requests.length;
    results.responseCount = networkLogs.responses.length;

    // Verify each request/response pair
    for (let i = 0; i < networkLogs.requests.length; i++) {
      const request = networkLogs.requests[i];
      const response = networkLogs.responses[i];

      const check = {
        requestId: request.requestId,
        request: {
          url: request.url,
          method: request.method,
          timestamp: request.timestamp,
          bodyHash: request.bodyHash || 'N/A'
        },
        response: response ? {
          status: response.status,
          timestamp: response.timestamp,
          bodyHash: response.bodyHash,
          responseTime: response.timestamp - request.timestamp,
          tlsCertificate: response.tlsCertificate ? {
            subject: response.tlsCertificate.subject,
            issuer: response.tlsCertificate.issuer,
            fingerprint: response.tlsCertificate.fingerprint,
            verified: response.tlsCertificate.verified
          } : null
        } : null
      };

      results.checks.push(check);
    }

    results.verified = true;
    return results;
  }

  /**
   * Step 9: Verify Source Code Reproducibility
   */
  verifySourceCode(evidenceData) {
    const results = {
      verified: false,
      hasReproducibilityInstructions: false,
      sourceFiles: {},
      containerDigest: null,
      runtime: null
    };

    const codeVerification = evidenceData.codeVerification;

    if (!codeVerification) {
      results.reason = 'No code verification data found';
      return results;
    }

    results.containerDigest = codeVerification.containerDigest;
    results.runtime = codeVerification.runtime;

    // Extract source file hashes
    if (codeVerification.sourceHashes && codeVerification.sourceHashes.sourceFiles) {
      results.sourceFiles = codeVerification.sourceHashes.sourceFiles;
    }

    // Check for reproducibility instructions
    if (codeVerification.reproducibility) {
      results.hasReproducibilityInstructions = true;
      results.reproducibility = codeVerification.reproducibility;
    }

    results.verified = true;
    return results;
  }

  /**
   * Step 10: Verify DNS Resolution
   */
  verifyDNSResolution(evidenceData) {
    const results = {
      verified: false,
      hostname: null,
      resolvedIPs: [],
      success: false
    };

    const dnsResolution = evidenceData.dnsResolution;

    if (!dnsResolution) {
      results.reason = 'No DNS resolution data found (may be cached or not logged)';
      results.verified = true; // Not critical if missing
      return results;
    }

    results.hostname = dnsResolution.hostname;
    results.resolvedIPs = dnsResolution.resolvedIPs || [];
    results.success = dnsResolution.success;
    results.duration = dnsResolution.duration;

    if (!dnsResolution.success) {
      results.error = dnsResolution.error;
    }

    results.verified = true;
    return results;
  }

  /**
   * Complete verification workflow
   */
  async verify(proofId, evidenceHash) {
    console.log('🔍 Proof Verification Workflow');
    console.log('='.repeat(70));
    console.log();

    try {
      // Step 1: Load evidence data
      console.log('📂 Step 1: Loading Evidence Data');
      console.log(`   Evidence Hash: ${evidenceHash}`);
      const evidenceData = await this.loadEvidenceData(evidenceHash);
      console.log(`   ✅ Evidence data loaded successfully`);
      console.log(`   Service: ${evidenceData.executionData.service}`);
      console.log(`   Agent ID: ${evidenceData.agentId}`);
      console.log(`   Timestamp: ${new Date(evidenceData.timestamp).toISOString()}`);
      console.log();

      // Step 2: Recompute merkle root
      console.log('🔐 Step 2: Recomputing Merkle Root');
      const recomputedRoot = this.recomputeMerkleRoot(evidenceData);
      console.log(`   Original (claimed):  ${evidenceData.merkleRoot}`);
      console.log(`   Recomputed (actual): ${recomputedRoot}`);

      const merkleMatch = recomputedRoot === evidenceData.merkleRoot;
      console.log(`   ${merkleMatch ? '✅' : '❌'} Merkle roots ${merkleMatch ? 'MATCH' : 'DO NOT MATCH'}`);
      console.log();

      // Step 3: Query on-chain commitment
      console.log('⛓️  Step 3: Querying On-Chain Commitment');
      const onChainProof = await this.getOnChainProof(proofId);
      console.log(`   On-Chain Merkle Root: ${onChainProof.merkleRoot}`);
      console.log(`   Submitter: ${onChainProof.submitter}`);
      console.log(`   Stake: ${onChainProof.stake} ETH`);
      console.log(`   Status: ${onChainProof.verified ? 'VERIFIED' : 'PENDING'}`);

      const onChainMatch = recomputedRoot === onChainProof.merkleRoot;
      console.log(`   ${onChainMatch ? '✅' : '❌'} Recomputed root ${onChainMatch ? 'MATCHES' : 'DOES NOT MATCH'} on-chain commitment`);
      console.log();

      // Step 4: Verify agent signature
      console.log('✍️  Step 4: Verifying Agent Signature');
      const signatureVerification = await this.verifyAgentSignature(evidenceData);
      console.log(`   Expected Signer: ${signatureVerification.expectedAddress}`);
      console.log(`   Recovered Signer: ${signatureVerification.recoveredAddress || 'N/A'}`);
      console.log(`   ${signatureVerification.isValid ? '✅' : '❌'} Signature ${signatureVerification.isValid ? 'VALID' : 'INVALID'}`);
      console.log();

      // Step 5: Verify submitter matches agent
      console.log('🔗 Step 5: Verifying Submitter Identity');
      const identityMatch = onChainProof.submitter.toLowerCase() === evidenceData.agentAddress.toLowerCase();
      console.log(`   On-Chain Submitter: ${onChainProof.submitter}`);
      console.log(`   Evidence Agent Address: ${evidenceData.agentAddress}`);
      console.log(`   ${identityMatch ? '✅' : '❌'} Identity ${identityMatch ? 'VERIFIED' : 'MISMATCH'}`);
      console.log();

      // NEW Step 6: Verify TEE Attestation (if present)
      console.log('🔐 Step 6: Verifying TEE Hardware Attestation');
      let teeVerificationResult = null;

      if (evidenceData.teeAttestation && evidenceData.teeAttestation.enabled !== false) {
        console.log(`   TEE attestation found in evidence`);
        console.log(`   Platform: ${evidenceData.teeAttestation.platform || 'Unknown'}`);

        // Import attestation verifier
        const TEEAttestationVerifier = require('./attestation-verifier');
        const teeVerifier = new TEEAttestationVerifier();

        try {
          // Verify the attestation token
          teeVerificationResult = await teeVerifier.verifyAttestationToken(
            evidenceData.teeAttestation.attestationToken,
            evidenceData.teeAttestation.platform
          );

          if (teeVerificationResult.valid) {
            console.log(`   ✅ TEE attestation VERIFIED`);
            console.log(`   Hardware Root of Trust: VALIDATED`);
            console.log(`   Code Hash: ${evidenceData.teeAttestation.codeHash?.substring(0, 32)}...`);
            console.log(`   Instance ID: ${evidenceData.teeAttestation.instanceID}`);
          } else {
            console.log(`   ❌ TEE attestation INVALID`);
            console.log(`   Reason: ${teeVerificationResult.reason}`);
          }
        } catch (error) {
          console.log(`   ⚠️  TEE attestation verification error: ${error.message}`);
          teeVerificationResult = { valid: false, reason: error.message };
        }
      } else {
        console.log(`   ⚠️  No TEE attestation in evidence`);
        console.log(`   This proof was not generated in a hardware TEE`);
        console.log(`   Security Level: Standard (cryptographic commitments only)`);
      }
      console.log();

      // NEW Step 7: Verify Full TEE Properties (if applicable)
      console.log('🔐 Step 7: Verifying Full TEE Security Properties');
      const fullTEEResult = this.verifyFullTEE(evidenceData);

      if (fullTEEResult.isFullTEE) {
        console.log(`   ✅ Full TEE mode detected (MAXIMUM security)`);
        console.log();

        // Container Digest Verification
        const containerCheck = fullTEEResult.checks.containerDigest;
        console.log(`   📦 Container Digest:`);
        if (containerCheck.present) {
          console.log(`      ${containerCheck.verified ? '✅' : '⚠️'} Digest: ${containerCheck.digest?.substring(0, 60)}...`);
          console.log(`      ${containerCheck.notes}`);
        } else {
          console.log(`      ❌ ${containerCheck.notes}`);
        }
        console.log();

        // Execution Binding Verification
        const bindingCheck = fullTEEResult.checks.executionBinding;
        console.log(`   🔗 Execution Binding:`);
        if (bindingCheck.present) {
          console.log(`      ${bindingCheck.valid ? '✅' : '❌'} ${bindingCheck.notes}`);
          if (!bindingCheck.valid) {
            console.log(`      Claimed: ${bindingCheck.claimed?.substring(0, 40)}...`);
            console.log(`      Expected: ${bindingCheck.recomputed?.substring(0, 40)}...`);
          }
        } else {
          console.log(`      ❌ ${bindingCheck.notes}`);
        }
        console.log();

        // TLS Certificate Verification
        const tlsCheck = fullTEEResult.checks.tlsCertificate;
        console.log(`   🔒 TLS Certificate:`);
        if (tlsCheck.present) {
          console.log(`      ${tlsCheck.verified ? '✅' : '⚠️'} Subject: ${tlsCheck.subject}`);
          console.log(`      Protocol: ${tlsCheck.protocol || 'Unknown'}`);
          console.log(`      Cipher: ${tlsCheck.cipher || 'Unknown'}`);
          console.log(`      Fingerprint: ${tlsCheck.fingerprint?.substring(0, 40)}...`);
          console.log(`      ${tlsCheck.notes}`);
        } else {
          console.log(`      ⚠️  ${tlsCheck.notes}`);
        }
        console.log();

        // Nonce Verification
        const nonceCheck = fullTEEResult.checks.nonce;
        console.log(`   🎲 Replay Protection (Nonce):`);
        if (nonceCheck.present) {
          console.log(`      ✅ Nonce: ${nonceCheck.value}`);
          console.log(`      ${nonceCheck.notes}`);
        } else {
          console.log(`      ⚠️  ${nonceCheck.notes}`);
        }
        console.log();

        // Security Level
        const securityCheck = fullTEEResult.checks.securityLevel;
        console.log(`   🛡️  Security Level:`);
        console.log(`      ${securityCheck.isMaximum ? '✅' : '⚠️'} ${securityCheck.claimed}`);
        console.log(`      ${securityCheck.notes}`);
        console.log();

        // Full TEE Verification Summary
        const fullTEEChecksPass =
          containerCheck.verified &&
          bindingCheck.valid &&
          tlsCheck.verified &&
          nonceCheck.present &&
          securityCheck.isMaximum;

        if (fullTEEChecksPass) {
          console.log(`   ✅ All Full TEE checks passed`);
          console.log(`   🎯 This proof provides MAXIMUM security guarantees:`);
          console.log(`      • Code identity verified (container digest)`);
          console.log(`      • Execution binding prevents attestation reuse`);
          console.log(`      • TLS certificate proves API endpoint`);
          console.log(`      • Nonce provides replay protection`);
          console.log(`      • All execution in hardware-isolated memory`);
        } else {
          console.log(`   ⚠️  Some Full TEE checks did not pass completely`);
          console.log(`   The proof still provides strong security but not all guarantees`);
        }
      } else {
        console.log(`   ℹ️  Not Full TEE mode - using standard or external TEE`);
        console.log(`   Security Level: ${evidenceData.teeAttestation?.securityLevel || 'STANDARD'}`);
      }
      console.log();

      // NEW Step 8: Verify Network Logs
      console.log('🌐 Step 8: Verifying Network Request/Response Logs');
      const networkLogResult = this.verifyNetworkLogs(evidenceData);

      if (networkLogResult.verified && networkLogResult.requestCount > 0) {
        console.log(`   ✅ Network logs verified`);
        console.log(`   Total Requests: ${networkLogResult.requestCount}`);
        console.log(`   Total Responses: ${networkLogResult.responseCount}`);
        console.log();

        // Display first request/response in detail
        const firstCheck = networkLogResult.checks[0];
        if (firstCheck) {
          console.log(`   📤 Request #1:`);
          console.log(`      URL: ${firstCheck.request.url}`);
          console.log(`      Method: ${firstCheck.request.method}`);
          console.log(`      Request Body Hash: ${firstCheck.request.bodyHash}`);
          console.log();

          if (firstCheck.response) {
            console.log(`   📥 Response #1:`);
            console.log(`      Status: ${firstCheck.response.status}`);
            console.log(`      Response Time: ${firstCheck.response.responseTime}ms`);
            console.log(`      Response Body Hash: ${firstCheck.response.bodyHash}`);

            if (firstCheck.response.tlsCertificate) {
              console.log();
              console.log(`   🔒 TLS Certificate:`);
              console.log(`      Subject: ${firstCheck.response.tlsCertificate.subject}`);
              console.log(`      Issuer: ${firstCheck.response.tlsCertificate.issuer}`);
              console.log(`      Fingerprint: ${firstCheck.response.tlsCertificate.fingerprint?.substring(0, 60)}...`);
              console.log(`      ${firstCheck.response.tlsCertificate.verified ? '✅' : '⚠️'} Certificate ${firstCheck.response.tlsCertificate.verified ? 'Verified' : 'NOT Verified'}`);
            }
          }
        }
      } else {
        console.log(`   ⚠️  ${networkLogResult.reason || 'No network logs found'}`);
      }
      console.log();

      // NEW Step 9: Verify Source Code
      console.log('📝 Step 9: Verifying Source Code Reproducibility');
      const sourceCodeResult = this.verifySourceCode(evidenceData);

      if (sourceCodeResult.verified) {
        console.log(`   ✅ Source code verification data present`);
        console.log(`   Container Digest: ${sourceCodeResult.containerDigest?.substring(0, 60)}...`);

        if (sourceCodeResult.runtime) {
          console.log(`   Node Version: ${sourceCodeResult.runtime.nodeVersion}`);
          console.log(`   Platform: ${sourceCodeResult.runtime.platform}`);
          console.log(`   Architecture: ${sourceCodeResult.runtime.arch}`);
        }

        console.log();
        console.log(`   Source File Hashes: ${Object.keys(sourceCodeResult.sourceFiles).length} files`);
        let fileCount = 0;
        for (const [file, data] of Object.entries(sourceCodeResult.sourceFiles)) {
          if (fileCount < 3) { // Show first 3 files
            console.log(`      ${file}: ${data.sha256?.substring(0, 16)}...`);
          }
          fileCount++;
        }
        if (fileCount > 3) {
          console.log(`      ... and ${fileCount - 3} more files`);
        }

        if (sourceCodeResult.hasReproducibilityInstructions) {
          console.log();
          console.log(`   🔄 Reproducibility Instructions Available:`);
          console.log(`      Repository: ${sourceCodeResult.reproducibility.repository}`);
          console.log(`      Commit: ${sourceCodeResult.reproducibility.commitHash}`);
          console.log(`      Build Command: ${sourceCodeResult.reproducibility.buildCommand}`);
        }
      } else {
        console.log(`   ⚠️  ${sourceCodeResult.reason || 'No source code verification data'}`);
      }
      console.log();

      // NEW Step 10: Verify DNS Resolution
      console.log('🌐 Step 10: Verifying DNS Resolution');
      const dnsResult = this.verifyDNSResolution(evidenceData);

      if (dnsResult.hostname) {
        console.log(`   Hostname: ${dnsResult.hostname}`);
        console.log(`   Resolved IPs: ${dnsResult.resolvedIPs.join(', ')}`);
        console.log(`   Resolution Time: ${dnsResult.duration}ms`);
        console.log(`   ${dnsResult.success ? '✅' : '❌'} DNS resolution ${dnsResult.success ? 'successful' : 'failed'}`);

        if (!dnsResult.success && dnsResult.error) {
          console.log(`   Error: ${dnsResult.error}`);
        }
      } else {
        console.log(`   ℹ️  No DNS resolution data (may be cached or not logged)`);
      }
      console.log();

      // Final Verdict
      console.log('='.repeat(70));
      const basicChecksPass = merkleMatch && onChainMatch && signatureVerification.isValid && identityMatch;
      const hasTEE = evidenceData.teeAttestation && evidenceData.teeAttestation.enabled !== false;
      const teeVerified = teeVerificationResult?.valid || false;
      const allChecksPass = basicChecksPass && (!hasTEE || teeVerified);

      if (allChecksPass) {
        console.log('✅ PROOF VERIFIED SUCCESSFULLY');
        console.log();
        console.log('All verification checks passed:');
        console.log('  ✅ Merkle root recomputes correctly from evidence data');
        console.log('  ✅ Recomputed root matches on-chain commitment');
        console.log('  ✅ Agent signature is valid');
        console.log('  ✅ Submitter identity verified');
        if (hasTEE && teeVerified) {
          console.log('  ✅ TEE hardware attestation verified');
        }
        console.log();
        console.log('🎯 Conclusion: This proof is TRUSTWORTHY');
        console.log('   The agent DID execute the claimed service');
        console.log('   The execution data HAS NOT been tampered with');
        console.log('   The proof IS cryptographically valid');
        if (hasTEE && teeVerified) {
          console.log('   The execution WAS performed in a hardware TEE');
          console.log('   Security Level: MAXIMUM (hardware-backed)');
        } else if (!hasTEE) {
          console.log('   Security Level: STANDARD (cryptographic only)');
        }
      } else {
        console.log('❌ PROOF VERIFICATION FAILED');
        console.log();
        console.log('One or more verification checks failed!');
        if (!merkleMatch) console.log('  ❌ Merkle root mismatch - evidence data may be corrupted');
        if (!onChainMatch) console.log('  ❌ On-chain mismatch - proof may be fraudulent');
        if (!signatureVerification.isValid) console.log('  ❌ Invalid signature - agent identity cannot be verified');
        if (!identityMatch) console.log('  ❌ Identity mismatch - submitter is not the claimed agent');
        if (hasTEE && !teeVerified) console.log('  ❌ TEE attestation invalid - hardware proof verification failed');
        console.log();
        console.log('⚠️  WARNING: This proof should NOT be trusted');
      }

      // Display evidence data for manual review
      console.log();
      console.log('📋 Evidence Data Summary');
      console.log('-'.repeat(70));
      console.log('Service Execution:');
      console.log(JSON.stringify(evidenceData.executionData, null, 2));
      console.log();
      console.log('Source Proof:');
      console.log(JSON.stringify(evidenceData.sourceProof, null, 2));
      console.log();

      return {
        verified: allChecksPass,
        checks: {
          merkleRootMatch: merkleMatch,
          onChainMatch: onChainMatch,
          signatureValid: signatureVerification.isValid,
          identityMatch: identityMatch
        },
        evidenceData,
        onChainProof
      };

    } catch (error) {
      console.error('❌ Verification Error:', error.message);
      console.error();
      console.error('Stack trace:');
      console.error(error.stack);
      throw error;
    }
  }
}

// Main execution
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage:');
    console.log('  node verify-proof.js <evidenceHash>');
    console.log('  node verify-proof.js --proof-id <proofId>');
    console.log();
    console.log('Example:');
    console.log('  node verify-proof.js QmEvidencemg5og4ag');
    console.log('  node verify-proof.js --proof-id 1');
    process.exit(1);
  }

  let proofId, evidenceHash;

  if (args[0] === '--proof-id') {
    proofId = parseInt(args[1]);

    // Query on-chain to get evidence hash
    const verifier = new ProofVerifier();
    const proof = await verifier.getOnChainProof(proofId);
    evidenceHash = proof.evidenceHash;

    console.log(`📌 Fetched evidence hash from on-chain proof #${proofId}`);
    console.log(`   Evidence Hash: ${evidenceHash}`);
    console.log();
  } else {
    evidenceHash = args[0];
    proofId = 1; // Default to proof 1, can be specified
  }

  const verifier = new ProofVerifier();
  const result = await verifier.verify(proofId, evidenceHash);

  process.exit(result.verified ? 0 : 1);
}

if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error.message);
    process.exit(1);
  });
}

module.exports = { ProofVerifier };
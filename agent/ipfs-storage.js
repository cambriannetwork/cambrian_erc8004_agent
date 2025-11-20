/**
 * IPFS Storage Module
 *
 * Provides evidence storage and retrieval via IPFS for verifiable proof system.
 *
 * Features:
 * - Upload evidence data to IPFS (via Pinata API or fallback to local)
 * - Retrieve evidence data from IPFS
 * - Local backup storage
 * - Multiple gateway fallback
 */

const fs = require('fs');
const path = require('path');
const axios = require('axios');

class IPFSStorage {
  constructor(options = {}) {
    // Configure IPFS upload endpoint
    // Pinata is a reliable IPFS pinning service
    this.pinataApiKey = options.pinataApiKey || process.env.PINATA_API_KEY;
    this.pinataSecretKey = options.pinataSecretKey || process.env.PINATA_SECRET_KEY;

    this.enabled = !!(this.pinataApiKey && this.pinataSecretKey);

    // Custom Pinata gateway configuration
    this.customGateway = options.customGateway || process.env.PINATA_GATEWAY;
    this.gatewayKey = options.gatewayKey || process.env.PINATA_GATEWAY_KEY;

    if (this.enabled) {
      console.log(`📡 IPFS storage enabled via Pinata`);
      if (this.customGateway && this.gatewayKey) {
        console.log(`   Custom gateway configured: ${this.customGateway}`);
      }
    } else {
      console.warn(`⚠️  IPFS upload not configured - using local storage only`);
      console.warn('   To enable IPFS: Set PINATA_API_KEY and PINATA_SECRET_KEY in .env');
    }

    // Local backup directory
    this.localBackupDir = path.join(__dirname, 'evidence');
    if (!fs.existsSync(this.localBackupDir)) {
      fs.mkdirSync(this.localBackupDir, { recursive: true });
    }

    // IPFS gateways for retrieval (prioritized order)
    this.gateways = [];

    // 1. Custom gateway first (if configured) - fastest, authenticated
    if (this.customGateway) {
      this.gateways.push(this.customGateway + '/ipfs/');
    }

    // 2. Public gateways as fallback
    this.gateways.push(
      'https://ipfs.io/ipfs/',
      'https://gateway.pinata.cloud/ipfs/',
      'https://cloudflare-ipfs.com/ipfs/',
      'https://dweb.link/ipfs/'
    );

    // Performance tracking
    this.gatewayStats = {};
  }

  /**
   * Upload evidence to IPFS
   * @param {Object} evidence - Full evidence data
   * @returns {Promise<string>} IPFS hash (CID)
   */
  async upload(evidence) {
    const evidenceJson = JSON.stringify(evidence, null, 2);

    // Always store local backup first
    const localHash = this.createLocalHash(evidence);
    const localPath = path.join(this.localBackupDir, `${localHash}.json`);
    fs.writeFileSync(localPath, evidenceJson);
    console.log(`💾 Evidence backed up locally: ${localPath}`);

    // Try to upload to IPFS via Pinata
    if (this.enabled) {
      try {
        const FormData = require('form-data');
        const formData = new FormData();

        // Create a buffer from the JSON string
        const buffer = Buffer.from(evidenceJson, 'utf-8');
        formData.append('file', buffer, {
          filename: `evidence_${Date.now()}.json`,
          contentType: 'application/json'
        });

        const response = await axios.post(
          'https://api.pinata.cloud/pinning/pinFileToIPFS',
          formData,
          {
            maxBodyLength: Infinity,
            headers: {
              'Content-Type': `multipart/form-data; boundary=${formData._boundary}`,
              'pinata_api_key': this.pinataApiKey,
              'pinata_secret_api_key': this.pinataSecretKey
            }
          }
        );

        const ipfsHash = response.data.IpfsHash;

        console.log(`📤 Evidence uploaded to IPFS: ${ipfsHash}`);
        console.log(`   View at: https://ipfs.io/ipfs/${ipfsHash}`);

        // Store mapping between local hash and IPFS hash
        this.storeHashMapping(localHash, ipfsHash);

        return ipfsHash;
      } catch (error) {
        console.error(`❌ IPFS upload failed: ${error.message}`);
        console.warn(`⚠️  Falling back to local storage only`);
        return localHash; // Return local hash as fallback
      }
    } else {
      console.log(`ℹ️  IPFS disabled, using local storage: ${localHash}`);
      return localHash;
    }
  }

  /**
   * Retrieve evidence from IPFS or local storage
   * @param {string} hash - IPFS CID or local hash
   * @returns {Promise<Object>} Evidence data
   */
  async retrieve(hash) {
    // Try local storage first (fastest)
    const localPath = path.join(this.localBackupDir, `${hash}.json`);
    if (fs.existsSync(localPath)) {
      console.log(`📂 Loading evidence from local storage: ${hash}`);
      return JSON.parse(fs.readFileSync(localPath, 'utf8'));
    }

    // Check if we have a mapping from local hash to IPFS hash
    const ipfsHash = this.getIPFSHashFromMapping(hash);
    if (ipfsHash) {
      hash = ipfsHash;
    }

    // Try IPFS retrieval with multiple gateways
    if (this.isIPFSHash(hash)) {
      console.log(`📡 Fetching evidence from IPFS: ${hash}`);

      for (let i = 0; i < this.gateways.length; i++) {
        const gateway = this.gateways[i];
        const isCustomGateway = (i === 0 && this.customGateway && gateway.includes(this.customGateway));

        try {
          const startTime = Date.now();

          // Build request config
          const config = {
            timeout: 10000,
            headers: { 'Accept': 'application/json' }
          };

          // Add authentication for custom gateway
          if (isCustomGateway && this.gatewayKey) {
            config.headers['x-pinata-gateway-token'] = this.gatewayKey;
          }

          const response = await axios.get(`${gateway}${hash}`, config);
          const latency = Date.now() - startTime;

          // Track performance
          this.recordGatewayPerformance(gateway, latency, true);

          console.log(`✅ Evidence retrieved from ${isCustomGateway ? 'custom gateway (authenticated)' : gateway} (${latency}ms)`);

          // Cache locally for future access
          fs.writeFileSync(localPath, JSON.stringify(response.data, null, 2));

          return response.data;
        } catch (error) {
          this.recordGatewayPerformance(gateway, null, false);
          console.warn(`⚠️  Gateway ${gateway} failed: ${error.message}`);
          continue;
        }
      }

      throw new Error(`Failed to retrieve evidence from IPFS after trying ${this.gateways.length} gateways`);
    }

    throw new Error(`Evidence not found: ${hash}`);
  }

  /**
   * Record gateway performance for optimization
   */
  recordGatewayPerformance(gateway, latency, success) {
    if (!this.gatewayStats[gateway]) {
      this.gatewayStats[gateway] = {
        attempts: 0,
        successes: 0,
        failures: 0,
        totalLatency: 0,
        avgLatency: 0
      };
    }

    const stats = this.gatewayStats[gateway];
    stats.attempts++;

    if (success) {
      stats.successes++;
      stats.totalLatency += latency;
      stats.avgLatency = stats.totalLatency / stats.successes;
    } else {
      stats.failures++;
    }
  }

  /**
   * Create local hash for evidence (SHA-256 based)
   */
  createLocalHash(evidence) {
    const crypto = require('crypto');
    const hash = crypto
      .createHash('sha256')
      .update(JSON.stringify(evidence))
      .digest('hex');
    return `local_${hash.substring(0, 46)}`; // Similar length to IPFS CID
  }

  /**
   * Check if hash is an IPFS CID (Content Identifier)
   */
  isIPFSHash(hash) {
    // IPFS CIDv0 starts with Qm (base58)
    // IPFS CIDv1 starts with b (base32) or other prefixes
    return hash.startsWith('Qm') || hash.startsWith('b') || hash.startsWith('z');
  }

  /**
   * Store mapping between local hash and IPFS hash
   */
  storeHashMapping(localHash, ipfsHash) {
    const mappingFile = path.join(this.localBackupDir, '_hash_mapping.json');
    let mappings = {};

    if (fs.existsSync(mappingFile)) {
      mappings = JSON.parse(fs.readFileSync(mappingFile, 'utf8'));
    }

    mappings[localHash] = ipfsHash;
    fs.writeFileSync(mappingFile, JSON.stringify(mappings, null, 2));
  }

  /**
   * Get IPFS hash from local hash mapping
   */
  getIPFSHashFromMapping(localHash) {
    const mappingFile = path.join(this.localBackupDir, '_hash_mapping.json');

    if (fs.existsSync(mappingFile)) {
      const mappings = JSON.parse(fs.readFileSync(mappingFile, 'utf8'));
      return mappings[localHash];
    }

    return null;
  }

  /**
   * Pin evidence to ensure persistence
   * (Requires IPFS node with pinning service)
   */
  async pin(hash) {
    if (!this.enabled) {
      console.warn('⚠️  IPFS not enabled, cannot pin');
      return false;
    }

    try {
      await this.ipfs.pin.add(hash);
      console.log(`📌 Evidence pinned: ${hash}`);
      return true;
    } catch (error) {
      console.error(`❌ Pin failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Get storage statistics
   */
  getStats() {
    const files = fs.readdirSync(this.localBackupDir)
      .filter(f => f.endsWith('.json') && f !== '_hash_mapping.json');

    const totalSize = files.reduce((sum, file) => {
      const stats = fs.statSync(path.join(this.localBackupDir, file));
      return sum + stats.size;
    }, 0);

    return {
      localEvidenceCount: files.length,
      localStorageSize: totalSize,
      ipfsEnabled: this.enabled,
      customGatewayEnabled: !!(this.customGateway && this.gatewayKey),
      customGateway: this.customGateway,
      gatewayStats: this.gatewayStats
    };
  }

  /**
   * Get gateway performance report
   */
  getGatewayReport() {
    console.log('\n📊 IPFS Gateway Performance Report');
    console.log('='.repeat(70));

    for (const [gateway, stats] of Object.entries(this.gatewayStats)) {
      const successRate = stats.attempts > 0 ? (stats.successes / stats.attempts * 100).toFixed(1) : 0;
      const avgLatency = stats.avgLatency ? stats.avgLatency.toFixed(0) : 'N/A';

      console.log(`\n${gateway}`);
      console.log(`  Attempts: ${stats.attempts}`);
      console.log(`  Success Rate: ${successRate}%`);
      console.log(`  Avg Latency: ${avgLatency}ms`);
    }

    console.log('\n' + '='.repeat(70));
  }
}

// Export singleton instance
module.exports = new IPFSStorage();
module.exports.IPFSStorage = IPFSStorage;
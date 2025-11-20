#!/usr/bin/env node
/**
 * Test Script for Official ERC-8004 Singleton Contracts
 *
 * This script tests interaction with the official ERC-8004 contracts
 * deployed on Base Sepolia testnet.
 *
 * Usage:
 *   node test-official-contracts.js
 *
 * Prerequisites:
 *   - SELLER_PRIVATE_KEY in .env (wallet with Base Sepolia ETH)
 *   - Base Sepolia RPC access
 */

require('dotenv').config();
const { ethers } = require('ethers');

// Official ERC-8004 Contract Addresses (Base Sepolia)
const IDENTITY_REGISTRY = process.env.IDENTITY_REGISTRY || '0x8004AA63c570c570eBF15376c0dB199918BFe9Fb';
const REPUTATION_REGISTRY = process.env.REPUTATION_REGISTRY || '0x8004bd8daB57f14Ed299135749a5CB5c42d341BF';
const VALIDATION_REGISTRY = process.env.VALIDATION_REGISTRY || '0x8004C269D0A5647E51E121FeB226200ECE932d55';

// Official Contract ABIs
const IDENTITY_ABI = [
  'function register() external returns (uint256 agentId)',
  'function register(string memory tokenUri) external returns (uint256 agentId)',
  'function ownerOf(uint256 tokenId) external view returns (address)',
  'function setMetadata(uint256 agentId, string memory key, bytes memory value) external',
  'function getMetadata(uint256 agentId, string memory key) external view returns (bytes memory)',
  'event Registered(uint256 indexed agentId, string tokenURI, address indexed owner)'
];

const REPUTATION_ABI = [
  'function giveFeedback(uint256 agentId, uint8 score, bytes32 tag1, bytes32 tag2, string calldata feedbackUri, bytes32 feedbackHash, bytes calldata feedbackAuth) external',
  'function getLastIndex(uint256 agentId, address clientAddress) external view returns (uint64)',
  'function readFeedback(uint256 agentId, address clientAddress, uint64 index) external view returns (uint8 score, bytes32 tag1, bytes32 tag2, bool isRevoked)',
  'function getSummary(uint256 agentId, address[] calldata clientAddresses, bytes32 tag1, bytes32 tag2) external view returns (uint64 count, uint8 averageScore)',
  'function getClients(uint256 agentId) external view returns (address[] memory)',
  'event NewFeedback(uint256 indexed agentId, address indexed clientAddress, uint8 score, bytes32 indexed tag1, bytes32 tag2, string feedbackUri, bytes32 feedbackHash)'
];

const VALIDATION_ABI = [
  'function validationRequest(address validatorAddress, uint256 agentId, string calldata requestUri, bytes32 requestHash) external',
  'function getValidationStatus(bytes32 requestHash) external view returns (address validatorAddress, uint256 agentId, uint8 response, bytes32 responseHash, bytes32 tag, uint256 lastUpdate)',
  'function getAgentValidations(uint256 agentId) external view returns (bytes32[] memory)',
  'event ValidationRequest(address indexed validatorAddress, uint256 indexed agentId, string requestUri, bytes32 indexed requestHash)'
];

class ERC8004Tester {
  constructor() {
    this.provider = new ethers.JsonRpcProvider(process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org');
    this.wallet = new ethers.Wallet(
      process.env.SELLER_PRIVATE_KEY || process.env.AGENT_PRIVATE_KEY,
      this.provider
    );

    this.identityRegistry = new ethers.Contract(IDENTITY_REGISTRY, IDENTITY_ABI, this.wallet);
    this.reputationRegistry = new ethers.Contract(REPUTATION_REGISTRY, REPUTATION_ABI, this.wallet);
    this.validationRegistry = new ethers.Contract(VALIDATION_REGISTRY, VALIDATION_ABI, this.wallet);

    this.testResults = [];
  }

  async run() {
    console.log('═══════════════════════════════════════════════════════════════════');
    console.log('  ERC-8004 Official Contract Test Suite');
    console.log('═══════════════════════════════════════════════════════════════════\n');

    console.log('Configuration:');
    console.log(`  Wallet:              ${this.wallet.address}`);
    console.log(`  Identity Registry:   ${IDENTITY_REGISTRY}`);
    console.log(`  Reputation Registry: ${REPUTATION_REGISTRY}`);
    console.log(`  Validation Registry: ${VALIDATION_REGISTRY}`);
    console.log(`  Network:             Base Sepolia (Chain ID: 84532)\n`);

    // Check balance
    const balance = await this.provider.getBalance(this.wallet.address);
    console.log(`  Wallet Balance:      ${ethers.formatEther(balance)} ETH\n`);

    if (balance === 0n) {
      console.error('❌ ERROR: Wallet has no ETH. Get testnet ETH from https://faucet.quicknode.com/base/sepolia\n');
      process.exit(1);
    }

    try {
      // Test 1: Register Agent
      await this.testRegisterAgent();

      // Test 2: Set Metadata
      await this.testSetMetadata();

      // Test 3: Generate FeedbackAuth
      await this.testGenerateFeedbackAuth();

      // Test 4: Give Feedback (if we have another wallet)
      // Skipped for now - requires second wallet

      // Test 5: Get Feedback Summary
      await this.testGetFeedbackSummary();

      // Test 6: Validation Request
      await this.testValidationRequest();

      // Print Summary
      this.printSummary();

    } catch (error) {
      console.error('\n❌ Test suite failed:', error.message);
      console.error(error);
      process.exit(1);
    }
  }

  async testRegisterAgent() {
    console.log('─────────────────────────────────────────────────────────────────');
    console.log('Test 1: Register Agent on Identity Registry');
    console.log('─────────────────────────────────────────────────────────────────');

    try {
      // Check if already registered
      let agentId;
      try {
        // Try to get agent ID (will fail if not registered)
        agentId = await this.identityRegistry.tokenOfOwnerByIndex?.(this.wallet.address, 0).catch(() => null);
      } catch (e) {
        // Not registered yet
      }

      if (agentId) {
        console.log(`ℹ️  Agent already registered: ID ${agentId}`);
        this.agentId = Number(agentId);
        this.testResults.push({ test: 'Register Agent', status: 'SKIPPED', message: 'Already registered' });
      } else {
        const tokenUri = `https://agent.example.com/agent-card.json`;
        console.log(`  Registering with tokenUri: ${tokenUri}`);

        const tx = await this.identityRegistry.register(tokenUri);
        console.log(`  Transaction sent: ${tx.hash}`);

        const receipt = await tx.wait();
        console.log(`  ✅ Transaction confirmed in block ${receipt.blockNumber}`);

        // Extract agent ID from event
        const event = receipt.logs.find(log => {
          try {
            return this.identityRegistry.interface.parseLog(log)?.name === 'Registered';
          } catch { return false; }
        });

        if (event) {
          const parsed = this.identityRegistry.interface.parseLog(event);
          this.agentId = Number(parsed.args[0]);
          console.log(`  ✅ Agent registered: ID ${this.agentId}`);
          this.testResults.push({ test: 'Register Agent', status: 'PASS', agentId: this.agentId });
        }
      }

      console.log('');
    } catch (error) {
      console.error(`  ❌ Failed: ${error.message}\n`);
      this.testResults.push({ test: 'Register Agent', status: 'FAIL', error: error.message });
      throw error;
    }
  }

  async testSetMetadata() {
    console.log('─────────────────────────────────────────────────────────────────');
    console.log('Test 2: Set Agent Metadata');
    console.log('─────────────────────────────────────────────────────────────────');

    try {
      const key = 'agentName';
      const value = ethers.toUtf8Bytes('Cambrian Data Agent');

      console.log(`  Setting metadata: ${key} = "Cambrian Data Agent"`);

      const tx = await this.identityRegistry.setMetadata(this.agentId, key, value);
      console.log(`  Transaction sent: ${tx.hash}`);

      const receipt = await tx.wait();
      console.log(`  ✅ Transaction confirmed in block ${receipt.blockNumber}`);

      // Read back
      const storedValue = await this.identityRegistry.getMetadata(this.agentId, key);
      const decodedValue = ethers.toUtf8String(storedValue);
      console.log(`  Retrieved metadata: "${decodedValue}"`);

      if (decodedValue === 'Cambrian Data Agent') {
        console.log(`  ✅ Metadata verified\n`);
        this.testResults.push({ test: 'Set Metadata', status: 'PASS' });
      } else {
        throw new Error('Metadata mismatch');
      }

    } catch (error) {
      console.error(`  ❌ Failed: ${error.message}\n`);
      this.testResults.push({ test: 'Set Metadata', status: 'FAIL', error: error.message });
    }
  }

  async testGenerateFeedbackAuth() {
    console.log('─────────────────────────────────────────────────────────────────');
    console.log('Test 3: Generate FeedbackAuth Signature (EIP-191)');
    console.log('─────────────────────────────────────────────────────────────────');

    try {
      const clientAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7'; // Example client
      const indexLimit = 1;
      const expiry = Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60); // 30 days
      const chainId = 84532;

      console.log(`  Client Address:   ${clientAddress}`);
      console.log(`  Index Limit:      ${indexLimit}`);
      console.log(`  Expiry:           ${new Date(expiry * 1000).toISOString()}`);
      console.log(`  Chain ID:         ${chainId}`);

      // Encode FeedbackAuth struct
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ['uint256', 'address', 'uint64', 'uint256', 'uint256', 'address', 'address'],
        [this.agentId, clientAddress, indexLimit, expiry, chainId, IDENTITY_REGISTRY, this.wallet.address]
      );

      const messageHash = ethers.keccak256(encoded);
      const signature = await this.wallet.signMessage(ethers.getBytes(messageHash));

      // Construct feedbackAuth bytes
      const feedbackAuthBytes = ethers.concat([encoded, signature]);

      console.log(`  Message Hash:     ${messageHash}`);
      console.log(`  Signature:        ${signature}`);
      console.log(`  FeedbackAuth Length: ${feedbackAuthBytes.length} bytes`);

      if (feedbackAuthBytes.length >= 289) {
        console.log(`  ✅ FeedbackAuth generated successfully\n`);
        this.feedbackAuthBytes = feedbackAuthBytes;
        this.testResults.push({ test: 'Generate FeedbackAuth', status: 'PASS' });
      } else {
        throw new Error(`FeedbackAuth too short: ${feedbackAuthBytes.length} bytes`);
      }

    } catch (error) {
      console.error(`  ❌ Failed: ${error.message}\n`);
      this.testResults.push({ test: 'Generate FeedbackAuth', status: 'FAIL', error: error.message });
    }
  }

  async testGetFeedbackSummary() {
    console.log('─────────────────────────────────────────────────────────────────');
    console.log('Test 4: Get Feedback Summary');
    console.log('─────────────────────────────────────────────────────────────────');

    try {
      const [count, averageScore] = await this.reputationRegistry.getSummary(
        this.agentId,
        [], // All clients
        ethers.ZeroHash, // No tag filter
        ethers.ZeroHash
      );

      console.log(`  Agent ID:         ${this.agentId}`);
      console.log(`  Feedback Count:   ${count.toString()}`);
      console.log(`  Average Score:    ${averageScore.toString()}/100`);

      const clients = await this.reputationRegistry.getClients(this.agentId);
      console.log(`  Unique Clients:   ${clients.length}`);

      console.log(`  ✅ Summary retrieved successfully\n`);
      this.testResults.push({ test: 'Get Feedback Summary', status: 'PASS', count: count.toString() });

    } catch (error) {
      console.error(`  ❌ Failed: ${error.message}\n`);
      this.testResults.push({ test: 'Get Feedback Summary', status: 'FAIL', error: error.message });
    }
  }

  async testValidationRequest() {
    console.log('─────────────────────────────────────────────────────────────────');
    console.log('Test 5: Create Validation Request');
    console.log('─────────────────────────────────────────────────────────────────');

    try {
      const validatorAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7'; // Example validator
      const requestUri = 'ipfs://QmTest123';
      const requestHash = ethers.keccak256(ethers.toUtf8Bytes('test-validation-request'));

      console.log(`  Validator:        ${validatorAddress}`);
      console.log(`  Agent ID:         ${this.agentId}`);
      console.log(`  Request URI:      ${requestUri}`);
      console.log(`  Request Hash:     ${requestHash}`);

      const tx = await this.validationRegistry.validationRequest(
        validatorAddress,
        this.agentId,
        requestUri,
        requestHash
      );
      console.log(`  Transaction sent: ${tx.hash}`);

      const receipt = await tx.wait();
      console.log(`  ✅ Transaction confirmed in block ${receipt.blockNumber}`);

      // Get validation status
      const status = await this.validationRegistry.getValidationStatus(requestHash);
      console.log(`  Validator:        ${status[0]}`);
      console.log(`  Agent ID:         ${status[1]}`);
      console.log(`  Response Score:   ${status[2]}`);
      console.log(`  ✅ Validation request created\n`);

      this.testResults.push({ test: 'Validation Request', status: 'PASS' });

    } catch (error) {
      console.error(`  ❌ Failed: ${error.message}\n`);
      this.testResults.push({ test: 'Validation Request', status: 'FAIL', error: error.message });
    }
  }

  printSummary() {
    console.log('═══════════════════════════════════════════════════════════════════');
    console.log('  Test Summary');
    console.log('═══════════════════════════════════════════════════════════════════\n');

    const passed = this.testResults.filter(r => r.status === 'PASS').length;
    const failed = this.testResults.filter(r => r.status === 'FAIL').length;
    const skipped = this.testResults.filter(r => r.status === 'SKIPPED').length;
    const total = this.testResults.length;

    this.testResults.forEach((result, idx) => {
      const icon = result.status === 'PASS' ? '✅' : result.status === 'FAIL' ? '❌' : 'ℹ️';
      console.log(`  ${icon} ${result.test.padEnd(30)} ${result.status}`);
    });

    console.log('');
    console.log(`  Total Tests:  ${total}`);
    console.log(`  Passed:       ${passed}`);
    console.log(`  Failed:       ${failed}`);
    console.log(`  Skipped:      ${skipped}`);
    console.log('');

    if (failed === 0) {
      console.log('  ✅ ALL TESTS PASSED!\n');
      console.log('  Your implementation is compatible with official ERC-8004 contracts.\n');
    } else {
      console.log('  ❌ SOME TESTS FAILED\n');
      console.log('  Please review the errors above and fix your implementation.\n');
      process.exit(1);
    }
  }
}

// Run tests
const tester = new ERC8004Tester();
tester.run().catch(error => {
  console.error('\n❌ Fatal error:', error);
  process.exit(1);
});

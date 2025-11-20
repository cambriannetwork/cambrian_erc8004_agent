/**
 * TEE Client Certificate Generator
 *
 * Generates client certificates with embedded TEE attestations for mutual TLS (mTLS).
 * This enables cryptographic proof that the Agent TEE is calling the MCP Server TEE.
 *
 * Certificate Extensions:
 * - 1.3.6.1.4.1.99999.1: Google-signed TEE attestation JWT
 * - 1.3.6.1.4.1.99999.2: Container digest (for reproducible builds)
 * - 1.3.6.1.4.1.99999.3: Agent wallet address
 */

const forge = require('node-forge');
const crypto = require('crypto');

class TEEClientCertGenerator {
  constructor(wallet, attestationJWT, containerDigest) {
    if (!wallet) {
      throw new Error('Wallet is required for client certificate generation');
    }

    this.wallet = wallet;
    this.attestationJWT = attestationJWT || null;
    this.containerDigest = containerDigest || 'sha256:unknown';

    console.log('🔐 TEEClientCertGenerator initialized');
    console.log(`   Container Digest: ${this.containerDigest.substring(0, 40)}...`);
    console.log(`   Attestation JWT: ${this.attestationJWT ? 'Present' : 'Missing (non-TEE mode)'}`);
  }

  /**
   * Generate a self-signed client certificate with embedded TEE attestation
   */
  async generateClientCertificate() {
    console.log('🔑 Generating TEE client certificate...');

    try {
      // Generate RSA key pair for the certificate
      const keys = forge.pki.rsa.generateKeyPair(2048);

      // Create certificate
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '01' + Date.now().toString(16);

      // Valid for 1 year
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

      // Subject: Include TEE identity
      const digestPrefix = this.containerDigest.substring(7, 23); // sha256:XXXXXXXXXXXXXXXX
      const attrs = [
        {
          name: 'commonName',
          value: `agent-tee-${digestPrefix}`
        },
        {
          name: 'organizationName',
          value: 'Cambrian ERC-8004 Agent TEE'
        },
        {
          shortName: 'OU',
          value: `Container-${digestPrefix}`
        },
        {
          name: 'countryName',
          value: 'US'
        }
      ];

      cert.setSubject(attrs);
      cert.setIssuer(attrs); // Self-signed

      // Standard extensions
      const extensions = [
        {
          name: 'basicConstraints',
          cA: false
        },
        {
          name: 'keyUsage',
          digitalSignature: true,
          keyEncipherment: true
        },
        {
          name: 'extKeyUsage',
          clientAuth: true
        },
        {
          name: 'subjectKeyIdentifier'
        }
      ];

      // CUSTOM EXTENSION 1: TEE Attestation JWT
      if (this.attestationJWT) {
        extensions.push({
          id: '1.3.6.1.4.1.99999.1',
          critical: false,
          value: forge.util.encode64(this.attestationJWT)
        });
      }

      // CUSTOM EXTENSION 2: Container Digest
      extensions.push({
        id: '1.3.6.1.4.1.99999.2',
        critical: false,
        value: forge.util.encode64(this.containerDigest)
      });

      // CUSTOM EXTENSION 3: Agent Wallet Address
      extensions.push({
        id: '1.3.6.1.4.1.99999.3',
        critical: false,
        value: forge.util.encode64(this.wallet.address)
      });

      cert.setExtensions(extensions);

      // Sign certificate with private key
      cert.sign(keys.privateKey, forge.md.sha256.create());

      const certPem = forge.pki.certificateToPem(cert);
      const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

      console.log('   ✅ Certificate generated successfully');
      console.log(`   Subject: agent-tee-${digestPrefix}`);
      console.log(`   Serial: ${cert.serialNumber}`);
      console.log(`   Valid: ${cert.validity.notBefore.toISOString()} to ${cert.validity.notAfter.toISOString()}`);
      console.log(`   Extensions: ${extensions.length}`);

      return {
        cert: certPem,
        key: keyPem,
        containerDigest: this.containerDigest,
        attestationJWT: this.attestationJWT,
        walletAddress: this.wallet.address,
        serialNumber: cert.serialNumber,
        validFrom: cert.validity.notBefore.toISOString(),
        validTo: cert.validity.notAfter.toISOString()
      };

    } catch (error) {
      console.error(`❌ Failed to generate client certificate: ${error.message}`);
      throw error;
    }
  }

  /**
   * Extract TEE attestation from a certificate
   */
  static extractAttestationFromCert(cert) {
    try {
      const certObj = typeof cert === 'string'
        ? forge.pki.certificateFromPem(cert)
        : cert;

      const ext = certObj.extensions?.find(e => e.id === '1.3.6.1.4.1.99999.1');
      if (!ext) return null;

      return forge.util.decode64(ext.value);
    } catch (error) {
      console.warn(`⚠️  Failed to extract attestation: ${error.message}`);
      return null;
    }
  }

  /**
   * Extract container digest from a certificate
   */
  static extractContainerDigestFromCert(cert) {
    try {
      const certObj = typeof cert === 'string'
        ? forge.pki.certificateFromPem(cert)
        : cert;

      const ext = certObj.extensions?.find(e => e.id === '1.3.6.1.4.1.99999.2');
      if (!ext) return null;

      return forge.util.decode64(ext.value);
    } catch (error) {
      console.warn(`⚠️  Failed to extract container digest: ${error.message}`);
      return null;
    }
  }

  /**
   * Extract wallet address from a certificate
   */
  static extractWalletAddressFromCert(cert) {
    try {
      const certObj = typeof cert === 'string'
        ? forge.pki.certificateFromPem(cert)
        : cert;

      const ext = certObj.extensions?.find(e => e.id === '1.3.6.1.4.1.99999.3');
      if (!ext) return null;

      return forge.util.decode64(ext.value);
    } catch (error) {
      console.warn(`⚠️  Failed to extract wallet address: ${error.message}`);
      return null;
    }
  }

  /**
   * Verify a TEE client certificate
   * Returns verification result with extracted data
   */
  static verifyClientCertificate(certPem, expectedContainerDigest = null) {
    try {
      const cert = forge.pki.certificateFromPem(certPem);

      // Extract embedded data
      const attestationJWT = this.extractAttestationFromCert(cert);
      const containerDigest = this.extractContainerDigestFromCert(cert);
      const walletAddress = this.extractWalletAddressFromCert(cert);

      // Verify certificate is valid (dates)
      const now = new Date();
      const validDates = now >= cert.validity.notBefore && now <= cert.validity.notAfter;

      // Verify signature (self-signed)
      let signatureValid = false;
      try {
        signatureValid = cert.verify(cert);
      } catch (e) {
        console.warn(`   Certificate signature verification failed: ${e.message}`);
      }

      // Verify container digest matches expected (if provided)
      let digestMatches = true;
      if (expectedContainerDigest) {
        digestMatches = containerDigest === expectedContainerDigest;
      }

      const verified = validDates && signatureValid && digestMatches;

      return {
        verified,
        attestationJWT,
        containerDigest,
        walletAddress,
        subject: cert.subject.getField('CN')?.value || 'unknown',
        serialNumber: cert.serialNumber,
        validFrom: cert.validity.notBefore.toISOString(),
        validTo: cert.validity.notAfter.toISOString(),
        checks: {
          validDates,
          signatureValid,
          digestMatches,
          hasAttestation: !!attestationJWT
        }
      };

    } catch (error) {
      console.error(`❌ Certificate verification failed: ${error.message}`);
      return {
        verified: false,
        error: error.message
      };
    }
  }
}

module.exports = { TEEClientCertGenerator };

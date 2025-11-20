#!/usr/bin/env node
/**
 * TLS Certificate Pinning Module
 *
 * Provides certificate pinning for external API calls to prevent MITM attacks.
 * This addresses the "Network Integrity" limitation from HonestLimitationsPanel.
 *
 * Security Properties:
 * - Pins TLS certificates for trusted endpoints
 * - Detects certificate substitution (MITM attacks)
 * - Provides cryptographic proof of endpoint identity
 * - Maintains certificate fingerprint database
 *
 * Usage:
 * const httpsAgent = createPinnedAgent('cambrian-api');
 * axios.get(url, { httpsAgent });
 */

const https = require('https');
const crypto = require('crypto');
const tls = require('tls');

/**
 * Known certificate fingerprints for trusted endpoints
 * These should be updated when certificates are renewed
 *
 * To get current fingerprint:
 * openssl s_client -connect opabinia.cambrian.network:443 < /dev/null 2>/dev/null | \
 *   openssl x509 -fingerprint -sha256 -noout
 */
const PINNED_CERTIFICATES = {
  'cambrian-api': {
    hostname: 'opabinia.cambrian.network',
    fingerprints: [
      // Primary certificate (will be populated on first connection if not set)
      null
    ],
    validFrom: null,
    validTo: null
  },
  'pyth-api': {
    hostname: 'api.pyth.network',
    fingerprints: [
      null
    ],
    validFrom: null,
    validTo: null
  }
};

/**
 * Calculate SHA-256 fingerprint of a certificate
 * @param {object} cert - TLS certificate
 * @returns {string} Fingerprint in format "SHA256:..."
 */
function calculateFingerprint(cert) {
  const derCert = cert.raw;
  const hash = crypto.createHash('sha256').update(derCert).digest('hex');
  return 'SHA256:' + hash.toUpperCase().match(/.{2}/g).join(':');
}

/**
 * Verify certificate against pinned fingerprints
 * @param {string} hostname - Hostname being connected to
 * @param {object} cert - TLS certificate to verify
 * @returns {object} Verification result
 */
function verifyCertificatePin(hostname, cert) {
  const fingerprint = calculateFingerprint(cert);

  // Find pinning configuration for this hostname
  const pinConfig = Object.values(PINNED_CERTIFICATES).find(
    config => config.hostname === hostname
  );

  if (!pinConfig) {
    // No pinning configured for this hostname - allow but warn
    return {
      verified: true,
      pinned: false,
      fingerprint,
      warning: `No certificate pinning configured for ${hostname}`,
      action: 'allow'
    };
  }

  // Check if any fingerprints are configured
  const configuredFingerprints = pinConfig.fingerprints.filter(f => f !== null);

  if (configuredFingerprints.length === 0) {
    // First connection - store fingerprint for future verification
    console.log(`📌 First connection to ${hostname}, storing certificate fingerprint: ${fingerprint}`);
    pinConfig.fingerprints[0] = fingerprint;
    pinConfig.validFrom = cert.valid_from;
    pinConfig.validTo = cert.valid_to;

    return {
      verified: true,
      pinned: true,
      fingerprint,
      action: 'stored',
      message: 'Certificate fingerprint stored for future verification'
    };
  }

  // Verify against pinned fingerprints
  const isMatch = configuredFingerprints.includes(fingerprint);

  if (!isMatch) {
    // CRITICAL: Certificate doesn't match pinned fingerprint - possible MITM!
    console.error(`🚨 SECURITY ALERT: Certificate mismatch for ${hostname}`);
    console.error(`Expected one of: ${configuredFingerprints.join(', ')}`);
    console.error(`Received: ${fingerprint}`);

    return {
      verified: false,
      pinned: true,
      fingerprint,
      expectedFingerprints: configuredFingerprints,
      action: 'reject',
      error: 'Certificate fingerprint mismatch - possible MITM attack'
    };
  }

  // Certificate matches pinned fingerprint
  return {
    verified: true,
    pinned: true,
    fingerprint,
    action: 'accept',
    message: 'Certificate verified against pinned fingerprint'
  };
}

/**
 * Create HTTPS agent with certificate pinning
 * @param {string} endpointName - Name of endpoint (e.g., 'cambrian-api')
 * @param {object} options - Additional agent options
 * @returns {https.Agent} HTTPS agent with pinning enabled
 */
function createPinnedAgent(endpointName, options = {}) {
  const pinConfig = PINNED_CERTIFICATES[endpointName];

  if (!pinConfig) {
    console.warn(`⚠️  No pinning configuration for ${endpointName}, using standard HTTPS`);
    return new https.Agent({
      rejectUnauthorized: true,
      ...options
    });
  }

  return new https.Agent({
    rejectUnauthorized: true,
    checkServerIdentity: (hostname, cert) => {
      // First verify standard hostname matching
      const hostnameError = tls.checkServerIdentity(hostname, cert);
      if (hostnameError) {
        return hostnameError;
      }

      // Then verify certificate pinning
      const pinResult = verifyCertificatePin(hostname, cert);

      if (!pinResult.verified) {
        return new Error(pinResult.error || 'Certificate pinning verification failed');
      }

      // Certificate is valid and matches pin
      return undefined;
    },
    ...options
  });
}

/**
 * Get current certificate information for a hostname
 * Useful for debugging and updating pins
 * @param {string} hostname - Hostname to check
 * @param {number} port - Port (default 443)
 * @returns {Promise<object>} Certificate information
 */
async function getCertificateInfo(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port,
      method: 'GET',
      rejectUnauthorized: true
    };

    const req = https.request(options, (res) => {
      const cert = res.socket.getPeerCertificate();

      if (!cert || Object.keys(cert).length === 0) {
        reject(new Error('No certificate received'));
        return;
      }

      const fingerprint = calculateFingerprint(cert);

      resolve({
        fingerprint,
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        serialNumber: cert.serialNumber,
        subjectAltNames: cert.subjectaltname
      });

      res.resume();
    });

    req.on('error', reject);
    req.end();
  });
}

module.exports = {
  createPinnedAgent,
  verifyCertificatePin,
  calculateFingerprint,
  getCertificateInfo,
  PINNED_CERTIFICATES
};

#!/usr/bin/env node

import * as crypto from 'crypto';

/**
 * Execution Logger for TEE MCP Server
 *
 * Logs all tool executions for proof generation:
 * - Request hashes
 * - Response hashes
 * - Timestamps
 * - TLS certificates from API calls
 */

export interface ToolExecutionLog {
  timestamp: number;
  toolName: string;
  requestHash: string;
  responseHash: string;
  requestSize: number;
  responseSize: number;
  duration: number;
  tlsCertificate?: TLSCertificateInfo;
}

export interface TLSCertificateInfo {
  verified: boolean;
  subject: string;
  issuer: string;
  fingerprint: string;
  validFrom: string;
  validTo: string;
  protocol?: string;
  cipher?: string;
}

export interface ExecutionSummary {
  totalExecutions: number;
  executionLogs: ToolExecutionLog[];
  containerDigest: string;
  teeMode: boolean;
}

export class ExecutionLogger {
  private logs: ToolExecutionLog[] = [];
  private containerDigest: string;
  private teeMode: boolean;

  constructor() {
    this.containerDigest = process.env.CONTAINER_DIGEST || 'unknown';
    this.teeMode = process.env.TEE_MODE === 'true';
  }

  /**
   * Log a tool execution
   */
  logExecution(
    toolName: string,
    request: any,
    response: any,
    duration: number,
    tlsCertificate?: TLSCertificateInfo
  ): ToolExecutionLog {
    const requestStr = JSON.stringify(request);
    const responseStr = JSON.stringify(response);

    const log: ToolExecutionLog = {
      timestamp: Date.now(),
      toolName,
      requestHash: this.hashData(requestStr),
      responseHash: this.hashData(responseStr),
      requestSize: requestStr.length,
      responseSize: responseStr.length,
      duration,
      tlsCertificate
    };

    this.logs.push(log);

    // Keep only last 100 executions to prevent memory issues
    if (this.logs.length > 100) {
      this.logs.shift();
    }

    return log;
  }

  /**
   * Get all execution logs
   */
  getLogs(): ToolExecutionLog[] {
    return [...this.logs];
  }

  /**
   * Get execution summary for attestation
   */
  getSummary(): ExecutionSummary {
    return {
      totalExecutions: this.logs.length,
      executionLogs: this.getLogs(),
      containerDigest: this.containerDigest,
      teeMode: this.teeMode
    };
  }

  /**
   * Clear logs (for privacy after attestation)
   */
  clearLogs(): void {
    this.logs = [];
  }

  /**
   * Hash data using SHA-256
   */
  private hashData(data: string): string {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Extract TLS certificate info from socket (if available)
   */
  static extractTLSCertificate(socket: any): TLSCertificateInfo | undefined {
    if (!socket || !socket.getPeerCertificate) {
      return undefined;
    }

    try {
      const cert = socket.getPeerCertificate(true);

      if (!cert || Object.keys(cert).length === 0) {
        return undefined;
      }

      // Compute SHA-256 fingerprint
      const certDER = cert.raw;
      const fingerprint = certDER
        ? crypto
            .createHash('sha256')
            .update(certDER)
            .digest('hex')
            .match(/.{2}/g)!
            .join(':')
            .toUpperCase()
        : 'unknown';

      return {
        verified: socket.authorized || false,
        subject: cert.subject?.CN || cert.subject?.O || 'Unknown',
        issuer: cert.issuer?.CN || cert.issuer?.O || 'Unknown',
        fingerprint,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        protocol: socket.getProtocol?.(),
        cipher: socket.getCipher?.()?.name
      };
    } catch (error) {
      console.warn('Failed to extract TLS certificate:', error);
      return undefined;
    }
  }
}

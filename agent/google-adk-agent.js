/**
 * Google ADK Agent - Node.js Implementation
 * Uses Gemini 2.5 Flash with MCP tool calling
 * Enhanced with complete network logging for dual TEE proof generation
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');
const axios = require('axios');
const crypto = require('crypto');
const dns = require('dns').promises;
const https = require('https');

/**
 * HTTPLogger - Captures complete HTTP request/response data for proofs
 */
class HTTPLogger {
  constructor() {
    this.requestLog = [];
    this.responseLog = [];
    this.requestCounter = 0;
  }

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

  logResponse(requestId, status, headers, body, tlsCertificate = null) {
    const responseRecord = {
      requestId,
      timestamp: Date.now(),
      status,
      headers: headers || {},
      body: body || null,
      bodyHash: body ? crypto.createHash('sha256').update(typeof body === 'string' ? body : JSON.stringify(body)).digest('hex') : null,
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

  sanitizeHeaders(headers) {
    if (!headers) return {};
    const sanitized = { ...headers };
    const sensitiveKeys = ['X-API-Key', 'Authorization', 'Cookie', 'Set-Cookie'];
    for (const key of sensitiveKeys) {
      if (sanitized[key]) {
        sanitized[key] = '[REDACTED]';
      }
    }
    return sanitized;
  }

  getCompleteLog() {
    return {
      requests: this.requestLog,
      responses: this.responseLog,
      totalRequests: this.requestLog.length,
      totalResponses: this.responseLog.length
    };
  }

  clearLogs() {
    this.requestLog = [];
    this.responseLog = [];
    this.requestCounter = 0;
  }
}

/**
 * DNSLogger - Captures DNS resolution data for proof verification
 */
class DNSLogger {
  constructor() {
    this.resolutions = [];
  }

  async logDNSResolution(hostname) {
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
      return resolution;
    }
  }

  getResolutions() {
    return this.resolutions;
  }

  clearResolutions() {
    this.resolutions = [];
  }
}

class GoogleADKAgent {
  constructor(geminiApiKey, mcpServerUrl, cambrianApiKey) {
    this.geminiApiKey = geminiApiKey || process.env.GEMINI_API_KEY;
    this.mcpServerUrl = mcpServerUrl || process.env.MCP_SERVER_URL;
    this.cambrianApiKey = cambrianApiKey || process.env.SERVER_CAMBRIAN_API_KEY;

    if (!this.geminiApiKey) {
      throw new Error('GEMINI_API_KEY is required');
    }

    this.genAI = new GoogleGenerativeAI(this.geminiApiKey);
    this.tools = [];
    this.initialized = false;
    this.sessions = new Map(); // Session ID -> conversation history

    // Network logging for proof generation
    this.httpLogger = new HTTPLogger();
    this.dnsLogger = new DNSLogger();
  }

  /**
   * Initialize by discovering MCP tools
   */
  async initialize() {
    if (this.initialized) return;

    console.log('🔄 Discovering MCP tools...');

    try {
      // Ensure MCP server URL ends with /mcp
      const mcpEndpoint = this.mcpServerUrl.endsWith('/mcp') ? this.mcpServerUrl : `${this.mcpServerUrl}/mcp`;

      // Fetch tools from MCP server
      const response = await axios.post(
        mcpEndpoint,
        {
          jsonrpc: '2.0',
          method: 'tools/list',
          id: 1
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'Authorization': `Bearer ${this.cambrianApiKey}`
          },
          timeout: 30000, // 30 second timeout
          responseType: 'text' // Get raw text to parse SSE format
        }
      );

      // Parse SSE (Server-Sent Events) format
      // Response format: "event: message\ndata: {json}\n\n"
      let jsonData;
      if (typeof response.data === 'string' && response.data.includes('data:')) {
        // Extract JSON from SSE format
        const lines = response.data.split('\n');
        const dataLine = lines.find(line => line.startsWith('data:'));
        if (dataLine) {
          const jsonStr = dataLine.substring(5).trim(); // Remove "data:" prefix
          jsonData = JSON.parse(jsonStr);
        }
      } else {
        // Direct JSON response
        jsonData = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
      }

      // Parse tools and convert to Gemini function declarations
      const mcpTools = jsonData?.result?.tools || [];
      this.tools = mcpTools.map(tool => this.convertMCPToolToGemini(tool));

      console.log(`✅ Discovered ${this.tools.length} MCP tools`);
      this.initialized = true;
    } catch (error) {
      console.error('Failed to discover MCP tools:', error.message);
      throw error;
    }
  }

  /**
   * Convert MCP tool to Gemini function declaration
   */
  convertMCPToolToGemini(mcpTool) {
    const properties = {};
    const required = [];

    if (mcpTool.inputSchema?.properties) {
      for (const [key, value] of Object.entries(mcpTool.inputSchema.properties)) {
        if (key.startsWith('_')) continue; // Skip internal params

        properties[key] = {
          type: value.type?.toUpperCase() || 'STRING',
          description: value.description || ''
        };

        if (mcpTool.inputSchema.required?.includes(key)) {
          required.push(key);
        }
      }
    }

    return {
      name: mcpTool.name,
      description: mcpTool.description,
      parameters: {
        type: 'OBJECT',
        properties,
        required
      }
    };
  }

  /**
   * Process a question with conversation history
   */
  async processQuestion(question, sessionId, conversationHistory = null) {
    if (!this.initialized) {
      await this.initialize();
    }

    sessionId = sessionId || `session_${Date.now()}`;

    // Get or create session
    let history = this.sessions.get(sessionId) || [];

    // Add conversation history if provided
    if (conversationHistory && conversationHistory.length > 0) {
      history = conversationHistory.map(msg => ({
        role: msg.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: msg.content }]
      }));
    }

    try {
      // Create model with tools
      const model = this.genAI.getGenerativeModel({
        model: 'gemini-1.5-pro',
        tools: [{ functionDeclarations: this.tools }],
        systemInstruction: this.getSystemInstruction()
      });

      // Start chat with history
      const chat = model.startChat({
        history
      });

      // Send message
      const result = await chat.sendMessage(question);
      const response = result.response;

      const toolsUsed = [];
      let finalAnswer = '';

      // Check for function calls
      const functionCalls = response.functionCalls();

      if (functionCalls && functionCalls.length > 0) {
        // Execute function calls via MCP
        const functionResponses = [];

        for (const call of functionCalls) {
          console.log(`🔧 Calling tool: ${call.name}`);
          toolsUsed.push(call.name);

          const mcpResult = await this.callMCPTool(call.name, call.args);
          functionResponses.push({
            functionResponse: {
              name: call.name,
              response: mcpResult
            }
          });
        }

        // Send function responses back to Gemini
        const followUpResult = await chat.sendMessage(functionResponses);
        finalAnswer = followUpResult.response.text();
      } else {
        // No function calls, just text response
        finalAnswer = response.text();
      }

      // Update session history
      history.push({
        role: 'user',
        parts: [{ text: question }]
      });
      history.push({
        role: 'model',
        parts: [{ text: finalAnswer }]
      });
      this.sessions.set(sessionId, history);

      return {
        success: true,
        answer: finalAnswer,
        tools_used: toolsUsed,
        metadata: {
          model: 'gemini-2.5-flash',
          protocol: 'MCP',
          total_tools: this.tools.length
        }
      };
    } catch (error) {
      console.error('Error processing question:', error);
      return {
        success: false,
        answer: `Error processing request: ${error.message}`,
        error: error.message,
        tools_used: []
      };
    }
  }

  /**
   * Capture TLS certificate from HTTPS connection
   */
  captureTLSCertificate(socket) {
    if (!socket || !socket.getPeerCertificate) {
      return null;
    }

    try {
      const cert = socket.getPeerCertificate(true);
      if (!cert || Object.keys(cert).length === 0) {
        return null;
      }

      const certDER = cert.raw;
      const fingerprint = crypto
        .createHash('sha256')
        .update(certDER)
        .digest('hex')
        .match(/.{2}/g)
        .join(':')
        .toUpperCase();

      const authorized = socket.authorized;

      return {
        verified: authorized,
        authError: socket.authorizationError ? socket.authorizationError.message : null,
        subject: cert.subject?.CN || cert.subject?.O || 'Unknown',
        issuer: cert.issuer?.CN || cert.issuer?.O || 'Unknown',
        fingerprint: fingerprint,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name || 'Unknown',
        timestamp: Date.now()
      };
    } catch (error) {
      console.warn(`⚠️  TLS certificate capture failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Call MCP tool with complete network logging
   */
  async callMCPTool(toolName, args) {
    try {
      // Ensure MCP server URL ends with /mcp
      const mcpEndpoint = this.mcpServerUrl.endsWith('/mcp') ? this.mcpServerUrl : `${this.mcpServerUrl}/mcp`;

      // Log DNS resolution BEFORE making request
      const url = new URL(mcpEndpoint);
      try {
        await this.dnsLogger.logDNSResolution(url.hostname);
      } catch (dnsError) {
        console.warn(`⚠️  DNS logging failed (continuing anyway): ${dnsError.message}`);
      }

      // Prepare request payload
      const requestPayload = {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: {
          name: toolName,
          arguments: args
        },
        id: Date.now()
      };

      const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Authorization': `Bearer ${this.cambrianApiKey}`
      };

      // Log HTTP request BEFORE sending
      const requestRecord = this.httpLogger.logRequest(
        mcpEndpoint,
        'POST',
        headers,
        requestPayload
      );

      console.log(`📤 MCP Request logged: ${requestRecord.requestId} → ${toolName}`);

      // Make request with custom HTTPS agent to capture TLS
      let tlsCertificate = null;

      const httpsAgent = new https.Agent({
        rejectUnauthorized: true
      });

      // Capture TLS certificate
      httpsAgent.once('socket', (socket) => {
        socket.once('secureConnect', () => {
          tlsCertificate = this.captureTLSCertificate(socket);
        });
      });

      const response = await axios.post(
        mcpEndpoint,
        requestPayload,
        {
          headers,
          timeout: 60000,
          httpsAgent,
          responseType: 'text' // Get raw text to parse SSE format
        }
      );

      // Parse SSE (Server-Sent Events) format
      let jsonData;
      if (typeof response.data === 'string' && response.data.includes('data:')) {
        // Extract JSON from SSE format
        const lines = response.data.split('\n');
        const dataLine = lines.find(line => line.startsWith('data:'));
        if (dataLine) {
          const jsonStr = dataLine.substring(5).trim(); // Remove "data:" prefix
          jsonData = JSON.parse(jsonStr);
        }
      } else {
        // Direct JSON response
        jsonData = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
      }

      const responseData = JSON.stringify(jsonData);

      // Log HTTP response AFTER receiving
      const responseRecord = this.httpLogger.logResponse(
        requestRecord.requestId,
        response.status,
        response.headers,
        responseData,
        tlsCertificate
      );

      console.log(`📥 MCP Response logged: ${responseRecord.requestId} (status: ${response.status})`);

      const result = jsonData?.result;

      if (result?.content && result.content.length > 0) {
        return { result: result.content[0].text };
      }

      return { result: JSON.stringify(result) };
    } catch (error) {
      console.error(`Error calling MCP tool ${toolName}:`, error.message);
      return { error: error.message };
    }
  }

  /**
   * Get system instruction for Gemini
   */
  getSystemInstruction() {
    const currentTime = Math.floor(Date.now() / 1000);
    const time24hAgo = currentTime - 86400;

    return `You are a Cambrian blockchain data assistant. ALWAYS use the available tools to answer questions.

CURRENT UNIX TIMESTAMP: ${currentTime}
24 HOURS AGO: ${time24hAgo}

CRITICAL RULES FOR PARAMETER HANDLING:

1. NEVER ask for missing parameters - use intelligent defaults immediately
2. When time parameters are missing, use these values:
   - after_time: ${time24hAgo} (24 hours ago)
   - before_time: ${currentTime} (current time)
   - interval: "1H" (hourly)
3. When limits are missing, use: 10 or 20
4. When days parameter is missing, use: 7
5. For multi-address endpoints without specific addresses, explain you need specific addresses

DEFAULT PARAMETER VALUES:
- Time ranges: Last 24 hours (calculate unix timestamps)
- Intervals: "1H" for OHLCV data
- Limits: 10 for lists
- Days: 7 for historical data
- Chain ID: 8453 for Base (EVM)
- Order: "liquidity" or "volume" for sorting

COMMON ADDRESSES:
- SOL: So11111111111111111111111111111111111111112
- USDC: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
- USDT: Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB
- BONK: DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263

ALWAYS inform user of default choices: "I'll use the last 24 hours of data with hourly intervals."
ALWAYS call tools with defaults rather than asking for parameters.`;
  }

  /**
   * Get execution logs for proof generation
   */
  getExecutionLogs() {
    return {
      httpLogs: this.httpLogger.getCompleteLog(),
      dnsLogs: this.dnsLogger.getResolutions()
    };
  }

  /**
   * Clear execution logs (call at start of new request for clean logs)
   */
  clearExecutionLogs() {
    this.httpLogger.clearLogs();
    this.dnsLogger.clearResolutions();
  }

  /**
   * Get capabilities
   */
  getCapabilities() {
    return {
      mode: 'google_adk',
      model: 'gemini-2.5-flash',
      protocol: 'MCP',
      mcpServer: this.mcpServerUrl,
      supportsStreaming: false,
      supportsToolCalling: true,
      totalTools: this.tools.length,
      networkLogging: {
        http: true,
        dns: true,
        tls: true
      }
    };
  }
}

module.exports = { GoogleADKAgent };

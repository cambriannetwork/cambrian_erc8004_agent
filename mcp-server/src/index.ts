#!/usr/bin/env node

import * as dotenv from "dotenv";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { 
  ListToolsRequestSchema,
  CallToolRequestSchema 
} from "@modelcontextprotocol/sdk/types.js";
import express, { Request, Response } from "express";
import { Server as HTTPServer } from "http";
import axios from "axios";
import rateLimit from "express-rate-limit";
import cors from "cors";

dotenv.config();

// Cambrian API configuration
const CAMBRIAN_API_BASE_URL = "https://opabinia.cambrian.network";
const CAMBRIAN_OPENAPI_URL = "https://opabinia.cambrian.network/openapi.json";

// Server's Cambrian API key for backend calls (optional)
const SERVER_CAMBRIAN_API_KEY = process.env.SERVER_CAMBRIAN_API_KEY;

// Rate limiting configuration  
const VERISENSE_RATE_LIMIT = parseInt(process.env.VERISENSE_RATE_LIMIT || "1000");
const VERISENSE_WINDOW_HOURS = parseInt(process.env.VERISENSE_WINDOW_HOURS || "1");
const AUTH_FALLBACK_LIMIT = parseInt(process.env.AUTH_FALLBACK_LIMIT || "50000");
const AUTH_FALLBACK_WINDOW_MINUTES = parseInt(process.env.AUTH_FALLBACK_WINDOW_MINUTES || "10");

// Response truncation configuration
const DEFAULT_RESPONSE_MAX_LENGTH = parseInt(process.env.RESPONSE_MAX_LENGTH || "30000");

// Store client API keys from MCP connections
const clientApiKeys = new Map<string, string>();

// Extract and store client's CAMBRIAN_API_KEY from request
function extractApiKey(req: Request, res: Response, next: any) {
  try {
    // Check for CAMBRIAN_API_KEY in various locations
    const authHeader = req.headers.authorization;
    const bearerKey = authHeader?.replace('Bearer ', '');
    const queryKey = req.query.CAMBRIAN_API_KEY as string;
    const headerKey = req.headers['x-cambrian-api-key'] as string;
    
    // Store the API key for this connection if provided
    const apiKey = bearerKey || queryKey || headerKey;
    if (apiKey) {
      // Store with session ID or request IP as identifier
      const sessionId = req.headers['x-session-id'] as string;
      const clientId = sessionId || req.ip || req.connection.remoteAddress || 'unknown';
      clientApiKeys.set(clientId, apiKey);
      
      // Attach to request for easy access
      (req as any).clientId = clientId;
      (req as any).apiKey = apiKey;
    }
    
    next();
  } catch (error) {
    console.error('Error extracting API key:', error);
    next();
  }
}

// Type definitions for OpenAPI schema
interface OpenAPISchema {
  paths: {
    [path: string]: {
      [method: string]: {
        operationId?: string;
        summary?: string;
        description?: string;
        parameters?: Array<{
          name: string;
          in: string;
          required?: boolean;
          schema?: {
            type: string;
            default?: any;
          };
          description?: string;
        }>;
      };
    };
  };
}

// Fetch and parse OpenAPI schema
async function fetchOpenAPISchema(): Promise<OpenAPISchema | null> {
  try {
    console.log("Fetching Cambrian API OpenAPI schema...");
    const response = await axios.get(CAMBRIAN_OPENAPI_URL);
    console.log("Successfully fetched OpenAPI schema");
    return response.data;
  } catch (error) {
    console.error("Failed to fetch OpenAPI schema:", error);
    return null;
  }
}

// Make API request to Cambrian
async function makeApiRequest(
  endpoint: string,
  params: Record<string, any> = {},
  clientId?: string
): Promise<any> {
  // Try to get client's API key first, fallback to server key
  const apiKey = clientId ? clientApiKeys.get(clientId) : null;
  const finalApiKey = apiKey || SERVER_CAMBRIAN_API_KEY;
  
  if (!finalApiKey) {
    throw new Error("No CAMBRIAN_API_KEY available. Client must provide API key via Authorization header or the server must have SERVER_CAMBRIAN_API_KEY set.");
  }
  
  try {
    const url = `${CAMBRIAN_API_BASE_URL}${endpoint}`;
    const response = await axios.get(url, {
      params,
      headers: {
        'accept': 'application/json',
        'x-api-key': finalApiKey
      },
      timeout: 60000
    });
    return response.data;
  } catch (error: any) {
    if (error.response) {
      throw new Error(`API error ${error.response.status}: ${JSON.stringify(error.response.data)}`);
    }
    throw error;
  }
}

// Normalize path for docs tool
function normalizePath(path?: string): string {
  if (!path) return '';
  
  // Remove leading/trailing slashes and whitespace
  let normalized = path.trim().replace(/^\/+|\/+$/g, '');
  
  // Convert underscores to hyphens for consistency
  normalized = normalized.replace(/_/g, '-');
  
  return normalized;
}

// Truncate response if too long
function truncateResponse(data: any, maxLength: number = DEFAULT_RESPONSE_MAX_LENGTH): string {
  // Convert data to string if it's not already
  let text: string;
  if (typeof data === 'string') {
    text = data;
  } else {
    text = JSON.stringify(data, null, 2);
  }
  
  if (text.length <= maxLength) {
    return text;
  }
  
  const truncated = text.substring(0, maxLength);
  const truncationMessage = `\n\n---\n\n**Note: Response truncated due to size limitations (${maxLength.toLocaleString()} character limit).**\n\n` +
    'For complete data, please use the Cambrian API directly:\n' +
    '- Full documentation: https://docs.cambrian.org\n' +
    '- API endpoint: https://opabinia.cambrian.org\n' +
    '- OpenAPI spec: https://opabinia.cambrian.network/openapi.json';
  
  return truncated + truncationMessage;
}

// Fetch documentation from Cambrian docs site
async function fetchDocumentation(path?: string): Promise<string> {
  const normalizedPath = normalizePath(path);
  
  try {
    if (!normalizedPath) {
      // No path provided - return full llms.txt
      const response = await axios.get('https://docs.cambrian.org/llms.txt', {
        timeout: 30000
      });
      return response.data;
    }
    
    // Check if this is a top-level path (just "solana" or "evm")
    const isTopLevel = normalizedPath === 'solana' || normalizedPath === 'evm';
    
    // Check if this looks like a partial path (ends with a category like price-volume but not a full endpoint)
    const pathParts = normalizedPath.split('/');
    const isPartialPath = pathParts.length >= 2 && !normalizedPath.match(/\/(single|multi|current|hour|unix|details|holders|leaderboard|statistics|history|metrics|data|map|bounded)$/);
    
    // Try to fetch endpoint-specific documentation first (but not for partial paths)
    if (!isTopLevel && !isPartialPath) {
      try {
        const endpointUrl = `https://docs.cambrian.org/api/v1/${normalizedPath}/llms.txt`;
        const response = await axios.get(endpointUrl, { 
          timeout: 30000,
          headers: {
            'Accept': 'text/plain'
          }
        });
        // Check if we got HTML instead of text documentation
        if (typeof response.data === 'string' && !response.data.startsWith('<!')) {
          return response.data;
        }
      } catch (error: any) {
        // If endpoint-specific docs not found, fall through to filtering main docs
        // Ignore 404 errors and continue to filtering
      }
    }
    
    // Fetch main llms.txt and filter it
    const response = await axios.get('https://docs.cambrian.org/llms.txt', {
      timeout: 30000
    });
    const fullDocs = response.data as string;
    
    // Filter the documentation based on the path
    const lines = fullDocs.split('\n');
    const filteredLines: string[] = [];
    let inHeader = true;
    let includeNext = false;
    
    for (const line of lines) {
      // Keep header section until we hit the first endpoint
      if (inHeader) {
        if (line.startsWith('### ') || line.match(/^- GET \/api\/v1\//)) {
          inHeader = false;
        } else {
          filteredLines.push(line);
          continue;
        }
      }
      
      // Check if this line matches our path filter
      if (line.match(/^- GET \/api\/v1\//)) {
        const pathPattern = new RegExp(`^- GET /api/v1/${normalizedPath}`);
        if (pathPattern.test(line)) {
          filteredLines.push(line);
          includeNext = true;
        } else {
          includeNext = false;
        }
      } else if (includeNext && line.startsWith('  ')) {
        // Include description/docs lines that follow matching endpoints
        filteredLines.push(line);
      } else if (line.startsWith('### ')) {
        // Include section headers that match our path
        if (line.toLowerCase().includes(normalizedPath.toLowerCase())) {
          filteredLines.push(line);
        }
      }
    }
    
    // Add footer
    filteredLines.push('');
    filteredLines.push('## Key Resources');
    filteredLines.push('- Full API documentation: https://docs.cambrian.org');
    filteredLines.push('- OpenAPI specification: https://opabinia.cambrian.network/openapi.json');
    
    return filteredLines.join('\n');
  } catch (error: any) {
    throw new Error(`Failed to fetch documentation: ${error.message}`);
  }
}

async function main() {
  const app = express();
  const port = process.env.PORT || 8080;
  
  // Enable CORS for browser-based MCP clients
  app.use(cors({
    origin: true, // Allow all origins for MCP clients
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Cambrian-Api-Key']
  }));
  
  // Parse JSON bodies (except for /mcp which needs raw stream)
  app.use((req, res, next) => {
    if (req.path === '/mcp') {
      // Skip JSON parsing for MCP endpoint
      next();
    } else {
      express.json({ limit: '10mb' })(req, res, next);
    }
  });

  // Rate limiter based on client identifier
  const rateLimiter = rateLimit({
    windowMs: AUTH_FALLBACK_WINDOW_MINUTES * 60 * 1000,
    max: AUTH_FALLBACK_LIMIT,
    message: {
      error: "Rate limit exceeded",
      message: `Rate limit exceeded. Limit: ${AUTH_FALLBACK_LIMIT} per ${AUTH_FALLBACK_WINDOW_MINUTES} minutes`,
      retryAfter: `${AUTH_FALLBACK_WINDOW_MINUTES} minutes`,
      resetTime: new Date(Date.now() + AUTH_FALLBACK_WINDOW_MINUTES * 60 * 1000).toISOString()
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      // Rate limit by client IP
      return `client_${req.ip || req.connection.remoteAddress || 'unknown'}`;
    },
    skip: (req) => req.path === '/health' || req.path === '/'
  });


  // Fetch OpenAPI schema to build tools
  const schema = await fetchOpenAPISchema();
  if (!schema) {
    console.error("Failed to fetch OpenAPI schema. Server will run with limited functionality.");
  }

  // Create MCP server
  const server = new Server(
    {
      name: "cambrian-api-mcp",
      version: "1.0.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Store tools for registration
  const availableTools: any[] = [];
  let toolCount = 0;
  
  if (schema && schema.paths) {
    for (const [path, pathItem] of Object.entries(schema.paths)) {
      const getOperation = pathItem.get;
      if (!getOperation) continue;

      // Generate a better tool name with underscores preserving path structure
      // Use double underscore for path separators, single underscore for hyphens
      let toolName: string;
      if (getOperation.operationId) {
        // Transform existing operationId to add separators based on path structure
        // e.g., path="/api/v1/solana/ohlcv/token" -> "solana__ohlcv__token"
        // e.g., path="/api/v1/solana/price-current" -> "solana__price_current"
        const pathSegments = path.split('/').filter(s => s && s !== 'api' && s !== 'v1');
        // Replace hyphens with single underscore within segments
        const processedSegments = pathSegments.map(segment => segment.replace(/-/g, '_'));
        // Join segments with double underscore
        toolName = processedSegments.join('__');
      } else {
        // Fallback: generate from path
        toolName = `get_${path.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase()}`;
      }
      
      const description = getOperation.summary || getOperation.description || 
        `GET ${path}`;

      // Build input schema from parameters
      const inputSchema: any = {
        type: "object",
        properties: {},
        required: []
      };

      if (getOperation.parameters) {
        for (const param of getOperation.parameters) {
          if (param.in === 'query') {
            // Build parameter schema, including items for arrays (required by JSON Schema)
            const paramSchema: any = {
              type: param.schema?.type || 'string',
              description: param.description
            };

            // Include 'items' field for array types (required by JSON Schema spec)
            if (param.schema && 'items' in param.schema) {
              paramSchema.items = (param.schema as any).items;
            }

            // Include 'enum' if present for constrained values
            if (param.schema && 'enum' in param.schema) {
              paramSchema.enum = (param.schema as any).enum;
            }

            // Include 'default' if present
            if (param.schema && param.schema.default !== undefined) {
              paramSchema.default = param.schema.default;
            }

            inputSchema.properties[param.name] = paramSchema;

            if (param.required) {
              inputSchema.required.push(param.name);
            }
          }
        }
      }
      
      // Add optional maxLength parameter for response truncation
      inputSchema.properties['_maxResponseLength'] = {
        type: 'number',
        description: `Optional: Maximum response length in characters (default: ${DEFAULT_RESPONSE_MAX_LENGTH})`
      };

      // Store tool definition
      availableTools.push({
        name: toolName,
        description,
        inputSchema,
        path
      });

      toolCount++;
    }
  }

  // Register tools/list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools = [
      {
        name: "docs",
        description: "Get Cambrian API documentation. Without parameters returns overview. With path parameter (e.g., 'solana/tokens') returns specific endpoint docs or filtered list.",
        inputSchema: {
          type: "object",
          properties: {
            path: {
              type: "string",
              description: "API path (e.g., 'solana/tokens', 'evm', 'solana/price-volume'). Flexible formatting accepted."
            },
            _maxResponseLength: {
              type: "number",
              description: `Optional: Maximum response length in characters (default: ${DEFAULT_RESPONSE_MAX_LENGTH})`
            }
          }
        }
      },
      ...availableTools.map(tool => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema
      }))
    ];

    return { tools };
  });

  // Register tools/call handler
  server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
    const { name, arguments: args = {} } = request.params;
    
    // Extract maxResponseLength parameter if provided
    const maxResponseLength = args._maxResponseLength || DEFAULT_RESPONSE_MAX_LENGTH;
    
    // Remove the internal parameter before passing to API
    const apiArgs = { ...args };
    delete apiArgs._maxResponseLength;

    if (name === "docs") {
      try {
        const documentation = await fetchDocumentation(apiArgs.path);
        // Apply truncation with custom or default limit
        const truncatedDocs = truncateResponse(documentation, maxResponseLength);
        return {
          content: [
            {
              type: "text",
              text: truncatedDocs
            }
          ]
        };
      } catch (error: any) {
        return {
          content: [
            {
              type: "text",
              text: `Error fetching documentation: ${error.message}`
            }
          ],
          isError: true
        };
      }
    }

    // Handle dynamic tools from Cambrian API
    const tool = availableTools.find(t => t.name === name);
    if (tool) {
      try {
        // Get client ID from the request context (would need to be passed through)
        // For now, we'll use the first available key
        const clientId = clientApiKeys.keys().next().value;
        const result = await makeApiRequest(tool.path, apiArgs, clientId);
        
        // Apply truncation to API responses
        const truncatedResult = truncateResponse(result, maxResponseLength);
        
        return {
          content: [
            {
              type: "text",
              text: truncatedResult
            }
          ]
        };
      } catch (error: any) {
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error.message}`
            }
          ],
          isError: true
        };
      }
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  console.log(`Registered ${toolCount} tools from Cambrian API`);

  // Transport handling
  let sseTransport: SSEServerTransport | null = null;
  let httpTransport: StreamableHTTPServerTransport | null = null;


  // Health check endpoint (no rate limiting)
  app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
      status: "healthy",
      toolCount,
      serverApiKeyConfigured: !!SERVER_CAMBRIAN_API_KEY,
      clientAuthRequired: !SERVER_CAMBRIAN_API_KEY
    });
  });

  // TEE Attestation endpoint (no rate limiting)
  app.get('/attestation', async (req: Request, res: Response) => {
    try {
      // Read attestation JWT from file saved by Go bootstrap
      const fs = await import('fs/promises');
      const attestationPath = '/app/attestation.jwt';

      let attestationJWT: string | null = null;
      try {
        attestationJWT = await fs.readFile(attestationPath, 'utf-8');
      } catch (error: any) {
        console.warn(`Failed to read attestation from ${attestationPath}: ${error.message}`);
      }

      // Get container digest and TEE info from environment
      const containerDigest = process.env.CONTAINER_DIGEST || 'unknown';
      const teeMode = process.env.TEE_MODE === 'true';

      // Build tools catalog
      const toolsCatalog = availableTools.map(tool => ({
        name: tool.name,
        path: tool.path,
        description: tool.description
      }));

      // Return attestation response
      const response = {
        success: true,
        attestationJWT: attestationJWT || null,
        container: {
          digest: containerDigest
        },
        platform: {
          provider: 'GCP',
          technology: 'AMD_SEV',
          confidentialSpace: true
        },
        securityLevel: teeMode ? 'MAXIMUM' : 'DEVELOPMENT',
        tools: toolsCatalog,
        toolCount: toolCount + 1, // +1 for docs tool
        timestamp: Date.now(),
        codeVerification: {
          containerDigest,
          teeMode,
          reproducibleBuild: teeMode
        }
      };

      res.status(200).json(response);
    } catch (error: any) {
      console.error('Error generating attestation response:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to generate attestation',
        message: error.message
      });
    }
  });

  // Root endpoint (no rate limiting)
  app.get('/', (req: Request, res: Response) => {
    res.status(200).json({ 
      service: "cambrian-api-mcp",
      status: "running",
      toolCount,
      authMode: SERVER_CAMBRIAN_API_KEY ? "server-authenticated" : "client-authenticated",
      message: `MCP server with ${toolCount} Cambrian API tools`,
      transports: {
        sse: "/sse",
        http: "/mcp"
      }
    });
  });

  // SSE endpoint for MCP (for future OAuth support)
  app.get('/sse', extractApiKey, rateLimiter, async (req: Request, res: Response) => {
    const clientId = (req as any).clientId || 'unknown';
    const hasApiKey = !!(req as any).apiKey;
    
    console.log(`SSE connection request from client: ${clientId}, has API key: ${hasApiKey}`);
    
    if (!hasApiKey && !SERVER_CAMBRIAN_API_KEY) {
      console.warn('No API key provided by client and no server key configured');
    }
    
    sseTransport = new SSEServerTransport('/messages', res);
    await server.connect(sseTransport);
    console.log(`SSE connection established for client: ${clientId}`);
  });

  // Messages endpoint for SSE transport
  app.post('/messages', extractApiKey, rateLimiter, async (req: Request, res: Response) => {
    if (sseTransport) {
      await sseTransport.handlePostMessage(req, res);
    } else {
      res.status(400).json({ error: "No active SSE connection" });
    }
  });
  
  // HTTP transport endpoint for MCP
  app.post('/mcp', async (req: Request, res: Response) => {
    // Extract API key from headers without consuming body
    const authHeader = req.headers.authorization;
    const bearerKey = authHeader?.replace('Bearer ', '');
    const headerKey = req.headers['x-cambrian-api-key'] as string;
    const apiKey = bearerKey || headerKey;
    
    console.log(`HTTP MCP request, has API key: ${!!apiKey}`);
    
    if (!apiKey && !SERVER_CAMBRIAN_API_KEY) {
      return res.status(401).json({ 
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "CAMBRIAN_API_KEY required. Provide via Authorization header or X-Cambrian-Api-Key header."
        },
        id: null
      });
    }
    
    // Store the API key for this connection
    const clientId = req.ip || req.connection.remoteAddress || 'unknown';
    if (apiKey) {
      clientApiKeys.set(clientId, apiKey);
    }
    
    // Use StreamableHTTPServerTransport for proper MCP handling
    if (!httpTransport) {
      httpTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined  // Stateless mode
      });
      await server.connect(httpTransport);
      console.log('Streamable HTTP transport connected');
    }
    
    try {
      await httpTransport.handleRequest(req, res);
    } catch (error: any) {
      console.error('MCP request error:', error);
      res.status(500).json({ error: error.message });
    }
  });
  
  // Health check for MCP endpoint
  app.get('/mcp', (req: Request, res: Response) => {
    res.json({ 
      transport: "streamable-http",
      status: "ready",
      message: "Streamable HTTP MCP transport ready - use POST to /mcp for requests"
    });
  });
  
  // OPTIONS endpoint for CORS preflight
  app.options('/mcp', cors(), (req: Request, res: Response) => {
    res.sendStatus(204);
  });

  // Start HTTP server
  const httpServer = app.listen(port, () => {
    console.log('========================================');
    console.log('🚀 Cambrian API MCP Server Started');
    console.log('========================================');
    console.log(`Port: ${port}`);
    console.log(`Environment: ${process.env.DEPLOY_ENV || 'development'}`);
    console.log(`TEE Mode: ${process.env.TEE_MODE === 'true' ? 'ENABLED' : 'disabled'}`);
    console.log(`Container Digest: ${process.env.CONTAINER_DIGEST ? process.env.CONTAINER_DIGEST.substring(0, 20) + '...' : 'N/A'}`);
    console.log(`\n🔗 Configuration:`);
    console.log(`  Cambrian API: ${CAMBRIAN_API_BASE_URL}`);
    console.log(`  Server API Key: ${SERVER_CAMBRIAN_API_KEY ? 'Configured (first 8 chars: ' + SERVER_CAMBRIAN_API_KEY.substring(0, 8) + '...)' : 'Not configured (client auth required)'}`);
    console.log(`  Tools: Dynamically loaded from Cambrian API OpenAPI spec`);
    console.log(`\n📡 Endpoints:`);
    console.log(`  Health: http://localhost:${port}/health`);
    console.log(`  SSE: http://localhost:${port}/sse`);
    console.log(`  MCP: http://localhost:${port}/mcp`);
    console.log('========================================');
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    httpServer.close(() => {
      console.log('HTTP server closed');
      process.exit(0);
    });
  });

  process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing HTTP server');
    httpServer.close(() => {
      console.log('HTTP server closed');
      process.exit(0);
    });
  });

  return httpServer;
}

// Start the server
main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
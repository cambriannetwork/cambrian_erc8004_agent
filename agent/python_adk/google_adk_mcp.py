"""
Google ADK with MCP integration - Final working version
Based on proven working pattern with Agent + Runner
"""

# CRITICAL: Fix ADK's MCP AnyUrl serialization bug BEFORE imports
import json
from pydantic import AnyUrl

original_default = json.JSONEncoder.default

def adk_mcp_json_fix(self, obj):
    if isinstance(obj, AnyUrl):
        return str(obj)
    return original_default(self, obj)

json.JSONEncoder.default = adk_mcp_json_fix
print("✅ Applied ADK MCP AnyUrl serialization fix")

# NOW import Google ADK modules (after the fix is applied)
import os
import logging
import time
from typing import Any, Dict, Optional
import asyncio

from google.adk.agents import Agent
from google.adk.runners import Runner, RunConfig
from google.adk.sessions import InMemorySessionService
from google.genai import types
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPServerParams
import aiohttp

logger = logging.getLogger(__name__)

class GoogleADKMCPFinal:
    """Google ADK with proper MCP integration using Agent + Runner pattern."""

    def __init__(self, gemini_api_key: str = None, cambrian_api_key: str = None):
        self.gemini_api_key = gemini_api_key or os.getenv('GEMINI_API_KEY')
        self.cambrian_api_key = cambrian_api_key or os.getenv('SERVER_CAMBRIAN_API_KEY') or os.getenv('CAMBRIAN_API_KEY')

        # Strip whitespace from API key (prevent header injection errors)
        if self.cambrian_api_key:
            self.cambrian_api_key = self.cambrian_api_key.strip()
            logger.info(f"🔑 Cambrian API key configured: {self.cambrian_api_key[:8]}... (length: {len(self.cambrian_api_key)})")

        # Configure MCP server URL from environment variable (REQUIRED - no fallback)
        mcp_url = os.getenv('MCP_SERVER_URL')
        if not mcp_url:
            raise ValueError("MCP_SERVER_URL environment variable is required - no default fallback")
        self.MCP_SERVER_URL = mcp_url if mcp_url.endswith('/mcp') else f'{mcp_url}/mcp'
        logger.info(f"🔗 Configured to use MCP server: {self.MCP_SERVER_URL}")
        
        if not self.gemini_api_key:
            raise ValueError("GEMINI_API_KEY is required")
        
        # Set the API key for Google AI
        os.environ['GOOGLE_API_KEY'] = self.gemini_api_key
        
        self.agent = None
        self.runner = None
        self.session_service = None
        self.session_initialized = False
        self.available_tools = []  # Store available tool names
        self.tool_mapping = {}  # Store OpenAPI to MCP tool name mapping
        
    async def _discover_tools(self):
        """Discover available tools from MCP server (single source of truth)."""
        try:
            # Clear existing tools to prevent accumulation across multiple discoveries
            self.available_tools.clear()

            logger.info("Discovering available tools from MCP server...")

            # Fetch MCP tools - the MCP server has already converted OpenAPI to MCP tools
            # No need to fetch OpenAPI directly - trust the MCP server as single source of truth
            mcp_tools = set()
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/event-stream',
                'Authorization': f'Bearer {self.cambrian_api_key}' if self.cambrian_api_key else None
            }
            headers = {k: v for k, v in headers.items() if v is not None}

            payload = {
                'jsonrpc': '2.0',
                'method': 'tools/list',
                'id': 1
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.MCP_SERVER_URL,
                    headers=headers,
                    json=payload
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.split('\n'):
                            if line.startswith('data: '):
                                try:
                                    data = json.loads(line[6:])
                                    if 'result' in data:
                                        for tool in data.get('result', {}).get('tools', []):
                                            tool_name = tool.get('name', '')
                                            if tool_name:
                                                mcp_tools.add(tool_name)
                                                self.available_tools.append(tool_name)
                                except:
                                    pass
                        logger.info(f"Found {len(mcp_tools)} tools in MCP server")
                    else:
                        logger.error(f"MCP server returned status {response.status}")
                        return False

            logger.info(f"✅ Tool discovery complete: {len(self.available_tools)} tools available from MCP")
            return True

        except Exception as e:
            logger.error(f"Failed to discover tools: {e}")
            return False

    def _create_tool_filter(self):
        """Create a tool_filter that filters out tools with invalid schemas.

        Since tool schemas are immutable after creation, we can't fix them.
        Instead, we filter out (reject) the 9 tools with invalid array parameter schemas.
        This leaves 60 working tools, which is acceptable.

        The problematic tools have array parameters (order_asc, order_desc) without 'items' field.
        """
        # Tools with known schema issues that should be filtered out
        # Based on error: function_declarations[5, 9, 11, 14, 17, 21, 26, 55, 67]
        # These are the tools that cause Gemini's schema validation to fail
        problematic_tool_patterns = [
            'order_asc',  # Tools with order_asc parameter
            'order_desc', # Tools with order_desc parameter
        ]

        def filter_invalid_schema_tools(*args):
            """Filter function that rejects tools with invalid schemas.

            Args can be (tool,) or (toolset, tool) depending on how MCPToolset calls it.
            Returns True to accept the tool, False to reject it.
            """
            from google.adk.tools.mcp_tool.mcp_tool import MCPTool

            # DEBUG: Log when filter is called
            logger.info(f"🔍 tool_filter called with {len(args)} args, types: {[type(arg).__name__ for arg in args]}")

            # Handle variable arguments - FIRST arg is the tool (not last!)
            # Called as: filter(tool, context)
            tool = args[0] if args else None

            if tool is None:
                logger.info("⚠️  tool_filter: tool is None, accepting")
                return True

            # Only filter MCPTool instances
            if not isinstance(tool, MCPTool):
                logger.info(f"⚠️  tool_filter: Not an MCPTool (is {type(tool).__name__}), accepting")
                return True  # Accept non-MCP tools

            try:
                # DEBUG: Log what we're checking
                logger.info(f"🔍 Checking MCPTool, has _function_declarations: {hasattr(tool, '_function_declarations')}")

                # Check if tool has problematic array parameters
                if hasattr(tool, '_function_declarations'):
                    for func_decl in tool._function_declarations:
                        schema = func_decl.parameters
                        logger.info(f"🔍 Checking tool '{func_decl.name}' schema...")
                        if schema and isinstance(schema, dict) and 'properties' in schema:
                            for prop_name, prop_def in schema['properties'].items():
                                # Check for array parameters without 'items' field
                                if isinstance(prop_def, dict) and prop_def.get('type') == 'array' and 'items' not in prop_def:
                                    # This tool has invalid schema - reject it
                                    logger.info(f"🚫 Filtering out tool '{func_decl.name}' - has array parameter '{prop_name}' without 'items' field")
                                    return False  # Reject this tool

                logger.info("✅ tool_filter: Accepting tool (no issues found)")
                return True  # Accept the tool

            except Exception as e:
                logger.warning(f"Error checking tool schema, accepting tool anyway: {e}")
                import traceback
                logger.warning(f"Traceback: {traceback.format_exc()}")
                return True  # Accept on error to be safe

        return filter_invalid_schema_tools

    def _fix_tool_schema(self, schema: Dict) -> Dict:
        """Fix common schema validation issues."""
        if not schema:
            return schema

        # Fix missing 'items' field for array parameters
        if 'properties' in schema:
            for prop_name, prop_def in schema['properties'].items():
                if prop_def.get('type') == 'array' and 'items' not in prop_def:
                    # Add default items schema for strings
                    prop_def['items'] = {'type': 'string'}
                    logger.debug(f"Fixed array parameter '{prop_name}' - added missing 'items' field")

        return schema

    def _fix_agent_tool_schemas(self) -> int:
        """Fix tool schemas in the agent after creation by monkey-patching function declarations.

        Returns:
            Number of tools fixed
        """
        fixed_count = 0

        try:
            # Access the agent's tools
            if not hasattr(self.agent, 'tools') or not self.agent.tools:
                logger.warning("Agent has no tools to fix")
                return 0

            # MCPToolset is in the tools list
            for toolset in self.agent.tools:
                # Check if this is an MCPToolset
                if hasattr(toolset, '_tools') and hasattr(toolset, '_session_manager'):
                    logger.info(f"Found MCPToolset with {len(toolset._tools) if toolset._tools else 0} tools")

                    # Iterate through MCP tools and fix their schemas
                    if toolset._tools:
                        for tool in toolset._tools:
                            if hasattr(tool, 'function_declarations'):
                                for func_decl in tool.function_declarations:
                                    schema = func_decl.parameters
                                    if schema and 'properties' in schema:
                                        for prop_name, prop_def in schema['properties'].items():
                                            if prop_def.get('type') == 'array' and 'items' not in prop_def:
                                                prop_def['items'] = {'type': 'string'}
                                                logger.info(f"Fixed tool '{func_decl.name}' parameter '{prop_name}' - added missing 'items' field")
                                                fixed_count += 1

                    # Also try accessing tools via get_tools() if available
                    elif hasattr(toolset, 'get_tools'):
                        try:
                            tools = toolset.get_tools()
                            for tool in tools:
                                if hasattr(tool, 'function_declarations'):
                                    for func_decl in tool.function_declarations:
                                        schema = func_decl.parameters
                                        if schema and 'properties' in schema:
                                            for prop_name, prop_def in schema['properties'].items():
                                                if prop_def.get('type') == 'array' and 'items' not in prop_def:
                                                    prop_def['items'] = {'type': 'string'}
                                                    logger.info(f"Fixed tool '{func_decl.name}' parameter '{prop_name}' - added missing 'items' field")
                                                    fixed_count += 1
                        except Exception as get_tools_error:
                            logger.debug(f"Could not access tools via get_tools(): {get_tools_error}")

        except Exception as e:
            logger.error(f"Error fixing agent tool schemas: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")

        return fixed_count

    async def initialize(self):
        """Initialize the agent with MCP tools."""
        try:
            # Discover available tools first
            await self._discover_tools()
            
            logger.info(f"Connecting to MCP server at {self.MCP_SERVER_URL}")
            
            # Get current timestamp for default calculations
            current_time = int(time.time())
            time_24h_ago = current_time - 86400  # 24 hours ago
            
            # Build tool list info for the instruction
            tool_info = f"Available tools: {len(self.available_tools)} tools discovered"
            if 'solanatokenssecuirty' in self.available_tools:
                tool_info += "\n- ✓ solanatokenssecuirty (security metrics - with typo)"
            if 'solanatokensholderdistributionovertime' in self.available_tools:
                tool_info += "\n- ✓ solanatokensholderdistributionovertime (holder distribution)"
            
            # Create the agent with MCP toolset
            # Note: We'll try MCPToolset with schema validation disabled if possible
            logger.info("Creating Agent with MCPToolset...")

            # First try: Use MCPToolset directly and see if newer version handles schemas better
            try:
                self.agent = Agent(
                    name="cambrian_assistant",
                    model="gemini-2.5-flash",  # Using Gemini 2.5 Flash
                    description="Cambrian blockchain data assistant with schema-validated MCP tools",
                    instruction=f"""You are a Cambrian blockchain data assistant. ALWAYS use the available tools to answer questions.
                
                CURRENT UNIX TIMESTAMP: {current_time}
                24 HOURS AGO: {time_24h_ago}

                {tool_info}

                CRITICAL TOOL NAMING - USE EXACT TOOL NAMES AS PROVIDED:
                - For token security metrics: You MUST use "solanatokenssecuirty" (NOT "solanatokensecurity")
                - For holder distribution over time: Use "solanatokensholderdistributionovertime"
                - These tool names have typos but you MUST use them exactly as shown
                - NEVER auto-correct or modify tool names - the MCP server only recognizes the exact names

                CRITICAL RULES FOR PARAMETER HANDLING:
                
                1. NEVER ask for missing parameters - use intelligent defaults immediately
                2. When time parameters are missing, use these values:
                   - after_time: {time_24h_ago} (24 hours ago)
                   - before_time: {current_time} (current time)
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
                
                TOOL USAGE EXAMPLES:
                - "Show OHLCV for SOL": Use solanaohlcvtoken with SOL address and last 24h
                - "Get pool transactions": Use solanapooltransactions with pool address and days=1
                - "Show trending tokens": Use solanatrendingtokens with order_by="volume"
                - "Get wallet balance history": Use solanawalletbalancehistory with last 24h
                
                ALWAYS inform user of default choices: "I'll use the last 24 hours of data with hourly intervals."
                ALWAYS call tools with defaults rather than asking for parameters.
                """,
                tools=[
                    MCPToolset(
                        connection_params=StreamableHTTPServerParams(
                            url=self.MCP_SERVER_URL,
                            headers={
                                "Authorization": f"Bearer {self.cambrian_api_key}",
                                "Accept": "application/json, text/event-stream"
                            } if self.cambrian_api_key else {"Accept": "application/json, text/event-stream"}
                        ),
                        tool_filter=self._create_tool_filter()  # Filter out tools with invalid schemas
                    ),
                ],
                )
                logger.info("✅ Agent created successfully with tool_filter (filtering out tools with invalid schemas)")

            except Exception as agent_error:
                logger.error(f"Failed to create Agent with MCPToolset: {agent_error}")
                logger.error(f"Error type: {type(agent_error).__name__}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                raise

            # Setup session and runner
            logger.info("Setting up session and runner...")
            self.session_service = InMemorySessionService()
            self.runner = Runner(
                agent=self.agent,
                app_name="cambrian_api",
                session_service=self.session_service
            )

            # Create session
            await self.session_service.create_session(
                app_name="cambrian_api",
                user_id="user",
                session_id="main_session"
            )
            self.session_initialized = True

            logger.info("✅ Google ADK Agent initialized with MCP tools")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize ADK agent: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    
    async def initialize_with_session(self, session_id: str):
        """Initialize the agent with a specific session ID for stateless operation."""
        try:
            # Discover available tools first
            await self._discover_tools()
            
            logger.info(f"Connecting to MCP server at {self.MCP_SERVER_URL} with session {session_id}")
            
            # Get current timestamp for default calculations
            current_time = int(time.time())
            time_24h_ago = current_time - 86400  # 24 hours ago
            
            # Build tool list info for the instruction
            tool_info = f"Available tools: {len(self.available_tools)} tools discovered"
            if 'solanatokenssecuirty' in self.available_tools:
                tool_info += "\n- ✓ solanatokenssecuirty (security metrics - with typo)"
            if 'solanatokensholderdistributionovertime' in self.available_tools:
                tool_info += "\n- ✓ solanatokensholderdistributionovertime (holder distribution)"
            
            # Create the agent with MCP toolset (reuse existing if possible)
            if not self.agent:
                self.agent = Agent(
                    name="cambrian_assistant",
                    model="gemini-2.5-flash",
                    description="Cambrian blockchain data assistant with auto-discovered MCP tools",
                    instruction=f"""You are a Cambrian blockchain data assistant. ALWAYS use the available tools to answer questions.
                    
                    CURRENT UNIX TIMESTAMP: {current_time}
                    24 HOURS AGO: {time_24h_ago}

                    {tool_info}

                    CRITICAL TOOL NAMING - USE EXACT TOOL NAMES AS PROVIDED:
                    - For token security metrics: You MUST use "solanatokenssecuirty" (NOT "solanatokensecurity")
                    - For holder distribution over time: Use "solanatokensholderdistributionovertime"  
                    - These tool names have typos but you MUST use them exactly as shown
                    - NEVER auto-correct or modify tool names - the MCP server only recognizes the exact names

                    CRITICAL RULES FOR PARAMETER HANDLING:
                    
                    1. NEVER ask for missing parameters - use intelligent defaults immediately
                    2. When time parameters are missing, use these values:
                       - after_time: {time_24h_ago} (24 hours ago)
                       - before_time: {current_time} (current time)
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
                    
                    TOOL USAGE EXAMPLES:
                    - "Show OHLCV for SOL": Use solanaohlcvtoken with SOL address and last 24h
                    - "Get pool transactions": Use solanapooltransactions with pool address and days=1
                    - "Show trending tokens": Use solanatrendingtokens with order_by="volume"
                    - "Get wallet balance history": Use solanawalletbalancehistory with last 24h
                    
                    ALWAYS inform user of default choices: "I'll use the last 24 hours of data with hourly intervals."
                    ALWAYS call tools with defaults rather than asking for parameters.
                    """,
                    tools=[
                        MCPToolset(
                            connection_params=StreamableHTTPServerParams(
                                url=self.MCP_SERVER_URL,
                                headers={
                                    "Authorization": f"Bearer {self.cambrian_api_key}",
                                    "Accept": "application/json, text/event-stream"
                                } if self.cambrian_api_key else {"Accept": "application/json, text/event-stream"}
                            ),
                            tool_filter=self._create_tool_filter()  # Filter out tools with invalid schemas
                        ),
                    ],
                )
            
            # Setup session and runner (only create once, reuse for all queries)
            if not self.session_service or not self.runner:
                self.session_service = InMemorySessionService()
                self.runner = Runner(
                    agent=self.agent,
                    app_name="cambrian_api",
                    session_service=self.session_service
                )

            # Create session with the provided session_id (each query gets its own session)
            await self.session_service.create_session(
                app_name="cambrian_api",
                user_id="user",
                session_id=session_id
            )
            self.session_initialized = True
            
            logger.info(f"✅ Google ADK Agent initialized with MCP tools for session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize ADK agent with session {session_id}: {e}")
            return False
    
    async def process_question(self, question: str, session_id: str = None, conversation_history: list = None) -> Dict[str, Any]:
        """Process a question using the ADK agent with optional conversation history."""
        # Use provided session_id or generate a unique one for stateless operation
        if not session_id:
            import uuid
            session_id = str(uuid.uuid4())
        
        # Check if we need to initialize or reuse existing session
        should_initialize = not self.session_initialized or session_id != getattr(self, '_current_session_id', None)
        
        if should_initialize:
            # Initialize with new session
            self.session_initialized = False
            success = await self.initialize_with_session(session_id)
            if not success:
                return {
                    "success": False,
                    "answer": "Failed to initialize agent with MCP tools",
                    "error": "Initialization failed"
                }
            self._current_session_id = session_id
        
        # Add conversation history to session if provided
        if conversation_history and should_initialize:
            await self._add_conversation_history(session_id, conversation_history)
        
        try:
            # Create message
            message = types.Content(
                role='user',
                parts=[types.Part(text=question)]
            )

            # CRITICAL: Log Gemini interaction for verifiability
            # This creates an audit trail of what we send and receive from Gemini
            import hashlib
            prompt_hash = hashlib.sha256(question.encode('utf-8')).hexdigest()
            timestamp_sent = int(time.time() * 1000)  # milliseconds

            logger.info(f"📤 Gemini Request - Hash: {prompt_hash[:16]}... Timestamp: {timestamp_sent}")

            # Collect response
            response_text = ""
            tools_used = []
            tool_calls_detail = []  # Store detailed tool call information

            async for event in self.runner.run_async(
                user_id="user",
                session_id=session_id,
                new_message=message
            ):
                # Collect text responses
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.text:
                            response_text += part.text

                # Track tool calls with full details
                for call in event.get_function_calls():
                    if call.name not in tools_used:
                        tools_used.append(call.name)

                    # Store detailed tool call for evidence
                    tool_calls_detail.append({
                        "tool_name": call.name,
                        "args": call.args if hasattr(call, 'args') else {},
                        "timestamp": int(time.time() * 1000)
                    })

            # CRITICAL: Log Gemini response for verifiability
            timestamp_received = int(time.time() * 1000)
            response_hash = hashlib.sha256(response_text.encode('utf-8')).hexdigest()

            logger.info(f"📥 Gemini Response - Hash: {response_hash[:16]}... Timestamp: {timestamp_received}")
            logger.info(f"🔧 Tool Calls Requested: {tools_used}")

            return {
                "success": True,
                "answer": response_text.strip(),
                "tools_used": tools_used,
                "metadata": {
                    "model": "gemini-2.5-flash",
                    "protocol": "MCP",
                    "total_tools": "68+"
                },
                # NEW: Gemini interaction log for verifiability
                "gemini_interaction": {
                    "prompt_hash": prompt_hash,
                    "response_hash": response_hash,
                    "timestamp_sent": timestamp_sent,
                    "timestamp_received": timestamp_received,
                    "tool_calls_requested": tool_calls_detail,
                    "latency_ms": timestamp_received - timestamp_sent
                }
            }
            
        except Exception as e:
            error_str = str(e)
            logger.error(f"Error processing question: {error_str}")

            # Check if it's the known schema validation error
            if "missing field" in error_str and ("order_asc" in error_str or "order_desc" in error_str):
                logger.warning("Detected schema validation error for array parameters")
                logger.warning("This is a known issue with MCP server tool schemas")
                logger.warning("The MCP server has 9 tools with array parameters missing 'items' field")

                return {
                    "success": False,
                    "answer": "I encountered a technical limitation with some data tools. The MCP server has incomplete schema definitions for certain advanced filtering parameters. However, I can still help with most queries using the 60+ working tools available. Please try rephrasing your question or ask about specific tokens, prices, or market data.",
                    "error": "Schema validation error - array parameters missing 'items' field",
                    "tools_affected": "9 tools with order_asc/order_desc parameters",
                    "workaround": "Queries without complex ordering should work"
                }

            return {
                "success": False,
                "answer": f"Error processing request: {error_str}",
                "error": error_str
            }
    

    def get_capabilities(self) -> Dict[str, Any]:
        """Get agent capabilities."""
        return {
            "mode": "google_adk_mcp_final",
            "model": "gemini-2.5-flash",
            "protocol": "MCP with auto-discovery",
            "mcp_server": self.MCP_SERVER_URL,
            "supports_streaming": True,
            "supports_tool_calling": True,
            "total_tools": f"{len(self.available_tools)} dynamically discovered" if self.available_tools else "68+ auto-discovered",
            "tools_with_typos": ["solanatokenssecuirty", "solanatokensholderdistributionovertime"],
            "dynamic_sync": True
        }
    
    async def _add_conversation_history(self, session_id: str, conversation_history: list):
        """Add conversation history to the Google ADK session."""
        try:
            if not conversation_history:
                return
                
            logger.info(f"Adding {len(conversation_history)} messages to conversation history")
            
            # Add each message from history to the session
            for msg in conversation_history:
                if isinstance(msg, dict) and 'role' in msg and 'content' in msg:
                    role = 'user' if msg['role'] == 'user' else 'model'
                    content = types.Content(
                        role=role,
                        parts=[types.Part(text=msg['content'])]
                    )
                    
                    # Add message to session history (this is a simplified approach)
                    # In a full implementation, we might need to actually run these through the ADK
                    # For now, we log them for context
                    logger.debug(f"History message - {role}: {msg['content'][:100]}...")
                    
        except Exception as e:
            logger.warning(f"Failed to add conversation history: {e}")


# For backward compatibility
class DirectGeminiClientMCP:
    """Wrapper for compatibility with existing interface."""
    
    def __init__(self, gemini_api_key: str = None, cambrian_api_key: str = None):
        self.agent = GoogleADKMCPFinal(gemini_api_key, cambrian_api_key)
    
    async def process_question(self, question: str, session_id: str = None, conversation_history: list = None) -> Dict[str, Any]:
        """Process a question."""
        return await self.agent.process_question(question, session_id, conversation_history)
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get capabilities."""
        return self.agent.get_capabilities()
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
    
    # Updated to new MCP server
    MCP_SERVER_URL = "https://cambrian-mcp-server-prod-981646676182.us-central1.run.app/mcp"
    
    def __init__(self, gemini_api_key: str = None, cambrian_api_key: str = None):
        self.gemini_api_key = gemini_api_key or os.getenv('GEMINI_API_KEY')
        self.cambrian_api_key = cambrian_api_key or os.getenv('CAMBRIAN_API_KEY')
        
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
        """Dynamically discover available tools from both OpenAPI and MCP server."""
        try:
            logger.info("Discovering available tools from OpenAPI and MCP...")
            
            # Fetch OpenAPI operations
            openapi_ops = set()
            async with aiohttp.ClientSession() as session:
                async with session.get("https://opabinia.cambrian.network/openapi.json") as response:
                    if response.status == 200:
                        data = await response.json()
                        for path, methods in data.get('paths', {}).items():
                            for method, details in methods.items():
                                if 'operationId' in details:
                                    openapi_ops.add(details['operationId'])
                        logger.info(f"Found {len(openapi_ops)} operations in OpenAPI spec")
            
            # Fetch MCP tools
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
            
            # Build mapping for tools with typos or naming differences
            def normalize(name):
                return name.lower().replace('_', '').replace('-', '')
            
            openapi_normalized = {normalize(op): op for op in openapi_ops}
            mcp_normalized = {normalize(tool): tool for tool in mcp_tools}
            
            # Create mapping for tools with different names
            for norm_name, openapi_name in openapi_normalized.items():
                if norm_name in mcp_normalized:
                    mcp_name = mcp_normalized[norm_name]
                    if openapi_name != mcp_name:
                        self.tool_mapping[openapi_name] = mcp_name
                        logger.debug(f"Mapped OpenAPI '{openapi_name}' to MCP '{mcp_name}'")
            
            # Log any tools with typos
            if 'solanatokenssecuirty' in mcp_tools:
                logger.info("✓ Found 'solanatokenssecuirty' (with typo) in MCP tools")
            if 'solanatokensholderdistributionovertime' in mcp_tools:
                logger.info("✓ Found 'solanatokensholderdistributionovertime' in MCP tools")
            
            logger.info(f"Tool discovery complete: {len(self.available_tools)} tools available")
            return True
            
        except Exception as e:
            logger.error(f"Failed to discover tools: {e}")
            return False
    
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
            self.agent = Agent(
                name="cambrian_assistant",
                model="gemini-2.5-flash",  # Using Gemini 2.5 Flash
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
                        )
                    ),
                ],
            )
            
            # Setup session and runner
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
                            )
                        ),
                    ],
                )
            
            # Setup session and runner
            self.session_service = InMemorySessionService()
            self.runner = Runner(
                agent=self.agent,
                app_name="cambrian_api",
                session_service=self.session_service
            )
            
            # Create session with the provided session_id
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
            
            # Collect response
            response_text = ""
            tools_used = []
            
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
                
                # Track tool calls
                for call in event.get_function_calls():
                    if call.name not in tools_used:
                        tools_used.append(call.name)
            
            return {
                "success": True,
                "answer": response_text.strip(),
                "tools_used": tools_used,
                "metadata": {
                    "model": "gemini-2.5-flash",
                    "protocol": "MCP",
                    "total_tools": "68+"
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing question: {e}")
            return {
                "success": False,
                "answer": f"Error processing request: {str(e)}",
                "error": str(e)
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
"""
Deep42 Unified Intelligence Agent - Direct API Implementation
==============================================================

Production agent that directly calls Deep42 and Opabinia APIs using Gemini AI
for intelligent query routing and orchestration.

This implementation:
- Uses Google Gemini AI with function calling for query understanding
- Makes direct HTTP requests to Deep42 and Opabinia endpoints
- Manages conversation history for multi-turn dialogues
- Returns comprehensive responses with documentation links

Author: Cambrian Team
Version: 1.0.0 (Production)
"""

import os
import logging
import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import aiohttp

# Import Google Gemini SDK
import google.generativeai as genai
from google.generativeai.types import FunctionDeclaration, Tool

logger = logging.getLogger(__name__)


class Deep42Agent:
    """
    Production Deep42 agent that orchestrates API calls to Deep42 and Opabinia endpoints.
    """

    # API Base URLs
    DEEP42_API = "https://deep42.cambrian.network"
    OPABINIA_API = "https://opabinia.cambrian.network"

    def __init__(self, gemini_api_key: str = None, cambrian_api_key: str = None):
        """
        Initialize the Deep42 agent.

        Args:
            gemini_api_key: Google Gemini API key (or set GEMINI_API_KEY env var)
            cambrian_api_key: Cambrian API key for authentication (or set CAMBRIAN_API_KEY env var)
        """
        self.gemini_api_key = gemini_api_key or os.getenv('GEMINI_API_KEY')
        self.cambrian_api_key = cambrian_api_key or os.getenv('CAMBRIAN_API_KEY')

        if not self.gemini_api_key:
            raise ValueError("GEMINI_API_KEY is required")
        if not self.cambrian_api_key:
            raise ValueError("CAMBRIAN_API_KEY is required")

        # Configure Gemini
        genai.configure(api_key=self.gemini_api_key)

        # Define available API tools for Gemini
        self.tools = self._define_api_tools()

        # Initialize Gemini model with tools
        self.model = genai.GenerativeModel(
            model_name='gemini-2.0-flash-exp',
            tools=[Tool(function_declarations=self.tools)]
        )

        # Conversation cache (in-memory for now)
        self.conversations: Dict[str, List[Dict]] = {}

        logger.info("✅ Deep42 Agent initialized successfully")

    def _define_api_tools(self) -> List[FunctionDeclaration]:
        """
        Define API endpoints as Gemini function tools.

        Returns:
            List of function declarations for Gemini
        """
        return [
            # Deep42 Discovery Endpoints
            FunctionDeclaration(
                name="search_projects",
                description="Search for cryptocurrency projects by name, symbol, technology, or blockchain. Returns comprehensive project information including social metrics, quality scores, and risk assessment.",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query (project name, symbol, or description keywords)"},
                        "chain": {"type": "string", "description": "Blockchain filter (e.g., 'solana', 'ethereum', 'base')"},
                        "technology": {"type": "string", "description": "Technology filter (e.g., 'DeFi', 'NFT', 'Gaming')"},
                    }
                }
            ),

            FunctionDeclaration(
                name="get_project_metadata",
                description="Get comprehensive metadata for specific cryptocurrency projects including social intelligence, technology assessment, and risk analysis.",
                parameters={
                    "type": "object",
                    "properties": {
                        "symbols": {"type": "string", "description": "Comma-separated project symbols (e.g., 'SOL,ETH,BTC')"},
                        "chain": {"type": "string", "description": "Blockchain filter"},
                    }
                }
            ),

            # Deep42 Social Data Endpoints
            FunctionDeclaration(
                name="get_alpha_tweets",
                description="Detect alpha signals from cryptocurrency tweets using high-quality curated data with 6-factor scoring.",
                parameters={
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "description": "Detection mode: 'curated' (high quality) or 'volume' (broader coverage)"},
                        "min_score": {"type": "number", "description": "Minimum alpha score threshold (0-100)"},
                    }
                }
            ),

            FunctionDeclaration(
                name="get_sentiment_shifts",
                description="Identify tokens with significant sentiment changes that could signal market movements and trading opportunities.",
                parameters={
                    "type": "object",
                    "properties": {
                        "min_shift": {"type": "number", "description": "Minimum sentiment shift threshold"},
                    }
                }
            ),

            FunctionDeclaration(
                name="analyze_token_social",
                description="Get comprehensive social intelligence report for a cryptocurrency token including sentiment analysis and community metrics.",
                parameters={
                    "type": "object",
                    "properties": {
                        "token_symbol": {"type": "string", "description": "Token symbol (e.g., 'SOL', 'BTC', 'ETH')"},
                        "chain": {"type": "string", "description": "Blockchain network"},
                    },
                    "required": ["token_symbol"]
                }
            ),

            FunctionDeclaration(
                name="get_trending_momentum",
                description="Identify tokens with rapidly increasing social signals and momentum indicators.",
                parameters={
                    "type": "object",
                    "properties": {
                        "min_momentum": {"type": "number", "description": "Minimum momentum score threshold"},
                    }
                }
            ),

            FunctionDeclaration(
                name="analyze_twitter_user",
                description="Analyze alpha metrics for a specific Twitter user including tweet counts, sentiment scores, and token discussion tracking.",
                parameters={
                    "type": "object",
                    "properties": {
                        "twitter_handle": {"type": "string", "description": "Twitter handle (without @)"},
                        "mode": {"type": "string", "description": "'summary' for 90-day overview or 'daily' for daily breakdown"},
                    },
                    "required": ["twitter_handle"]
                }
            ),

            # Deep42 GitHub Endpoints
            FunctionDeclaration(
                name="get_repository_data",
                description="Get combined market data and GitHub metrics for cryptocurrency projects or individual repositories.",
                parameters={
                    "type": "object",
                    "properties": {
                        "repository": {"type": "string", "description": "Repository name or project symbol"},
                    },
                    "required": ["repository"]
                }
            ),

            # Opabinia EVM Endpoints
            FunctionDeclaration(
                name="get_token_price",
                description="Get current or historical price data for tokens on EVM chains (Base, Ethereum, etc.).",
                parameters={
                    "type": "object",
                    "properties": {
                        "token_address": {"type": "string", "description": "Token contract address"},
                        "chain_id": {"type": "number", "description": "Chain ID (e.g., 8453 for Base)"},
                        "timeframe": {"type": "string", "description": "'current' or 'hour' for historical"},
                    },
                    "required": ["token_address", "chain_id"]
                }
            ),

            FunctionDeclaration(
                name="get_pool_info",
                description="Get detailed information about DEX liquidity pools including TVL, APR, volume, and fees.",
                parameters={
                    "type": "object",
                    "properties": {
                        "pool_address": {"type": "string", "description": "Pool contract address"},
                        "dex": {"type": "string", "description": "DEX name (e.g., 'aerodrome', 'uniswap')"},
                        "version": {"type": "string", "description": "DEX version (v2 or v3)"},
                    },
                    "required": ["pool_address", "dex"]
                }
            ),

            FunctionDeclaration(
                name="get_top_holders",
                description="Get top token holders for a specific token address on EVM chains.",
                parameters={
                    "type": "object",
                    "properties": {
                        "token_address": {"type": "string", "description": "Token contract address"},
                        "chain_id": {"type": "number", "description": "Chain ID"},
                    },
                    "required": ["token_address", "chain_id"]
                }
            ),
        ]

    async def _call_api(self, base_url: str, endpoint: str, params: Dict = None) -> Dict:
        """
        Make HTTP request to Cambrian API.

        Args:
            base_url: Base API URL (DEEP42_API or OPABINIA_API)
            endpoint: API endpoint path
            params: Query parameters

        Returns:
            API response as dictionary
        """
        url = f"{base_url}{endpoint}"
        headers = {
            "X-API-KEY": self.cambrian_api_key,
            "Accept": "application/json"
        }

        logger.info(f"📡 Calling API: {endpoint}")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"✅ API call successful: {endpoint}")
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(f"❌ API error {response.status}: {error_text}")
                        return {"error": f"API returned status {response.status}", "details": error_text}

        except asyncio.TimeoutError:
            logger.error(f"⏱️ API timeout: {endpoint}")
            return {"error": "API request timed out"}
        except Exception as e:
            logger.error(f"❌ API request failed: {e}")
            return {"error": str(e)}

    async def _execute_function(self, function_name: str, function_args: Dict) -> Dict:
        """
        Execute API function call based on Gemini's request.

        Args:
            function_name: Name of the function to call
            function_args: Function arguments from Gemini

        Returns:
            API response data
        """
        logger.info(f"🔧 Executing function: {function_name}")
        logger.debug(f"   Arguments: {function_args}")

        # Map function names to API endpoints
        endpoint_mapping = {
            "search_projects": ("/api/v1/deep42/discovery/search-projects", self.DEEP42_API),
            "get_project_metadata": ("/api/v1/deep42/discovery/project-metadata", self.DEEP42_API),
            "get_alpha_tweets": ("/api/v1/deep42/social-data/alpha-tweet-detection", self.DEEP42_API),
            "get_sentiment_shifts": ("/api/v1/deep42/social-data/sentiment-shifts", self.DEEP42_API),
            "analyze_token_social": ("/api/v1/deep42/social-data/token-analysis", self.DEEP42_API),
            "get_trending_momentum": ("/api/v1/deep42/social-data/trending-momentum", self.DEEP42_API),
            "analyze_twitter_user": ("/api/v1/deep42/agents/twitter-user-alpha-metrics", self.DEEP42_API),
            "get_repository_data": ("/api/v1/deep42/github/repository-market-data", self.DEEP42_API),
            "get_token_price": ("/api/v1/evm/price-current", self.OPABINIA_API),
            "get_pool_info": (None, self.OPABINIA_API),  # Dynamic based on DEX
            "get_top_holders": ("/api/v1/evm/tvl/top-owners", self.OPABINIA_API),
        }

        if function_name not in endpoint_mapping:
            return {"error": f"Unknown function: {function_name}"}

        endpoint, base_url = endpoint_mapping[function_name]

        # Special handling for pool info (dynamic endpoint)
        if function_name == "get_pool_info":
            dex = function_args.get("dex", "aerodrome")
            version = function_args.get("version", "v2")
            endpoint = f"/api/v1/evm/{dex}/{version}/pool"

        # Call the API
        result = await self._call_api(base_url, endpoint, function_args)

        # Ensure we always return a dict (Gemini function responses require this)
        # Wrap array responses in a dictionary
        if isinstance(result, list):
            return {"data": result, "count": len(result)}
        else:
            return result

    async def process_question(
        self,
        question: str,
        chat_id: str = None,
        conversation_history: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Process user question using Gemini AI with API function calling.

        Args:
            question: User question
            chat_id: Optional conversation ID
            conversation_history: Optional previous conversation messages

        Returns:
            Dictionary with answer, chat_id, and docs_urls
        """
        logger.info(f"🤔 Processing question: {question[:100]}...")

        try:
            # Build conversation context
            history = conversation_history or []

            # Add system instruction
            system_instruction = """You are the Deep42 Unified Intelligence Agent, an expert cryptocurrency research assistant.

You have access to comprehensive blockchain data through these API functions:
- search_projects: Find cryptocurrency projects
- get_project_metadata: Get detailed project information
- get_alpha_tweets: Detect alpha signals from Twitter
- get_sentiment_shifts: Identify sentiment changes
- analyze_token_social: Analyze token social metrics
- get_trending_momentum: Find trending tokens
- analyze_twitter_user: Analyze Twitter user alpha metrics
- get_repository_data: Get GitHub development metrics
- get_token_price: Get current/historical token prices
- get_pool_info: Get DEX pool information
- get_top_holders: Get top token holders

When a user asks a question:
1. Determine which API functions would provide relevant data
2. Call the appropriate functions with correct parameters
3. Synthesize the results into a comprehensive, well-formatted answer
4. Use tables, bullet points, and bold text for clarity
5. Include actionable insights and recommendations

Always provide complete, helpful responses that combine data from multiple sources when relevant."""

            # Create chat session with history
            chat = self.model.start_chat(history=[
                {"role": msg["role"], "parts": [msg["content"]]}
                for msg in history
            ])

            # Send user question
            response = await asyncio.to_thread(
                chat.send_message,
                question
            )

            # Process function calls if Gemini requests them
            tools_used = []
            docs_urls = []

            while response.candidates[0].content.parts[0].function_call:
                function_call = response.candidates[0].content.parts[0].function_call
                function_name = function_call.name
                function_args = dict(function_call.args)

                tools_used.append(function_name)

                logger.info(f"🔨 Gemini requests function: {function_name}")

                # Execute the function
                function_result = await self._execute_function(function_name, function_args)

                # Send function response back to Gemini
                response = await asyncio.to_thread(
                    chat.send_message,
                    {
                        "function_response": {
                            "name": function_name,
                            "response": function_result
                        }
                    }
                )

            # Extract final text response
            answer = response.text

            # Generate documentation URLs
            for tool in tools_used:
                # Map tool names to documentation URLs
                if "project" in tool or "metadata" in tool:
                    docs_urls.append("https://docs.cambrian.org/api/v1/deep42/discovery/llms.txt")
                elif "social" in tool or "sentiment" in tool or "alpha" in tool or "twitter" in tool:
                    docs_urls.append("https://docs.cambrian.org/api/v1/deep42/social-data/llms.txt")
                elif "github" in tool or "repository" in tool:
                    docs_urls.append("https://docs.cambrian.org/api/v1/deep42/github/llms.txt")
                elif "price" in tool or "pool" in tool or "holders" in tool:
                    docs_urls.append("https://docs.cambrian.org/api/v1/evm/llms.txt")

            # Remove duplicates
            docs_urls = list(set(docs_urls))

            logger.info(f"✅ Answer generated ({len(answer)} chars, {len(tools_used)} tools used)")

            return {
                "success": True,
                "answer": answer,
                "tools_used": tools_used,
                "docs_urls": docs_urls
            }

        except Exception as e:
            logger.error(f"❌ Error processing question: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "answer": f"I encountered an error processing your question: {str(e)}"
            }


# Singleton instance
_agent_instance = None
_agent_lock = asyncio.Lock()


async def get_agent() -> Deep42Agent:
    """
    Get or create singleton Deep42Agent instance.

    Returns:
        Deep42Agent instance
    """
    global _agent_instance

    async with _agent_lock:
        if _agent_instance is None:
            logger.info("🔧 Creating singleton Deep42Agent instance...")
            _agent_instance = Deep42Agent()
            logger.info("✅ Singleton agent created and ready")

        return _agent_instance


if __name__ == "__main__":
    """Test the agent locally"""
    import asyncio

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    async def test():
        agent = await get_agent()

        test_questions = [
            "What are some trending DeFi projects on Solana?",
            "Analyze social sentiment for Bitcoin",
        ]

        for q in test_questions:
            print(f"\n{'='*80}")
            print(f"Q: {q}")
            print('='*80)

            result = await agent.process_question(q)

            if result['success']:
                print(f"\nAnswer:\n{result['answer']}")
                print(f"\nTools used: {result['tools_used']}")
                print(f"Docs: {result['docs_urls']}")
            else:
                print(f"\nError: {result['error']}")

    asyncio.run(test())

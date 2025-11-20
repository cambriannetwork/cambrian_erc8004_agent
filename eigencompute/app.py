"""
Deep42 Unified Intelligence Agent - EigenCompute TEE Deployment
================================================================

FastAPI application that exposes the Deep42 Agent in a Trusted Execution Environment.

Endpoint: GET /api/v1/deep42/agents/deep42
Parameters:
  - question (required): User query
  - continue_chat_id (optional): UUID for conversation continuity

Response:
  {
    "answer": "...",
    "chat_id": "uuid",
    "docs_urls": [...]
  }

Author: Cambrian Team
Version: 1.0.0 (Production)
"""

import os
import logging
import uuid
import asyncio
from typing import Optional, Dict, List
from datetime import datetime

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import Deep42 agent
from deep42_agent import Deep42Agent, get_agent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Deep42 Unified Intelligence Agent",
    description="Comprehensive cryptocurrency intelligence combining blockchain data, developer activity, social sentiment, and research capabilities.",
    version="1.0.0"
)

# In-memory conversation storage
# Format: {chat_id: [{'role': 'user'|'assistant', 'content': str}]}
conversation_store: Dict[str, List[Dict[str, str]]] = {}

# Lock for thread-safe conversation access
conversation_lock = asyncio.Lock()


class AgentResponse(BaseModel):
    """Response model for agent queries"""
    answer: str = Field(description="The agent's response with relevant data and analysis")
    chat_id: str = Field(description="Unique conversation identifier for follow-up questions")
    docs_urls: List[str] = Field(default=[], description="URLs to relevant documentation")


@app.on_event("startup")
async def startup_event():
    """Initialize the agent on startup"""
    logger.info("🚀 Starting Deep42 Unified Intelligence Agent in TEE...")

    # Verify environment variables
    gemini_key = os.getenv('GEMINI_API_KEY')
    cambrian_key = os.getenv('CAMBRIAN_API_KEY')

    if not gemini_key:
        logger.error("❌ GEMINI_API_KEY not set")
        raise RuntimeError("GEMINI_API_KEY environment variable is required")

    if not cambrian_key:
        logger.error("❌ CAMBRIAN_API_KEY not set")
        raise RuntimeError("CAMBRIAN_API_KEY environment variable is required")

    logger.info("✅ Environment validated - agent ready for requests")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "deep42-unified-agent",
        "environment": "eigencompute-tee",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/capabilities")
async def get_capabilities():
    """Get agent capabilities"""
    return {
        "agent_name": "Deep42 Unified Intelligence Agent",
        "version": "1.0.0",
        "model": "gemini-2.0-flash-exp",
        "capabilities": [
            "Blockchain data analysis (Solana, Base, EVM chains)",
            "Token analytics (prices, volume, liquidity, security)",
            "DEX pool metrics (TVL, APR, swap volumes)",
            "Developer intelligence (GitHub repos, commits)",
            "Social sentiment analysis and alpha signal detection",
            "Market research and competitive analysis"
        ],
        "deployment": {
            "environment": "EigenCompute TEE",
            "runtime": "Intel TDX",
            "isolation": "Hardware-level"
        },
        "api_endpoints": {
            "deep42": "https://deep42.cambrian.network",
            "opabinia": "https://opabinia.cambrian.network"
        }
    }


@app.get("/api/v1/deep42/agents/deep42", response_model=AgentResponse)
async def execute_deep42_agent(
    question: str = Query(
        ...,
        description="Question about blockchain data, developer activity, social sentiment, or market research",
        example="What are the top trending tokens on Solana?",
        max_length=10000
    ),
    continue_chat_id: Optional[str] = Query(
        None,
        description="Optional conversation ID for multi-turn dialogue",
        regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
) -> AgentResponse:
    """
    Execute Deep42 Unified Intelligence Agent query.

    Provides comprehensive cryptocurrency intelligence by combining:
    - Blockchain data (Solana, Base, EVM)
    - Token analytics (prices, volume, liquidity)
    - DEX pools (TVL, APR, volumes)
    - Developer activity (GitHub metrics)
    - Social sentiment (Twitter alpha signals)
    - Market research and analysis

    Supports multi-turn conversations via chat_id.
    """
    request_start = datetime.utcnow()
    logger.info(f"📥 Received query: {question[:100]}...")

    try:
        # Get or create chat session
        chat_id = continue_chat_id if continue_chat_id else str(uuid.uuid4())

        # Retrieve conversation history
        async with conversation_lock:
            conversation_history = conversation_store.get(chat_id, [])

            # Check if continuing non-existent conversation
            if continue_chat_id and not conversation_history:
                logger.warning(f"⚠️  Conversation not found: {continue_chat_id}")
                raise HTTPException(
                    status_code=404,
                    detail=f"Conversation {continue_chat_id} not found. Start a new conversation."
                )

        logger.info(f"💬 Chat session: {chat_id} ({len(conversation_history)} messages)")

        # Get agent
        agent = await get_agent()

        # Process question
        result = await agent.process_question(
            question=question,
            chat_id=chat_id,
            conversation_history=conversation_history
        )

        if not result.get('success', False):
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"❌ Agent execution failed: {error_msg}")
            raise HTTPException(status_code=500, detail=f"Agent error: {error_msg}")

        answer = result.get('answer', '')
        docs_urls = result.get('docs_urls', [])

        # Store conversation
        async with conversation_lock:
            if chat_id not in conversation_store:
                conversation_store[chat_id] = []

            # Add user question
            conversation_store[chat_id].append({
                'role': 'user',
                'content': question
            })

            # Add assistant response
            conversation_store[chat_id].append({
                'role': 'assistant',
                'content': answer
            })

            # Limit history to last 20 messages (10 turns)
            if len(conversation_store[chat_id]) > 20:
                conversation_store[chat_id] = conversation_store[chat_id][-20:]

        # Log metrics
        duration_ms = int((datetime.utcnow() - request_start).total_seconds() * 1000)
        logger.info(f"✅ Query completed in {duration_ms}ms")
        logger.info(f"   Answer: {len(answer)} chars")
        logger.info(f"   Tools: {len(result.get('tools_used', []))}")

        return AgentResponse(
            answer=answer,
            chat_id=chat_id,
            docs_urls=docs_urls
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": type(exc).__name__
        }
    )


if __name__ == "__main__":
    # Get port from environment
    port = int(os.getenv("PORT", "3000"))

    logger.info(f"🚀 Starting Deep42 Agent on port {port}...")
    logger.info(f"   Environment: EigenCompute TEE")
    logger.info(f"   APIs: Deep42 + Opabinia")

    # Run server (bind to 0.0.0.0 for TEE accessibility)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )

#!/usr/bin/env python3
"""
Flask server wrapper for Google ADK + MCP integration
Provides HTTP API for Node.js agent to call Python Google ADK
"""

# CRITICAL: Early error logging BEFORE any imports
import sys
sys.stderr.write("=== Python server.py starting ===\n")
sys.stderr.write(f"=== Python version: {sys.version} ===\n")
sys.stderr.write(f"=== sys.path: {sys.path} ===\n")
sys.stderr.flush()

try:
    import os
    sys.stderr.write("✅ os imported\n")
    import logging
    sys.stderr.write("✅ logging imported\n")
    import asyncio
    sys.stderr.write("✅ asyncio imported\n")
    from flask import Flask, request, jsonify
    sys.stderr.write("✅ flask imported\n")
    from flask_cors import CORS
    sys.stderr.write("✅ flask_cors imported\n")

    # Add current directory to path for imports
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from google_adk_mcp import GoogleADKMCPFinal
    sys.stderr.write("✅ google_adk_mcp imported\n")

    sys.stderr.write("=== All imports successful ===\n")
    sys.stderr.flush()

except Exception as e:
    sys.stderr.write(f"=== IMPORT ERROR: {e} ===\n")
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.stderr.flush()
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Enable CORS for production UI and local development
CORS(app,
     origins=[
         'https://erc8004-ui.rickycambrian.org',
         'http://localhost:5173',
         'http://localhost:3000'
     ],
     allow_headers=['Content-Type', 'Authorization', 'X-Cambrian-Api-Key', 'X-API-Key'],
     supports_credentials=True,
     max_age=86400)

# Global agent instance
agent = None

def get_agent():
    """Get or create Google ADK agent instance."""
    global agent
    if agent is None:
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        cambrian_api_key = os.getenv('SERVER_CAMBRIAN_API_KEY') or os.getenv('CAMBRIAN_API_KEY')

        if not gemini_api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")

        logger.info("Creating Google ADK + MCP agent...")
        agent = GoogleADKMCPFinal(
            gemini_api_key=gemini_api_key,
            cambrian_api_key=cambrian_api_key
        )

        # Initialize agent in event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success = loop.run_until_complete(agent.initialize())

        if not success:
            raise RuntimeError("Failed to initialize Google ADK agent")

        logger.info("✅ Google ADK + MCP agent initialized successfully")

    return agent

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    try:
        agent_instance = get_agent()
        return jsonify({
            "status": "healthy",
            "agent": "google_adk_mcp",
            "initialized": agent_instance is not None
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "error_type": type(e).__name__
        }), 503

@app.route('/ask', methods=['POST'])
def ask():
    """Process a natural language question using Google ADK + MCP."""
    try:
        # Get request data
        data = request.get_json()
        question = data.get('question')
        session_id = data.get('session_id')
        conversation_history = data.get('conversation_history')
        user_cambrian_api_key = data.get('cambrian_api_key')  # User's API key from request

        if not question:
            return jsonify({
                "success": False,
                "error": "Missing required parameter: question"
            }), 400

        if not user_cambrian_api_key:
            return jsonify({
                "success": False,
                "error": "Missing required parameter: cambrian_api_key"
            }), 400

        logger.info(f"Processing question: {question[:100]}...")
        logger.info(f"Using user's Cambrian API key: {user_cambrian_api_key[:8]}...")

        # Create a per-request agent instance with user's API key
        # This allows each user to use their own Cambrian API key
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        if not gemini_api_key:
            return jsonify({
                "success": False,
                "error": "Server configuration error: GEMINI_API_KEY not set"
            }), 500

        agent_instance = GoogleADKMCPFinal(
            gemini_api_key=gemini_api_key,
            cambrian_api_key=user_cambrian_api_key  # Use user's key, not server's
        )

        # Initialize agent for this request
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Initialize and process in same event loop
        success = loop.run_until_complete(agent_instance.initialize())
        if not success:
            return jsonify({
                "success": False,
                "error": "Failed to initialize agent with user's API key"
            }), 500

        # Process question
        result = loop.run_until_complete(
            agent_instance.process_question(
                question=question,
                session_id=session_id,
                conversation_history=conversation_history
            )
        )

        logger.info(f"Question processed: success={result.get('success')}")

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error processing question: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e),
            "answer": f"Error processing request: {str(e)}"
        }), 500

@app.route('/capabilities', methods=['GET'])
def capabilities():
    """Get agent capabilities."""
    try:
        agent_instance = get_agent()
        caps = agent_instance.get_capabilities()
        return jsonify(caps), 200
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.getenv('PYTHON_ADK_PORT', 9000))
    host = os.getenv('PYTHON_ADK_HOST', '127.0.0.1')

    logger.info(f"Starting Google ADK Flask server on {host}:{port}")
    logger.info(f"Endpoints: /health, /ask, /capabilities")

    app.run(
        host=host,
        port=port,
        debug=False,  # Disable debug in production
        threaded=True
    )

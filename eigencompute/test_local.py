"""
Local Test Script for Deep42 Agent
===================================

Test the agent locally before deploying to EigenCompute.

Usage:
1. Set up environment variables:
   cp .env.example .env
   # Edit .env with your API keys

2. Install dependencies:
   pip install -r requirements.txt

3. Run tests:
   python test_local.py

Author: Cambrian Team
"""

import os
import asyncio
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import agent
from deep42_agent import get_agent


async def test_agent():
    """Test the Deep42 agent with sample questions"""

    # Verify environment variables
    if not os.getenv('GEMINI_API_KEY'):
        logger.error("❌ GEMINI_API_KEY not set in .env file")
        return

    if not os.getenv('CAMBRIAN_API_KEY'):
        logger.error("❌ CAMBRIAN_API_KEY not set in .env file")
        return

    logger.info("✅ Environment variables loaded")

    # Get agent instance
    try:
        agent = await get_agent()
        logger.info("✅ Agent initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize agent: {e}")
        return

    # Test questions
    test_questions = [
        "What are some trending DeFi projects on Solana?",
        "Analyze social sentiment for Bitcoin",
        "Find alpha signals in recent crypto tweets",
    ]

    # Run tests
    for i, question in enumerate(test_questions, 1):
        print(f"\n{'='*80}")
        print(f"TEST {i}/{len(test_questions)}")
        print(f"Q: {question}")
        print('='*80)

        try:
            result = await agent.process_question(question)

            if result['success']:
                print(f"\n✅ SUCCESS")
                print(f"\nAnswer:\n{result['answer'][:500]}...")
                print(f"\nTools used: {result.get('tools_used', [])}")
                print(f"Docs: {result.get('docs_urls', [])}")
            else:
                print(f"\n❌ FAILED")
                print(f"Error: {result.get('error')}")

        except Exception as e:
            print(f"\n❌ EXCEPTION")
            print(f"Error: {e}")

        print(f"\n{'='*80}\n")

        # Small delay between requests
        await asyncio.sleep(2)

    logger.info("✅ All tests completed")


if __name__ == "__main__":
    asyncio.run(test_agent())

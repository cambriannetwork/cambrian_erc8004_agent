#!/usr/bin/env python3
"""
Standalone test for Google ADK + MCP integration.
Can be run locally or in Docker for testing.
"""

import asyncio
import sys
import os
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import our Google ADK MCP implementation
from google_adk_mcp import GoogleADKMCPFinal

async def test_initialization():
    """Test agent initialization."""
    print("\n" + "=" * 70)
    print("TEST 1: Agent Initialization")
    print("=" * 70)

    try:
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        cambrian_api_key = os.getenv('SERVER_CAMBRIAN_API_KEY') or os.getenv('CAMBRIAN_API_KEY')

        if not gemini_api_key:
            print("   ❌ GEMINI_API_KEY not set")
            return None

        print(f"   API Keys: GEMINI={'✓' if gemini_api_key else '✗'}, CAMBRIAN={'✓' if cambrian_api_key else '✗'}")

        agent = GoogleADKMCPFinal(
            gemini_api_key=gemini_api_key,
            cambrian_api_key=cambrian_api_key
        )

        print("   Initializing agent...")
        success = await agent.initialize()

        if not success:
            print("   ❌ Agent initialization failed")
            return None

        print(f"   ✅ Agent initialized successfully")
        print(f"   📊 Available tools: {len(agent.available_tools)}")

        return agent

    except Exception as e:
        print(f"   ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

async def test_query(agent, question):
    """Test a single query."""
    print(f"\n   Question: {question}")

    try:
        result = await agent.process_question(
            question=question,
            session_id="test_session"
        )

        if result.get('success'):
            answer = result.get('answer', 'No answer')
            print(f"   ✅ Success!")
            print(f"   📝 Answer: {answer[:200]}{'...' if len(answer) > 200 else ''}")

            if result.get('tools_used'):
                print(f"   🔧 Tools used: {result['tools_used']}")

            return True
        else:
            print(f"   ❌ Failed: {result.get('answer', 'Unknown error')}")
            return False

    except Exception as e:
        print(f"   ❌ Exception: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_queries(agent):
    """Test various queries."""
    print("\n" + "=" * 70)
    print("TEST 2: Query Processing")
    print("=" * 70)

    test_questions = [
        "What is the current block on Solana?",
        "What is the current price of SOL token So11111111111111111111111111111111111111112?",
        "Show me trending tokens on Solana",
        "Get security metrics for So11111111111111111111111111111111111111112",
    ]

    results = []
    for i, question in enumerate(test_questions, 1):
        print(f"\nQuery {i}:")
        success = await test_query(agent, question)
        results.append(success)

    return results

async def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("GOOGLE ADK + MCP INTEGRATION TEST SUITE")
    print("=" * 70)

    # Test 1: Initialization
    agent = await test_initialization()
    if not agent:
        print("\n❌ Initialization failed - cannot continue")
        sys.exit(1)

    # Test 2: Queries
    results = await test_queries(agent)

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    successful = sum(results)
    total = len(results)
    print(f"   Queries: {successful}/{total} successful")
    print(f"   Success rate: {(successful/total*100):.1f}%")

    if successful == total:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {total - successful} test(s) failed")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

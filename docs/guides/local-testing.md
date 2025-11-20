# Local Testing Guide

This guide explains how to test the ERC-8004 agent locally before deploying to production.

## Prerequisites

- Docker and Docker Compose installed
- Environment variables set:
  ```bash
  export GEMINI_API_KEY="your-gemini-api-key"
  export CAMBRIAN_API_KEY="your-cambrian-api-key"
  ```

## Quick Start

```bash
# Test Python ADK directly
cd agent/python_adk && python test_google_adk.py

# Test with Docker Compose
docker-compose up python-adk

# Test full agent stack
docker-compose up agent
```

See full documentation in the file for all testing options.

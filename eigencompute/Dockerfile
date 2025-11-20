# Deep42 Agent - EigenCompute TEE Production Dockerfile
# ======================================================

# Use official Python slim image for linux/amd64 (required by EigenCompute)
FROM --platform=linux/amd64 python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Run as root user (required by EigenCompute TEE)
USER root

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py deep42_agent.py ./

# Expose port 3000 for HTTP access
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Run the application
# IMPORTANT: Bind to 0.0.0.0 (not localhost) for external accessibility in TEE
CMD ["python", "app.py"]

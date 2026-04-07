# Aether Protect Agent - Dockerfile for Bedrock AgentCore
# ARM64 architecture required by AgentCore

FROM public.ecr.aws/docker/library/python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all agent code
COPY . .

# Set Python path to include /app
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# AgentCore expects these environment variables at runtime:
# AWS_REGION, SAGEMAKER_ENDPOINT, WAF_TEST_ENDPOINT

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ping || exit 1

# Entry point for AgentCore - run from /app directory
EXPOSE 8080
CMD ["python", "earendel_strands/app.py"]

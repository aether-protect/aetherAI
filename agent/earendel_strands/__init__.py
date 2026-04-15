# Copyright (c) 2026 Aether Protect Contributors. MIT License. See license.txt.
"""
Aether Protect Strands Agent - AI-powered security analysis agent.

Deployed to Bedrock AgentCore for scalable, serverless execution.
"""

from .agent import create_security_agent

__all__ = ["create_security_agent"]

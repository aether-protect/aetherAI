"""Aether Protect security agent - Strands agent definition."""

from strands import Agent
from strands.models import BedrockModel

from .tools import scan_threat, full_scan, explain_mitre_technique, waf_check
from .prompts import SECURITY_ANALYST_PROMPT, QUICK_SCAN_PROMPT


def create_security_agent(
    model_id: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    quick_mode: bool = False
) -> Agent:
    """
    Create an Aether Protect security analysis agent.

    Args:
        model_id: Bedrock model ID to use for reasoning
        quick_mode: If True, use a shorter prompt for faster responses

    Returns:
        Configured Strands Agent
    """
    model = BedrockModel(model_id=model_id)

    system_prompt = QUICK_SCAN_PROMPT if quick_mode else SECURITY_ANALYST_PROMPT

    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=[scan_threat, full_scan, explain_mitre_technique, waf_check]
    )


def create_lightweight_agent() -> Agent:
    """
    Create a lightweight agent using Claude Haiku for faster responses.
    Good for high-volume scanning where speed matters more than depth.
    """
    return create_security_agent(
        model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        quick_mode=True
    )


def analyze(text: str, detailed: bool = True) -> str:
    """
    Analyze text for security threats.

    Args:
        text: Text to analyze
        detailed: If True, provide detailed analysis; if False, quick scan

    Returns:
        Analysis result as string
    """
    agent = create_security_agent(quick_mode=not detailed)
    result = agent(f"Analyze this for security threats:\n\n{text}")
    return result.message

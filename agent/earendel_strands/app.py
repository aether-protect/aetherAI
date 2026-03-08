"""Aether Protect agent - Bedrock AgentCore entry point."""

import os
import sys

# Ensure the agent directory is in the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from earendel_strands.agent import create_security_agent, create_lightweight_agent

# Initialize the AgentCore app
app = BedrockAgentCoreApp()

# Create the security agent
agent = create_security_agent()


@app.entrypoint
def invoke(payload: dict) -> dict:
    """
    Main invocation handler for AgentCore.

    Args:
        payload: Request payload with keys:
            - prompt: The text to analyze or question to ask
            - mode: Optional - "quick" for faster analysis

    Returns:
        Response dict with analysis result
    """
    prompt = payload.get("prompt", "")
    mode = payload.get("mode", "detailed")

    if not prompt:
        return {
            "error": "No prompt provided",
            "usage": "Send a payload with 'prompt' key containing text to analyze"
        }

    # Use quick mode if requested
    if mode == "quick":
        quick_agent = create_lightweight_agent()
        result = quick_agent(prompt)
    else:
        result = agent(prompt)

    return {
        "result": result.message,
        "stop_reason": result.stop_reason
    }


@app.entrypoint
async def invoke_stream(payload: dict):
    """
    Streaming invocation handler for AgentCore.

    Yields events as the agent processes the request.
    """
    prompt = payload.get("prompt", "")

    if not prompt:
        yield {"error": "No prompt provided"}
        return

    async for event in agent.stream_async(prompt):
        yield event


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Aether Protect Security Agent")
    parser.add_argument("--serve", action="store_true", help="Run as AgentCore server")
    parser.add_argument("--test", type=str, help="Test with a prompt")
    args = parser.parse_args()

    if args.serve:
        print("Starting Aether Protect on AgentCore...")
        app.run()
    elif args.test:
        print(f"Testing with prompt: {args.test}")
        result = invoke({"prompt": args.test})
        print(result["result"])
    else:
        app.run()

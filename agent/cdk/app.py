#!/usr/bin/env python3
"""Aether Protect agent CDK application."""

import os
import sys
from pathlib import Path
import aws_cdk as cdk
from stack import AetherProtectAgentStack
from agentcore_stack import AetherProtectAgentCoreStack

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import AGENTCORE_STACK_NAME, AGENT_STACK_NAME, APP_NAME, PRIMARY_REGION

app = cdk.App()

env = cdk.Environment(
    account=os.environ.get('CDK_DEFAULT_ACCOUNT', os.environ.get('AWS_ACCOUNT_ID')),
    region=PRIMARY_REGION
)

agent_stack = AetherProtectAgentStack(
    app,
    AGENT_STACK_NAME,
    env=env,
    description=f"{APP_NAME} Agent - S3, SageMaker endpoint, IAM"
)

agentcore_stack = AetherProtectAgentCoreStack(
    app,
    AGENTCORE_STACK_NAME,
    model_bucket=agent_stack.model_bucket,
    sagemaker_endpoint=agent_stack.endpoint_name,
    env=env,
    description=f"{APP_NAME} Strands agent on Bedrock AgentCore"
)
agentcore_stack.add_dependency(agent_stack)

app.synth()

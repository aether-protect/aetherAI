#!/usr/bin/env python3
"""Aether Protect web UI CDK application."""

import os
import sys
from pathlib import Path
import aws_cdk as cdk
from stack import AetherProtectWebStack

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import APP_NAME, PRIMARY_REGION, WEB_STACK_NAME

app = cdk.App()

env = cdk.Environment(
    account=os.environ.get('CDK_DEFAULT_ACCOUNT', os.environ.get('AWS_ACCOUNT_ID')),
    region=PRIMARY_REGION
)

web_stack = AetherProtectWebStack(
    app,
    WEB_STACK_NAME,
    env=env,
    description=f"{APP_NAME} Web UI - CloudFront, Lambda, DynamoDB"
)

app.synth()

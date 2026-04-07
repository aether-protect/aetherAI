#!/usr/bin/env python3
"""
Aether Protect WAF CDK app

Deploys the WAF test infrastructure for Layer 2 defense.

Usage:
    cd waf
    cdk deploy AetherProtectWAFTestStack
"""

import os
import sys
from pathlib import Path
import aws_cdk as cdk

from waf_test_stack import AetherProtectWAFTestStack

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from project_config import APP_NAME, PRIMARY_REGION, WAF_STACK_NAME

app = cdk.App()

env = cdk.Environment(
    account=os.environ.get('CDK_DEFAULT_ACCOUNT', os.environ.get('AWS_ACCOUNT_ID')),
    region=PRIMARY_REGION
)

AetherProtectWAFTestStack(
    app, WAF_STACK_NAME,
    env=env,
    description=f"{APP_NAME} WAF test endpoint for layer 2 defense"
)

app.synth()

"""Aether Protect core scanner - SageMaker ML endpoint and WAF integration."""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any
from datetime import datetime
from pathlib import Path
import sys

import boto3
from botocore.exceptions import ClientError

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import (
    DEFAULT_SAGEMAKER_ENDPOINT,
    PRIMARY_REGION,
    WAF_STACK_NAME,
    WAF_TEST_ENDPOINT_PARAM,
)

# Configuration from environment
# All Aether Protect resources are in us-east-1
SAGEMAKER_REGION = os.environ.get('SAGEMAKER_REGION', PRIMARY_REGION)
REGION = os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', PRIMARY_REGION))
SAGEMAKER_ENDPOINT = os.environ.get('SAGEMAKER_ENDPOINT', os.environ.get('SAGEMAKER_ENDPOINT_NAME', DEFAULT_SAGEMAKER_ENDPOINT))
WAF_TEST_ENDPOINT = os.environ.get('WAF_TEST_ENDPOINT', '')

# Lazy-initialized clients
_clients: Dict[str, Any] = {}
_waf_endpoint_cache: str = ""


def get_client(service: str):
    """Get or create AWS client."""
    if service not in _clients:
        # Use SAGEMAKER_REGION for sagemaker-runtime, REGION for others
        region = SAGEMAKER_REGION if service == 'sagemaker-runtime' else REGION
        _clients[service] = boto3.client(service, region_name=region)
    return _clients[service]


def get_waf_endpoint() -> str:
    """Get WAF test endpoint URL from env var or SSM Parameter Store."""
    global _waf_endpoint_cache

    if _waf_endpoint_cache:
        return _waf_endpoint_cache

    if WAF_TEST_ENDPOINT:
        _waf_endpoint_cache = WAF_TEST_ENDPOINT
        return _waf_endpoint_cache

    try:
        ssm = get_client('ssm')
        response = ssm.get_parameter(Name=WAF_TEST_ENDPOINT_SSM_PARAM)
        _waf_endpoint_cache = response['Parameter']['Value']
        return _waf_endpoint_cache
    except Exception as e:
        print(f"Could not get WAF endpoint from SSM: {e}")
        return ""


def check_waf(payload: str) -> Dict[str, Any]:
    """
    Test payload against real AWS WAF managed rules.

    Sends the payload to a test endpoint protected by AWS WAF.
    If WAF blocks the request, returns would_block=True.

    Args:
        payload: The text/payload to test against WAF rules

    Returns:
        dict with keys:
            - would_block: bool - True if WAF would block this payload
            - waf_response: dict with status_code and message
            - matched_rule: str - Rule that matched (if blocked)
            - error: str - Error message (if any)
    """
    result = {
        "payload_preview": payload[:100] + "..." if len(payload) > 100 else payload,
        "would_block": False,
        "waf_response": None,
        "matched_rule": None,
        "rule_group": None
    }

    waf_endpoint = get_waf_endpoint()
    if not waf_endpoint:
        result["error"] = f"WAF_TEST_ENDPOINT not configured (deploy {WAF_STACK_NAME} first)"
        return result

    try:
        # Prepare request with payload in body and headers
        data = json.dumps({
            "payload": payload,
            "test_header": payload
        }).encode('utf-8')

        req = urllib.request.Request(
            waf_endpoint,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'X-Test-Payload': payload[:500]
            },
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            result["waf_response"] = {
                "status_code": response.status,
                "message": "Request passed WAF"
            }
            result["would_block"] = False

    except urllib.error.HTTPError as e:
        if e.code == 403:
            result["would_block"] = True
            result["waf_response"] = {
                "status_code": 403,
                "message": "Blocked by AWS WAF"
            }
            waf_rule = e.headers.get('x-amzn-waf-action', 'BLOCK')
            result["matched_rule"] = waf_rule
            result["rule_group"] = "AWS Managed Rules"
        else:
            result["error"] = f"HTTP {e.code}: {str(e)[:100]}"

    except urllib.error.URLError as e:
        result["error"] = f"Connection error: {str(e)[:100]}"

    except Exception as e:
        result["error"] = f"Error: {str(e)[:100]}"

    return result


def analyze_with_sagemaker(text: str) -> Dict[str, Any]:
    """
    Analyze text for security threats using the SageMaker ML model.

    Args:
        text: Text to analyze (SQL query, HTTP request, log entry, etc.)

    Returns:
        dict with keys:
            - is_threat: bool
            - confidence: float (0-1)
            - threat_type: str
            - mitre_attack: list of MITRE ATT&CK IDs
            - recommendations: list of security recommendations
            - root_cause: str explanation
    """
    try:
        runtime = get_client('sagemaker-runtime')
        response = runtime.invoke_endpoint(
            EndpointName=SAGEMAKER_ENDPOINT,
            ContentType='application/json',
            Body=json.dumps({"text": text})
        )
        result = json.loads(response['Body'].read())
        result['analyzed_text'] = text[:100] + "..." if len(text) > 100 else text
        return result
    except ClientError as e:
        return {
            "error": str(e),
            "analyzed_text": text,
            "is_threat": False,
            "confidence": 0,
            "threat_type": "error",
            "mitre_attack": [],
            "recommendations": ["Unable to analyze - check SageMaker endpoint"],
            "root_cause": f"SageMaker error: {str(e)}"
        }


def scan(text: str, ip: str = "0.0.0.0") -> Dict[str, Any]:
    """
    Scan text for security threats and return structured result.

    Args:
        text: Text to scan
        ip: Optional IP address for logging

    Returns:
        Structured scan result with ML analysis and decision
    """
    result = {
        "text": text[:100] + "..." if len(text) > 100 else text,
        "ip": ip,
        "timestamp": datetime.utcnow().isoformat(),
        "ml_result": None,
        "decision": None
    }

    # ML Analysis
    ml_result = analyze_with_sagemaker(text)
    result["ml_result"] = {
        "is_threat": ml_result.get("is_threat", False),
        "confidence": ml_result.get("confidence", 0),
        "threat_type": ml_result.get("threat_type", "unknown"),
        "mitre_attack": ml_result.get("mitre_attack", [])
    }

    # Decision
    if ml_result.get("is_threat"):
        result["decision"] = {
            "action": "BLOCK",
            "reason": f"ML detected: {ml_result.get('threat_type')}",
            "confidence": ml_result.get("confidence", 0)
        }
    else:
        result["decision"] = {
            "action": "ALLOW",
            "reason": "No threat detected",
            "confidence": ml_result.get("confidence", 0)
        }

    return result

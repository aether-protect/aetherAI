"""Aether Protect web UI Lambda handler."""

import json
import os
import re
import uuid
import boto3
import base64
import hmac
import hashlib
import sys
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import unquote
from botocore.exceptions import ClientError

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import (
    APP_VERSION,
    DEFAULT_AUTH_USERS,
    DEFAULT_SAGEMAKER_ENDPOINT,
    DEFAULT_SCANS_TABLE,
    DEFAULT_TOKEN_EXPIRY_HOURS,
    DEFAULT_TOKEN_SECRET,
    PRIMARY_REGION,
)

# Configuration
AGENTCORE_RUNTIME_ARN = os.environ.get('AGENTCORE_RUNTIME_ARN', '')
SCANS_TABLE = os.environ.get('SCANS_TABLE', DEFAULT_SCANS_TABLE)
REGION = os.environ.get('AWS_REGION_NAME', PRIMARY_REGION)
SAGEMAKER_ENDPOINT = os.environ.get('SAGEMAKER_ENDPOINT', DEFAULT_SAGEMAKER_ENDPOINT)
WAF_TEST_ENDPOINT = os.environ.get('WAF_TEST_ENDPOINT', '')

# Token configuration
TOKEN_SECRET = os.environ.get('TOKEN_SECRET', DEFAULT_TOKEN_SECRET)
TOKEN_EXPIRY_HOURS = int(os.environ.get('TOKEN_EXPIRY_HOURS', str(DEFAULT_TOKEN_EXPIRY_HOURS)))

# Users from environment (format: "user1:pass1,user2:pass2")
def _parse_users():
    users_str = os.environ.get('AUTH_USERS', DEFAULT_AUTH_USERS)
    users = {}
    for pair in users_str.split(','):
        if ':' in pair:
            u, p = pair.split(':', 1)
            users[u.strip()] = p.strip()
    return users

USERS = _parse_users()

# AWS clients
dynamodb = boto3.resource('dynamodb', region_name=REGION)
agentcore_client = boto3.client('bedrock-agentcore', region_name=REGION)
sagemaker_runtime = boto3.client('sagemaker-runtime', region_name=REGION)
scans_table = dynamodb.Table(SCANS_TABLE)


def authenticate(username: str, password: str) -> Optional[str]:
    if username in USERS and USERS[username] == password:
        return username
    return None


def create_token(username: str) -> str:
    """Create HMAC-signed token with expiration."""
    expiry = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)
    expiry_ts = int(expiry.timestamp())
    payload = f"{username}:{expiry_ts}"
    signature = hmac.new(
        TOKEN_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()[:32]
    token_data = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(token_data.encode()).decode()


def verify_token(token: str) -> Optional[str]:
    """Verify HMAC-signed token and check expiration."""
    try:
        token_data = base64.urlsafe_b64decode(token.encode()).decode()
        parts = token_data.split(':')
        if len(parts) != 3:
            return None
        username, expiry_ts, signature = parts

        # Check expiration
        if int(expiry_ts) < int(datetime.utcnow().timestamp()):
            return None

        # Verify signature
        payload = f"{username}:{expiry_ts}"
        expected_sig = hmac.new(
            TOKEN_SECRET.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()[:32]

        if not hmac.compare_digest(signature, expected_sig):
            return None

        if username in USERS:
            return username
    except Exception:
        pass
    return None


def get_user_from_event(event: Dict[str, Any]) -> Optional[str]:
    headers = event.get("headers") or {}
    auth_header = headers.get("Authorization") or headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return verify_token(token)
    return None


INTERESTING_HEADERS = {
    'authorization', 'x-auth-token', 'x-api-key', 'api-key',
    'user-agent', 'x-forwarded-for', 'x-real-ip',
    'referer', 'origin', 'cookie', 'content-type'
}


def detect_input_format(text: str) -> str:
    stripped = text.strip().lower()

    if stripped.startswith('curl ') or stripped.startswith('curl\t'):
        return "curl"

    http_methods = ('get ', 'post ', 'put ', 'delete ', 'patch ', 'head ', 'options ')
    if any(stripped.startswith(m) for m in http_methods):
        return "http"

    if 'http/1.' in stripped or 'http/2' in stripped:
        return "http"

    return "raw"


def parse_http_request(raw: str) -> Dict[str, Any]:
    result = {
        "method": None,
        "path": None,
        "query_params": {},
        "headers": {},
        "body": None,
        "input_type": "http"
    }

    lines = raw.split('\n')
    lines = [line.rstrip('\r') for line in lines]

    if not lines:
        return result

    request_match = re.match(r'^(\w+)\s+([^\s]+)(?:\s+HTTP/[\d.]+)?', lines[0], re.IGNORECASE)
    if request_match:
        result["method"] = request_match.group(1).upper()
        full_path = request_match.group(2)

        if '?' in full_path:
            path, query_string = full_path.split('?', 1)
            result["path"] = path
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    try:
                        result["query_params"][unquote(key)] = unquote(value)
                    except Exception:
                        result["query_params"][key] = value
        else:
            result["path"] = full_path

    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if line == '':
            body_start = i + 1
            break
        colon_idx = line.find(':')
        if colon_idx > 0:
            header_name = line[:colon_idx].strip()
            header_value = line[colon_idx + 1:].strip()
            result["headers"][header_name] = header_value

    if body_start < len(lines):
        body = '\n'.join(lines[body_start:]).strip()
        if body:
            result["body"] = body

    return result


def parse_curl_command(cmd: str) -> Dict[str, Any]:
    import shlex
    result = {
        "method": "GET",
        "path": None,
        "query_params": {},
        "headers": {},
        "body": None,
        "input_type": "curl"
    }

    normalized = re.sub(r'\\\n\s*', ' ', cmd).strip()

    try:
        tokens = shlex.split(normalized)
    except ValueError:
        tokens = normalized.split()

    if tokens and tokens[0].lower() == 'curl':
        tokens = tokens[1:]

    i = 0
    while i < len(tokens):
        token = tokens[i]
        next_token = tokens[i + 1] if i + 1 < len(tokens) else None

        if token in ('-X', '--request') and next_token:
            result["method"] = next_token.upper()
            i += 2
            continue

        if token in ('-H', '--header') and next_token:
            colon_idx = next_token.find(':')
            if colon_idx > 0:
                result["headers"][next_token[:colon_idx].strip()] = next_token[colon_idx + 1:].strip()
            i += 2
            continue

        if token in ('-d', '--data', '--data-raw', '--data-binary') and next_token:
            result["body"] = next_token
            if result["method"] == "GET":
                result["method"] = "POST"
            i += 2
            continue

        if token.startswith('http://') or token.startswith('https://'):
            from urllib.parse import urlparse, parse_qs
            try:
                parsed = urlparse(token)
                result["path"] = parsed.path or '/'
                for key, values in parse_qs(parsed.query).items():
                    result["query_params"][key] = values[0] if values else ""
            except Exception:
                result["path"] = token
            i += 1
            continue

        if token.startswith('-') and next_token and not next_token.startswith('-'):
            i += 2
        else:
            i += 1

    return result


def parse_input(text: str) -> Dict[str, Any]:
    input_type = detect_input_format(text)

    if input_type == "http":
        parsed = parse_http_request(text)
    elif input_type == "curl":
        parsed = parse_curl_command(text)
    else:
        parsed = {"body": text, "input_type": "raw", "method": None, "path": None, "query_params": {}, "headers": {}}

    parts = []
    if parsed.get("path"):
        parts.append(parsed["path"])
    for value in parsed.get("query_params", {}).values():
        parts.append(value)
    for name, value in parsed.get("headers", {}).items():
        if name.lower() in INTERESTING_HEADERS:
            parts.append(value)
    if parsed.get("body"):
        parts.append(parsed["body"])

    parsed["combined_text"] = " ".join(parts) if parts else text
    return parsed


def analyze_with_sagemaker_direct(text: str) -> Dict[str, Any]:
    try:
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=SAGEMAKER_ENDPOINT,
            ContentType='application/json',
            Body=json.dumps({'text': text})
        )
        result = json.loads(response['Body'].read())
        is_threat = result.get('is_threat', False)
        threat_type = result.get('threat_type', 'unknown')

        ml_result = {
            "is_threat": is_threat,
            "confidence": result.get('confidence', 0),
            "threat_type": threat_type,
            "mitre_attack": result.get('mitre_attack', []),
            "recommendations": result.get('recommendations', []),
            "root_cause": result.get('root_cause', '')
        }

        waf_result = {"checked": False, "would_block": False, "matched_rule": None, "rule_group": None}
        if not is_threat and WAF_TEST_ENDPOINT:
            waf_result = check_waf_direct(text)
            waf_result["checked"] = True

        if is_threat:
            decision = {
                "action": "BLOCK",
                "reason": f"ML detected: {threat_type}",
                "confidence": ml_result["confidence"],
                "detection_layer": "ML"
            }
        elif waf_result.get("would_block"):
            decision = {
                "action": "BLOCK",
                "reason": f"WAF blocked: {waf_result.get('matched_rule', 'Unknown')}",
                "confidence": 1.0,
                "detection_layer": "WAF"
            }
        else:
            decision = {
                "action": "ALLOW",
                "reason": "No threat detected",
                "confidence": 1.0 - ml_result["confidence"],
                "detection_layer": None
            }

        return {
            "ml_result": ml_result,
            "waf_result": waf_result,
            "decision": decision,
            "agent_analysis": f"SageMaker Analysis (Fallback Mode): {'Threat detected - ' + threat_type if is_threat else 'No threat detected'}",
            "model": "sagemaker"
        }

    except Exception as e:
        return {
            "error": str(e),
            "agent_analysis": f"SageMaker error: {str(e)}",
            "ml_result": {"is_threat": False, "confidence": 0, "threat_type": "error"},
            "waf_result": {"checked": False, "would_block": False},
            "decision": {"action": "ERROR", "reason": str(e), "confidence": 0, "detection_layer": None}
        }


def check_waf_direct(payload: str) -> Dict[str, Any]:
    import urllib.request
    import urllib.error
    result = {"would_block": False, "matched_rule": None, "rule_group": None}

    if not WAF_TEST_ENDPOINT:
        result["error"] = "WAF endpoint not configured"
        return result

    try:
        data = json.dumps({"payload": payload}).encode('utf-8')
        req = urllib.request.Request(
            WAF_TEST_ENDPOINT,
            data=data,
            headers={'Content-Type': 'application/json', 'X-Test-Payload': payload[:500]},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result["would_block"] = False
    except urllib.error.HTTPError as e:
        if e.code == 403:
            result["would_block"] = True
            result["matched_rule"] = e.headers.get('x-amzn-waf-action', 'BLOCK')
            result["rule_group"] = "AWS Managed Rules"
    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_with_agent(text: str) -> Dict[str, Any]:
    try:
        prompt = f"Analyze this for security threats:\n\n{text}"
        payload = json.dumps({"prompt": prompt, "mode": "detailed"})
        response = agentcore_client.invoke_agent_runtime(
            agentRuntimeArn=AGENTCORE_RUNTIME_ARN,
            payload=payload.encode('utf-8'),
            contentType='application/json'
        )
        response_body = response['response'].read()
        return parse_agent_response(response_body)
    except (ClientError, Exception):
        return analyze_with_sagemaker_direct(text)


def parse_agent_response(response_body: bytes) -> Dict[str, Any]:
    content = response_body.decode('utf-8')
    ml_result = {
        "is_threat": False,
        "confidence": 0,
        "threat_type": None,
        "mitre_attack": []
    }
    waf_result = {
        "would_block": False,
        "checked": False,
        "matched_rule": None,
        "rule_group": None
    }
    analysis_parts = []

    for line in content.split('\n'):
        if not line.startswith('data: '):
            continue
        data = line[6:]

        if "'is_threat':" in data or '"is_threat":' in data:
            try:
                if "'is_threat': True" in data or '"is_threat": true' in data:
                    ml_result["is_threat"] = True
                conf_match = re.search(r'["\']confidence["\']\s*:\s*([\d.eE+-]+)', data)
                if conf_match and 'threat_type_confidence' not in data[:data.find(conf_match.group(0))+len(conf_match.group(0))].split(',')[-1]:
                    try:
                        ml_result["confidence"] = float(conf_match.group(1))
                    except ValueError:
                        pass
                type_match = re.search(r"'threat_type':\s*'([^']+)'|\"threat_type\":\s*\"([^\"]+)\"", data)
                if type_match:
                    ml_result["threat_type"] = type_match.group(1) or type_match.group(2)
                mitre_match = re.search(r"'mitre_attack':\s*\[([^\]]+)\]|\"mitre_attack\":\s*\[([^\]]+)\]", data)
                if mitre_match:
                    mitre_str = mitre_match.group(1) or mitre_match.group(2)
                    ml_result["mitre_attack"] = [t.strip().strip("'\"") for t in mitre_str.split(',')]
            except Exception:
                pass

        if "'would_block':" in data or '"would_block":' in data:
            try:
                waf_result["checked"] = True
                if "'would_block': True" in data or '"would_block": true' in data:
                    waf_result["would_block"] = True
                rule_match = re.search(r"'matched_rule':\s*'([^']+)'|\"matched_rule\":\s*\"([^\"]+)\"", data)
                if rule_match:
                    waf_result["matched_rule"] = rule_match.group(1) or rule_match.group(2)
                group_match = re.search(r"'rule_group':\s*'([^']+)'|\"rule_group\":\s*\"([^\"]+)\"", data)
                if group_match:
                    waf_result["rule_group"] = group_match.group(1) or group_match.group(2)
            except Exception:
                pass

        if '"text":' in data or "'text':" in data:
            try:
                text_match = re.search(r'"text":\s*"((?:[^"\\]|\\.)*)"|\'text\':\s*\'((?:[^\'\\]|\\.)*)\'', data)
                if text_match:
                    text = text_match.group(1) or text_match.group(2)
                    text = text.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace("\\'", "'")
                    if (len(text) > 20 and
                        not text.startswith("{'is_threat'") and
                        not text.startswith('{"is_threat"') and
                        not text.startswith("{'would_block'") and
                        not text.startswith('{"would_block"') and
                        "Analyze this for security threats:" not in text):
                        analysis_parts.append(text)
            except Exception:
                pass

    agent_analysis = "".join(analysis_parts)
    if "## Threat Analysis" in agent_analysis:
        agent_analysis = agent_analysis[agent_analysis.find("## Threat Analysis"):]
    elif "**Verdict**" in agent_analysis:
        agent_analysis = agent_analysis[agent_analysis.find("**Verdict**"):]

    agent_analysis = agent_analysis.strip()

    return {
        "ml_result": ml_result,
        "waf_result": waf_result,
        "agent_analysis": agent_analysis
    }


def parse_agent_analysis(analysis: str) -> Dict[str, Any]:
    result = {
        "is_threat": False,
        "confidence": 0.0,
        "threat_type": "unknown",
        "detection_layer": None,
        "mitre_attack": [],
        "waf_checked": False,
        "waf_blocked": False
    }

    analysis_lower = analysis.lower()

    if "threat detected" in analysis_lower or "verdict**: threat" in analysis_lower:
        result["is_threat"] = True
    elif "blocked" in analysis_lower and "waf" in analysis_lower:
        result["is_threat"] = True
        result["waf_blocked"] = True

    if "layer 1" in analysis_lower or "ml" in analysis_lower.split("detection")[0] if "detection" in analysis_lower else "":
        result["detection_layer"] = "ML"
    if "layer 2" in analysis_lower or "waf" in analysis_lower:
        result["waf_checked"] = True
        if result["waf_blocked"]:
            result["detection_layer"] = "WAF"

    threat_types = ["sql_injection", "xss", "command_injection", "path_traversal",
                   "ssrf", "xxe", "ldap_injection", "nosql_injection"]
    for tt in threat_types:
        if tt.replace("_", " ") in analysis_lower or tt in analysis_lower:
            result["threat_type"] = tt
            break

    confidence_match = re.search(r'(\d+(?:\.\d+)?)\s*%', analysis)
    if confidence_match:
        result["confidence"] = float(confidence_match.group(1)) / 100

    mitre_matches = re.findall(r'T\d{4}(?:\.\d{3})?', analysis)
    result["mitre_attack"] = list(set(mitre_matches))
    return result


def scan(text: str) -> Dict[str, Any]:
    agent_result = analyze_with_agent(text)
    if agent_result.get("error"):
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_analysis": agent_result.get("agent_analysis", ""),
            "ml_result": {
                "is_threat": False,
                "confidence": 0.0,
                "threat_type": "unknown",
                "mitre_attack": [],
                "recommendations": [],
                "root_cause": ""
            },
            "waf_result": {
                "checked": False,
                "would_block": False,
                "matched_rule": None,
                "rule_group": None,
                "error": agent_result.get("error")
            },
            "decision": {
                "action": "ERROR",
                "reason": f"Agent error: {agent_result.get('error_code', 'Unknown')}",
                "confidence": 0,
                "detection_layer": None
            }
        }

    ml_result = agent_result.get("ml_result", {})
    waf_result = agent_result.get("waf_result", {})

    ml_result.setdefault("is_threat", False)
    ml_result.setdefault("confidence", 0.0)
    ml_result.setdefault("threat_type", "unknown")
    ml_result.setdefault("mitre_attack", [])
    ml_result.setdefault("recommendations", [])
    ml_result.setdefault("root_cause", "")

    waf_result.setdefault("checked", False)
    waf_result.setdefault("would_block", False)
    waf_result.setdefault("matched_rule", None)
    waf_result.setdefault("rule_group", None)
    waf_result.setdefault("error", None)

    is_threat = ml_result.get("is_threat", False)
    waf_blocked = waf_result.get("would_block", False)

    if is_threat:
        detection_layer = "ML"
    elif waf_blocked:
        detection_layer = "WAF"
        is_threat = True
    else:
        detection_layer = None

    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "agent_analysis": agent_result.get("agent_analysis", ""),
        "ml_result": ml_result,
        "waf_result": waf_result,
        "decision": None
    }

    if is_threat:
        result["decision"] = {
            "action": "BLOCK",
            "reason": f"Agent detected: {ml_result.get('threat_type', 'threat')}",
            "confidence": ml_result.get("confidence", 0.0),
            "detection_layer": detection_layer
        }
    else:
        result["decision"] = {
            "action": "ALLOW",
            "reason": "Agent analysis: No threat detected",
            "confidence": ml_result.get("confidence", 0.0),
            "detection_layer": None
        }

    return result


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def save_scan(
    raw_request: str,
    input_type: str,
    processed_query: str,
    response: Dict,
    threat_detected: bool,
    threat_type: Optional[str],
    user_id: str = "anonymous"
) -> str:
    scan_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    item = {
        "id": scan_id,
        "timestamp": timestamp,
        "raw_request": raw_request,
        "input_type": input_type,
        "processed_query": processed_query,
        "response": json.dumps(response),
        "threat_detected": "true" if threat_detected else "false",
        "threat_type": threat_type or "none",
        "user_id": user_id,
        "ttl": int((datetime.utcnow() + timedelta(days=30)).timestamp())
    }

    scans_table.put_item(Item=item)
    return scan_id


def get_scans(limit: int = 50, threat_only: bool = False, user_id: Optional[str] = None) -> List[Dict]:
    if threat_only:
        response = scans_table.query(
            IndexName="threat-index",
            KeyConditionExpression="threat_detected = :td",
            ExpressionAttributeValues={":td": "true"},
            ScanIndexForward=False,
            Limit=limit * 2
        )
    else:
        response = scans_table.scan(Limit=limit * 2)

    items = response.get("Items", [])

    if user_id:
        items = [item for item in items if item.get("user_id") == user_id]

    for item in items:
        item["response"] = json.loads(item.get("response", "{}"))
        item["threat_detected"] = item.get("threat_detected") == "true"
        if item.get("threat_type") == "none":
            item["threat_type"] = None

    items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return items[:limit]


def get_scan_by_id(scan_id: str) -> Optional[Dict]:
    response = scans_table.query(
        KeyConditionExpression="id = :id",
        ExpressionAttributeValues={":id": scan_id},
        Limit=1
    )

    items = response.get("Items", [])
    if not items:
        return None

    item = items[0]
    item["response"] = json.loads(item.get("response", "{}"))
    item["threat_detected"] = item.get("threat_detected") == "true"
    if item.get("threat_type") == "none":
        item["threat_type"] = None

    return item


def get_stats(user_id: Optional[str] = None) -> Dict[str, Any]:
    response = scans_table.scan(
        ProjectionExpression="threat_detected, threat_type, user_id"
    )

    items = response.get("Items", [])

    if user_id:
        items = [item for item in items if item.get("user_id") == user_id]

    total = len(items)
    threats = sum(1 for item in items if item.get("threat_detected") == "true")

    type_counts = {}
    for item in items:
        threat_type = item.get("threat_type")
        if threat_type and threat_type != "none":
            type_counts[threat_type] = type_counts.get(threat_type, 0) + 1

    by_type = [{"threat_type": k, "count": v} for k, v in sorted(type_counts.items(), key=lambda x: -x[1])]

    return {
        "total_scans": total,
        "threats_detected": threats,
        "by_type": by_type
    }


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    http_method = event.get("httpMethod", "GET")
    path = event.get("path", "")
    body = event.get("body")

    if body and isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass

    try:
        if path == "/api/health":
            return response(200, {
                "status": "ok",
                "version": APP_VERSION,
                "model": "agentcore",
                "runtime": AGENTCORE_RUNTIME_ARN
            })

        if path == "/api/login" and http_method == "POST":
            if not body or not body.get("username") or not body.get("password"):
                return response(400, {"error": "username and password are required"})

            username = body["username"]
            password = body["password"]

            authenticated_user = authenticate(username, password)
            if not authenticated_user:
                return response(401, {"error": "Invalid credentials"})

            token = create_token(authenticated_user)
            return response(200, {
                "token": token,
                "username": authenticated_user
            })

        user_id = get_user_from_event(event)
        if not user_id:
            return response(401, {"error": "Authentication required"})

        if path == "/api/scan" and http_method == "POST":
            if not body or not body.get("raw_request"):
                return response(400, {"error": "raw_request is required"})

            raw_request = body["raw_request"]
            parsed = parse_input(raw_request)
            processed_query = parsed["combined_text"]
            result = scan(processed_query)

            decision = result.get("decision", {})
            threat_detected = decision.get("action") == "BLOCK"
            detection_layer = decision.get("detection_layer")

            if detection_layer == "ML":
                threat_type = result.get("ml_result", {}).get("threat_type")
            else:
                threat_type = None

            scan_id = save_scan(
                raw_request=raw_request,
                input_type=parsed["input_type"],
                processed_query=processed_query,
                response=result,
                threat_detected=threat_detected,
                threat_type=threat_type,
                user_id=user_id
            )

            return response(200, {
                "id": scan_id,
                "input_type": parsed["input_type"],
                "processed_query": processed_query,
                "parsed": {
                    "method": parsed.get("method"),
                    "path": parsed.get("path"),
                    "query_params": parsed.get("query_params", {})
                },
                "threat_detected": threat_detected,
                "threat_type": threat_type,
                "detection_layer": detection_layer,
                "result": result
            })

        if path == "/api/scans" and http_method == "GET":
            params = event.get("queryStringParameters") or {}
            limit = int(params.get("limit", 50))
            threat_only = params.get("threat_only") == "true"

            scans = get_scans(limit=limit, threat_only=threat_only, user_id=user_id)
            return response(200, {"scans": scans, "count": len(scans)})

        if path.startswith("/api/scans/") and http_method == "GET":
            scan_id = path.split("/")[-1]
            scan_record = get_scan_by_id(scan_id)

            if not scan_record:
                return response(404, {"error": "Scan not found"})

            if scan_record.get("user_id") != user_id:
                return response(403, {"error": "Access denied"})

            return response(200, scan_record)

        if path == "/api/stats" and http_method == "GET":
            stats = get_stats(user_id=user_id)
            return response(200, stats)

        return response(404, {"error": "Not found"})

    except Exception as e:
        return response(500, {"error": str(e)})


def response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(body, cls=DecimalEncoder)
    }

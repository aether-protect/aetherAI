#!/usr/bin/env python3
"""
Aether Protect Security Agent CLI

Command-line interface for local development and testing.
Uses ONNX inference for threat detection.

Usage:
    python earendel_agent.py scan "SELECT * FROM users WHERE id=1"
    python earendel_agent.py analyze "GET /api/users HTTP/1.1"
    python earendel_agent.py --help
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

# Add parent directories to path for imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(SCRIPT_DIR, '..', 'web', 'lambda'))
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from project_config import APP_NAME, APP_VERSION, ONNX_MODEL_FILENAMES

# Try to import ONNX inference
try:
    from model.onnx_inference import run_onnx_inference, load_onnx_model, ONNX_AVAILABLE as _onnx_avail
    ONNX_AVAILABLE = _onnx_avail
except ImportError:
    try:
        # Fallback: try the lambda handler's inference
        sys.path.insert(0, os.path.join(SCRIPT_DIR, '..', 'web', 'lambda'))
        from onnx_handler import run_inference as run_onnx_inference
        ONNX_AVAILABLE = True
    except ImportError:
        ONNX_AVAILABLE = False
        run_onnx_inference = None

# MITRE ATT&CK mapping
MITRE_MAPPING = {
    "sql_injection": ["T1190", "T1059"],
    "xss": ["T1189", "T1059.007"],
    "command_injection": ["T1059", "T1203"],
    "path_traversal": ["T1083", "T1005"],
    "ssrf": ["T1090", "T1071"],
    "xxe": ["T1059", "T1005"],
    "ldap_injection": ["T1087", "T1069"],
    "nosql_injection": ["T1190", "T1059"],
    "malware_signature": ["T1204", "T1105"],
    "red_team_tool": ["T1055", "T1003", "T1059"],
    "network_intrusion": ["T1071", "T1095"],
    "data_exfiltration": ["T1041", "T1567"]
}


def get_model_path() -> str:
    """Find the ONNX model file."""
    locations = []
    for model_name in ONNX_MODEL_FILENAMES:
        locations.extend([
            os.path.join(SCRIPT_DIR, 'model', 'onnx_distilled', model_name),
            os.path.join(SCRIPT_DIR, 'model', model_name),
            os.path.join(SCRIPT_DIR, '..', 'web', 'lambda', model_name),
        ])

    for path in locations:
        if os.path.exists(path):
            return path

    return locations[0]  # Return first as default


def analyze_local(text: str) -> Dict[str, Any]:
    """
    Analyze text for security threats using local ONNX model.

    Args:
        text: Text to analyze

    Returns:
        Analysis result with threat detection info
    """
    if not ONNX_AVAILABLE:
        return {
            "error": "ONNX runtime not available. Install with: pip install onnxruntime",
            "is_threat": False,
            "confidence": 0,
            "threat_type": "error"
        }

    try:
        result = run_onnx_inference(text)
        return result
    except FileNotFoundError as e:
        return {
            "error": f"Model file not found: {e}",
            "is_threat": False,
            "confidence": 0,
            "threat_type": "error",
            "hint": "Download model from GitHub releases or run deploy.sh"
        }
    except Exception as e:
        return {
            "error": str(e),
            "is_threat": False,
            "confidence": 0,
            "threat_type": "error"
        }


def scan(text: str, ip: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Perform a full security scan.

    Args:
        text: Text to scan
        ip: Source IP (for logging)

    Returns:
        Structured scan result
    """
    ml_result = analyze_local(text)

    is_threat = ml_result.get("is_threat", False)
    threat_type = ml_result.get("threat_type", "unknown")
    confidence = ml_result.get("confidence", 0)

    result = {
        "text": text[:100] + "..." if len(text) > 100 else text,
        "analyzed_text": text[:100] + "..." if len(text) > 100 else text,
        "ip": ip,
        "timestamp": datetime.utcnow().isoformat(),
        "ml_result": {
            "is_threat": is_threat,
            "confidence": confidence,
            "threat_type": threat_type,
            "mitre_attack": ml_result.get("mitre_attack", MITRE_MAPPING.get(threat_type, []))
        },
        "decision": {
            "action": "BLOCK" if is_threat else "ALLOW",
            "reason": f"ML detected: {threat_type}" if is_threat else "No threat detected",
            "confidence": confidence
        }
    }

    if ml_result.get("error"):
        result["error"] = ml_result["error"]
        result["decision"]["action"] = "ERROR"
        result["decision"]["reason"] = ml_result["error"]

    return result


def main():
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} Security Agent - ML-powered threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s scan "SELECT * FROM users WHERE id=1 OR 1=1"
    %(prog)s analyze "<script>alert('xss')</script>"
    %(prog)s scan "GET /etc/passwd HTTP/1.1"
        """
    )

    parser.add_argument(
        "command",
        choices=["scan", "analyze", "version", "health"],
        help="Command to execute"
    )

    parser.add_argument(
        "text",
        nargs="?",
        default="",
        help="Text to analyze"
    )

    parser.add_argument(
        "--ip",
        default="127.0.0.1",
        help="Source IP for logging"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Output as JSON (default)"
    )

    args = parser.parse_args()

    if args.command == "version":
        result = {
            "name": f"{APP_NAME} Security Agent",
            "version": APP_VERSION,
            "onnx_available": ONNX_AVAILABLE,
            "model_path": get_model_path() if ONNX_AVAILABLE else None
        }
    elif args.command == "health":
        model_path = get_model_path()
        model_exists = os.path.exists(model_path)
        result = {
            "status": "ok" if ONNX_AVAILABLE and model_exists else "degraded",
            "onnx_available": ONNX_AVAILABLE,
            "model_exists": model_exists,
            "model_path": model_path
        }
    elif args.command in ["scan", "analyze"]:
        if not args.text:
            parser.error(f"'{args.command}' requires text argument")

        if args.command == "scan":
            result = scan(args.text, args.ip)
        else:  # analyze
            result = analyze_local(args.text)
    else:
        result = {"error": f"Unknown command: {args.command}"}

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    # If no args, print help
    if len(sys.argv) == 1:
        print(f"{APP_NAME} Security Agent v{APP_VERSION}")
        print("Usage: python earendel_agent.py <command> [text]")
        print("Commands: scan, analyze, version, health")
        sys.exit(0)

    main()

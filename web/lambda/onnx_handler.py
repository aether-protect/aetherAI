"""
Aether Protect - Unified inference Lambda handler.

Supports both ONNX and SecureBERT backends. Backend is selected via:
  - MODEL_BACKEND env var: "onnx" or "securebert"
  - Auto-detection from model directory contents

API endpoints (unchanged):
  POST /api/scan-onnx  - Run inference on text
  GET  /api/onnx-info  - Get model info
"""

import json
import os
import sys
from typing import Dict, Any

# Add model directory to path for inference_engine import
MODEL_DIR = os.environ.get("MODEL_DIR", "/opt/python")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agent", "model"))

from inference_engine import create_backend, InferenceBackend

# Global backend (loaded once per Lambda container)
_backend: InferenceBackend = None


def get_backend() -> InferenceBackend:
    global _backend
    if _backend is None:
        _backend = create_backend(MODEL_DIR)
    return _backend


def response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body),
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
        # GET /api/onnx-info
        if path == "/api/onnx-info" and http_method == "GET":
            backend = get_backend()
            return response(200, {
                "status": "loaded",
                "backend": backend.backend_name,
                "num_classes": len(backend.threat_types),
                "threat_types": backend.threat_types,
            })

        # POST /api/scan-onnx
        if path == "/api/scan-onnx" and http_method == "POST":
            if not body or not body.get("text"):
                return response(400, {"error": "text field is required"})

            backend = get_backend()
            text = body["text"]
            result = backend.predict(text)

            return response(200, {
                "model": backend.backend_name,
                "input_text": text[:200] + "..." if len(text) > 200 else text,
                "result": result,
                "decision": {
                    "action": "BLOCK" if result["is_threat"] else "ALLOW",
                    "reason": f"{backend.backend_name} detected: {result['threat_type']}"
                    if result["is_threat"]
                    else "No threat detected",
                    "confidence": result["confidence"],
                },
            })

        if http_method == "OPTIONS":
            return response(200, {})

        return response(404, {"error": "Not found"})

    except Exception as e:
        return response(500, {"error": str(e)})


if __name__ == "__main__":
    # Local testing
    os.environ.setdefault("MODEL_DIR", os.path.join(
        os.path.dirname(__file__), "..", "..", "agent", "model", "securebert"))

    test_texts = [
        "SELECT * FROM users WHERE id=1 OR 1=1--",
        "<script>alert('xss')</script>",
        "GET /api/users HTTP/1.1",
        "Hello, this is a normal request",
    ]

    backend = get_backend()
    print(f"Backend: {backend.backend_name}\n")

    for text in test_texts:
        result = backend.predict(text)
        tag = "THREAT" if result["is_threat"] else "BENIGN"
        print(f"[{tag}] {result['threat_type']:<20s} {result['confidence']:5.1%} | {text[:60]}")

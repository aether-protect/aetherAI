"""
Aether Protect - Unified SageMaker Inference Handler.

Supports both ONNX and SecureBERT backends. Backend is auto-detected
from model directory contents, or set via MODEL_BACKEND env var.

SageMaker Interface:
    model_fn   - Load model (auto-detects backend)
    input_fn   - Deserialize JSON input
    predict_fn - Run inference via selected backend
    output_fn  - Serialize JSON output
"""

import json
import os
import sys
from typing import Dict, Any

# Add model module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "model"))

from inference_engine import create_backend, InferenceBackend

_backend: InferenceBackend = None


def model_fn(model_dir: str):
    """Load model — auto-detects ONNX or SecureBERT from directory contents."""
    global _backend
    print(f"Loading model from {model_dir}")
    print(f"Directory contents: {os.listdir(model_dir)}")

    _backend = create_backend(model_dir)
    print(f"Backend: {_backend.backend_name} ({len(_backend.threat_types)} classes)")
    return _backend


def input_fn(request_body: str, request_content_type: str) -> Dict[str, Any]:
    if request_content_type == "application/json":
        return json.loads(request_body)
    raise ValueError(f"Unsupported content type: {request_content_type}")


def predict_fn(input_data: Dict[str, Any], model) -> Dict[str, Any]:
    text = input_data.get("text", "")
    if not text:
        return {"error": "No text provided"}
    return _backend.predict(text)


def output_fn(prediction: Dict[str, Any], accept: str) -> str:
    return json.dumps(prediction)


# Local testing
if __name__ == "__main__":
    model_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    model_fn(model_dir)

    test_texts = [
        "SELECT * FROM users WHERE id=1 OR 1=1--",
        "<script>alert('xss')</script>",
        "GET /api/users HTTP/1.1",
        "Hello, this is a normal request",
    ]

    for text in test_texts:
        result = predict_fn({"text": text}, None)
        tag = "THREAT" if result["is_threat"] else "BENIGN"
        print(f"[{tag}] {result['threat_type']:<20s} {result['confidence']:5.1%} | {text[:60]}")

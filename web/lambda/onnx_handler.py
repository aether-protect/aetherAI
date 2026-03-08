"""Aether Protect ONNX inference Lambda handler."""

import json
import os
import re
import pickle
import sys
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import numpy as np

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import ONNX_MODEL_FILENAMES

# ONNX Runtime
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ort = None
    ONNX_AVAILABLE = False

# Configuration
MODEL_PATH = os.environ.get('MODEL_PATH', '/opt/python/earendel.onnx')
TOKENIZER_PATH = os.environ.get('TOKENIZER_PATH', '/opt/python/tokenizer.pkl')
CONFIG_PATH = os.environ.get('CONFIG_PATH', '/opt/python/config.json')
MAX_SEQ_LEN = int(os.environ.get('MAX_SEQ_LEN', '256'))
MAX_CHAR_LEN = int(os.environ.get('MAX_CHAR_LEN', '512'))
THREAT_THRESHOLD = float(os.environ.get('THREAT_THRESHOLD', '0.35'))

# Threat classification
THREAT_TYPES = [
    "benign", "sql_injection", "xss", "command_injection", "path_traversal",
    "ssrf", "xxe", "ldap_injection", "nosql_injection", "malware_signature",
    "crypto_miner", "red_team_tool", "network_intrusion", "data_exfiltration"
]

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
    "crypto_miner": ["T1496"],
    "red_team_tool": ["T1055", "T1003", "T1059"],
    "network_intrusion": ["T1071", "T1095"],
    "data_exfiltration": ["T1041", "T1567"]
}

# Global model components (loaded once per container)
_session = None
_tokenizer = None
_config = None
_pattern_extractor = None
_is_hybrid = False


class ThreatPatternExtractor:
    """
    Extract 30 hand-crafted threat pattern features aligned with MITRE ATT&CK.
    These features are used alongside the ML model for hybrid detection.
    """

    MITRE_TACTICS = [
        'reconnaissance', 'resource_development', 'initial_access',
        'execution', 'persistence', 'privilege_escalation', 'defense_evasion',
        'credential_access', 'discovery', 'lateral_movement', 'collection',
        'command_and_control', 'exfiltration', 'impact'
    ]

    THREAT_KEYWORDS = [
        'malware', 'trojan', 'backdoor', 'ransomware', 'exploit',
        'payload', 'shellcode', 'dropper', 'rat', 'rootkit',
        'vulnerability', 'attack', 'threat', 'adversary', 'intrusion'
    ]

    PLATFORMS = ['windows', 'linux', 'macos', 'cloud', 'network']

    ATTACK_INDICATORS = [
        'sql', 'xss', 'injection', 'overflow', 'traversal',
        'bypass', 'escalat', 'exfil', 'lateral', 'beacon'
    ]

    def __init__(self):
        self.technique_pattern = re.compile(r'T1\d{3}(?:\.\d{3})?')
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    def extract(self, text: str) -> np.ndarray:
        """
        Extract 30 normalized features from text.
        Returns: numpy array of shape (30,) with values in [0, 1]
        """
        features = []
        text_lower = text.lower()

        # 1-14: MITRE ATT&CK tactics (14 features)
        for tactic in self.MITRE_TACTICS:
            count = text_lower.count(tactic)
            features.append(min(count, 5) / 5.0)

        # 15: Threat keyword count (1 feature)
        threat_count = sum(text_lower.count(kw) for kw in self.THREAT_KEYWORDS)
        features.append(min(threat_count, 10) / 10.0)

        # 16-20: Platform indicators (5 features)
        for platform in self.PLATFORMS:
            count = text_lower.count(platform)
            features.append(min(count, 5) / 5.0)

        # 21: Text length normalized (1 feature)
        features.append(min(len(text) / 1000.0, 1.0))

        # 22: MITRE technique ID count (1 feature)
        technique_count = len(self.technique_pattern.findall(text))
        features.append(min(technique_count, 10) / 10.0)

        # 23: CVE mention count (1 feature)
        cve_count = len(self.cve_pattern.findall(text))
        features.append(min(cve_count, 5) / 5.0)

        # 24: Special character ratio (1 feature)
        special_count = sum(1 for c in text if not c.isalnum() and c != ' ')
        special_ratio = special_count / max(len(text), 1)
        features.append(min(special_ratio * 5, 1.0))

        # 25: Attack indicator count (1 feature)
        attack_count = sum(text_lower.count(ind) for ind in self.ATTACK_INDICATORS)
        features.append(min(attack_count, 10) / 10.0)

        # 26: Hex pattern indicator (1 feature)
        hex_patterns = len(re.findall(r'(?:0x[0-9a-f]+|\\x[0-9a-f]{2})', text_lower))
        features.append(min(hex_patterns, 10) / 10.0)

        # 27: URL encoding indicator (1 feature)
        url_encoded = len(re.findall(r'%[0-9a-f]{2}', text_lower))
        features.append(min(url_encoded, 20) / 20.0)

        # 28: Base64 indicator (1 feature)
        base64_indicator = 1.0 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text) else 0.0
        features.append(base64_indicator)

        # 29: IP address indicator (1 feature)
        ip_count = len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))
        features.append(min(ip_count, 5) / 5.0)

        # 30: Command pattern indicator (1 feature)
        cmd_patterns = len(re.findall(r'(?:;|\||&&|\$\(|`)', text))
        features.append(min(cmd_patterns, 10) / 10.0)

        return np.array(features, dtype=np.float32)


class SimpleTokenizer:
    """Lightweight tokenizer for ONNX inference with character encoding support."""

    def __init__(self, word2idx: Dict[str, int], max_length: int = 256,
                 max_char_length: int = 512):
        self.word2idx = word2idx
        self.max_length = max_length
        self.max_char_length = max_char_length

    def _encode_chars(self, text: str) -> np.ndarray:
        """Encode text to character IDs (ASCII capped at 255)."""
        char_ids = []
        for char in text[:self.max_char_length]:
            char_ids.append(min(ord(char), 255))
        # Pad to max_char_length
        pad_len = self.max_char_length - len(char_ids)
        char_ids += [0] * pad_len
        return np.array([char_ids], dtype=np.int64)

    def encode(self, text: str, return_char_ids: bool = False) -> Dict[str, np.ndarray]:
        """Tokenize text and return numpy arrays for ONNX."""
        tokens = ["[CLS]"] + re.findall(r'\b\w+\b|[^\w\s]', text.lower()) + ["[SEP]"]

        if len(tokens) > self.max_length:
            tokens = tokens[:self.max_length - 1] + ["[SEP]"]

        input_ids = [self.word2idx.get(t, 1) for t in tokens]  # 1 = UNK

        pad_len = self.max_length - len(input_ids)
        input_ids += [0] * pad_len

        result = {
            'input_ids': np.array([input_ids], dtype=np.int64)
        }

        if return_char_ids:
            result['char_ids'] = self._encode_chars(text)

        return result


def load_model():
    """Load ONNX model, tokenizer, and pattern extractor."""
    global _session, _tokenizer, _config, _pattern_extractor, _is_hybrid

    if _session is not None:
        return _session, _tokenizer, _config, _pattern_extractor, _is_hybrid

    if not ONNX_AVAILABLE:
        raise ImportError("onnxruntime not installed")

    # Check paths - try /opt/python/ first (Lambda layer), then local
    model_path = MODEL_PATH
    tokenizer_path = TOKENIZER_PATH
    config_path = CONFIG_PATH

    # For local testing
    if not os.path.exists(model_path):
        local_dir = os.path.dirname(os.path.abspath(__file__))
        # Try FP16 first, then FP32, then default
        for onnx_name in ONNX_MODEL_FILENAMES:
            test_path = os.path.join(local_dir, onnx_name)
            if os.path.exists(test_path):
                model_path = test_path
                break
        tokenizer_path = os.path.join(local_dir, 'tokenizer.pkl')
        config_path = os.path.join(local_dir, 'config.json')

    # Load ONNX model
    _session = ort.InferenceSession(
        model_path,
        providers=['CPUExecutionProvider']
    )

    # Detect if hybrid model (has char_ids and pattern_features inputs)
    input_names = [inp.name for inp in _session.get_inputs()]
    _is_hybrid = 'char_ids' in input_names and 'pattern_features' in input_names

    # Load tokenizer
    with open(tokenizer_path, 'rb') as f:
        tokenizer_data = pickle.load(f)

    max_char_length = tokenizer_data.get('max_char_length', MAX_CHAR_LEN) if _is_hybrid else 0
    _tokenizer = SimpleTokenizer(
        tokenizer_data['word2idx'],
        tokenizer_data.get('max_length', MAX_SEQ_LEN),
        max_char_length
    )

    # Load config
    _config = {}
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            _config = json.load(f)

    # Initialize pattern extractor for hybrid models
    _pattern_extractor = ThreatPatternExtractor() if _is_hybrid else None

    print(f"ONNX model loaded: {model_path}", file=sys.stderr)
    print(f"Hybrid mode: {_is_hybrid}", file=sys.stderr)
    print(f"Precision: {_config.get('precision', 'fp32')}", file=sys.stderr)

    return _session, _tokenizer, _config, _pattern_extractor, _is_hybrid


def softmax(x: np.ndarray) -> np.ndarray:
    """Compute softmax."""
    exp_x = np.exp(x - np.max(x))
    return exp_x / exp_x.sum()


def run_inference(text: str) -> Dict[str, Any]:
    """Run ONNX inference on text using hybrid or simple model."""
    session, tokenizer, config, pattern_extractor, is_hybrid = load_model()

    # Prepare inputs based on model type
    if is_hybrid:
        # Hybrid model: input_ids, char_ids, pattern_features
        encoded = tokenizer.encode(text, return_char_ids=True)
        pattern_features = pattern_extractor.extract(text).reshape(1, -1)

        # Check if FP16 model (pattern_features may need float16)
        precision = config.get('precision', 'fp32')
        if precision == 'fp16':
            pattern_features = pattern_features.astype(np.float16)

        onnx_inputs = {
            'input_ids': encoded['input_ids'],
            'char_ids': encoded['char_ids'],
            'pattern_features': pattern_features
        }
    else:
        # Simple model: input_ids only
        encoded = tokenizer.encode(text, return_char_ids=False)
        onnx_inputs = {'input_ids': encoded['input_ids']}

    # Run inference
    binary_logits, class_logits = session.run(None, onnx_inputs)

    # Process binary classification
    binary_probs = softmax(binary_logits[0])
    is_threat = bool(binary_probs[1] > THREAT_THRESHOLD)
    confidence = float(binary_probs[1])

    # Process multi-class
    class_probs = softmax(class_logits[0])
    predicted_class = int(np.argmax(class_probs))
    threat_type = THREAT_TYPES[predicted_class] if is_threat else "benign"

    # Get MITRE mapping
    mitre_attack = MITRE_MAPPING.get(threat_type, [])

    return {
        "is_threat": is_threat,
        "confidence": confidence,
        "threat_type": threat_type,
        "mitre_attack": mitre_attack,
        "class_probabilities": {
            THREAT_TYPES[i]: float(class_probs[i])
            for i in range(len(THREAT_TYPES))
        },
        "model_info": {
            "hybrid": is_hybrid,
            "precision": config.get('precision', 'fp32')
        }
    }


def get_model_info() -> Dict[str, Any]:
    """Get information about the loaded ONNX model."""
    try:
        session, tokenizer, config, pattern_extractor, is_hybrid = load_model()

        # Get input/output info
        inputs = [{"name": inp.name, "shape": inp.shape} for inp in session.get_inputs()]
        outputs = [{"name": out.name, "shape": out.shape} for out in session.get_outputs()]

        return {
            "status": "loaded",
            "onnx_available": ONNX_AVAILABLE,
            "config": config,
            "vocab_size": len(tokenizer.word2idx),
            "max_seq_len": tokenizer.max_length,
            "max_char_len": tokenizer.max_char_length,
            "inputs": inputs,
            "outputs": outputs,
            "threat_types": THREAT_TYPES,
            "hybrid_mode": is_hybrid,
            "precision": config.get('precision', 'fp32'),
            "char_cnn_enabled": is_hybrid,
            "pattern_features_enabled": is_hybrid
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "onnx_available": ONNX_AVAILABLE
        }


def response(status_code: int, body: Any) -> Dict[str, Any]:
    """Build API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(body)
    }


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """Main Lambda handler for ONNX inference."""
    http_method = event.get("httpMethod", "GET")
    path = event.get("path", "")
    body = event.get("body")

    # Parse body if present
    if body and isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass

    try:
        # GET /api/onnx-info
        if path == "/api/onnx-info" and http_method == "GET":
            info = get_model_info()
            return response(200, info)

        # POST /api/scan-onnx
        if path == "/api/scan-onnx" and http_method == "POST":
            if not body or not body.get("text"):
                return response(400, {"error": "text field is required"})

            text = body["text"]

            # Run ONNX inference
            result = run_inference(text)

            return response(200, {
                "model": "onnx",
                "input_text": text[:200] + "..." if len(text) > 200 else text,
                "result": result,
                "decision": {
                    "action": "BLOCK" if result["is_threat"] else "ALLOW",
                    "reason": f"ONNX detected: {result['threat_type']}" if result["is_threat"] else "No threat detected",
                    "confidence": result["confidence"]
                }
            })

        # OPTIONS (CORS preflight)
        if http_method == "OPTIONS":
            return response(200, {})

        return response(404, {"error": "Not found"})

    except Exception as e:
        return response(500, {"error": str(e)})


# For local testing
if __name__ == "__main__":
    # Test locally
    test_texts = [
        "SELECT * FROM users WHERE id=1",
        "GET /api/users HTTP/1.1",
        "<script>alert('xss')</script>",
        "Hello, this is a normal request"
    ]

    print("Testing ONNX inference locally...\n")

    for text in test_texts:
        try:
            result = run_inference(text)
            print(f"Input: {text[:50]}...")
            print(f"  Threat: {result['is_threat']}")
            print(f"  Type: {result['threat_type']}")
            print(f"  Confidence: {result['confidence']:.3f}")
            print()
        except Exception as e:
            print(f"Error: {e}")

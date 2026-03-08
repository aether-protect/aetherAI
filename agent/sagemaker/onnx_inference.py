"""
Aether Protect SageMaker ONNX Inference Handler

Loads and runs the ONNX model for threat detection.

SageMaker Interface:
    model_fn  - Load ONNX model from model directory
    input_fn  - Deserialize JSON input
    predict_fn - Run ONNX inference
    output_fn - Serialize JSON output
"""

import os
import json
import re
import pickle
from typing import Dict, Any, List
from pathlib import Path
import sys

import numpy as np
import onnxruntime as ort

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import ONNX_MODEL_FILENAMES

# Global model components
model_session = None
tokenizer = None
pattern_extractor = None
config = None

# Threat classification constants
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
    "red_team_tool": ["T1055", "T1003", "T1059"],
    "network_intrusion": ["T1071", "T1095"],
    "data_exfiltration": ["T1041", "T1567"]
}


class ThreatPatternExtractor:
    """
    Extract 30 hand-crafted threat pattern features aligned with MITRE ATT&CK.
    This is feature engineering, not neural network architecture.
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
        """Extract 30 normalized features from text."""
        features = []
        text_lower = text.lower()

        # 1-14: MITRE ATT&CK tactics
        for tactic in self.MITRE_TACTICS:
            count = text_lower.count(tactic)
            features.append(min(count, 5) / 5.0)

        # 15: Threat keyword count
        threat_count = sum(text_lower.count(kw) for kw in self.THREAT_KEYWORDS)
        features.append(min(threat_count, 10) / 10.0)

        # 16-20: Platform indicators
        for platform in self.PLATFORMS:
            count = text_lower.count(platform)
            features.append(min(count, 5) / 5.0)

        # 21: Text length normalized
        features.append(min(len(text) / 1000.0, 1.0))

        # 22: MITRE technique ID count
        technique_count = len(self.technique_pattern.findall(text))
        features.append(min(technique_count, 10) / 10.0)

        # 23: CVE mention count
        cve_count = len(self.cve_pattern.findall(text))
        features.append(min(cve_count, 5) / 5.0)

        # 24: Special character ratio
        special_count = sum(1 for c in text if not c.isalnum() and c != ' ')
        special_ratio = special_count / max(len(text), 1)
        features.append(min(special_ratio * 5, 1.0))

        # 25: Attack indicator count
        attack_count = sum(text_lower.count(ind) for ind in self.ATTACK_INDICATORS)
        features.append(min(attack_count, 10) / 10.0)

        # 26: Hex pattern indicator
        hex_patterns = len(re.findall(r'(?:0x[0-9a-f]+|\\x[0-9a-f]{2})', text_lower))
        features.append(min(hex_patterns, 10) / 10.0)

        # 27: URL encoding indicator
        url_encoded = len(re.findall(r'%[0-9a-f]{2}', text_lower))
        features.append(min(url_encoded, 20) / 20.0)

        # 28: Base64 indicator
        base64_indicator = 1.0 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text) else 0.0
        features.append(base64_indicator)

        # 29: IP address indicator
        ip_count = len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))
        features.append(min(ip_count, 5) / 5.0)

        # 30: Command pattern indicator
        cmd_patterns = len(re.findall(r'(?:;|\||&&|\$\(|`)', text))
        features.append(min(cmd_patterns, 10) / 10.0)

        return np.array(features, dtype=np.float32)


class SimpleTokenizer:
    """Simple tokenizer for ONNX inference."""

    def __init__(self, word2idx: Dict[str, int], max_length: int = 256,
                 max_char_length: int = 512):
        self.word2idx = word2idx
        self.max_length = max_length
        self.max_char_length = max_char_length

    def _encode_chars(self, text: str) -> np.ndarray:
        """Encode text to character IDs."""
        char_ids = []
        for char in text[:self.max_char_length]:
            char_ids.append(min(ord(char), 255))
        pad_len = self.max_char_length - len(char_ids)
        char_ids += [0] * pad_len
        return np.array([char_ids], dtype=np.int64)

    def encode(self, text: str) -> Dict[str, np.ndarray]:
        """Tokenize text and return numpy arrays for ONNX."""
        tokens = ["[CLS]"] + re.findall(r'\b\w+\b|[^\w\s]', text.lower()) + ["[SEP]"]

        if len(tokens) > self.max_length:
            tokens = tokens[:self.max_length - 1] + ["[SEP]"]

        input_ids = [self.word2idx.get(t, 1) for t in tokens]
        pad_len = self.max_length - len(input_ids)
        input_ids += [0] * pad_len

        return {
            'input_ids': np.array([input_ids], dtype=np.int64),
            'char_ids': self._encode_chars(text)
        }


# ============================================================================
# SAGEMAKER HANDLERS
# ============================================================================

def model_fn(model_dir: str):
    """Load ONNX model from the model directory."""
    global model_session, tokenizer, pattern_extractor, config

    print(f"Loading ONNX model from {model_dir}")
    print(f"Directory contents: {os.listdir(model_dir)}")

    # Find ONNX model file
    onnx_path = None
    for name in ONNX_MODEL_FILENAMES:
        test_path = os.path.join(model_dir, name)
        if os.path.exists(test_path):
            onnx_path = test_path
            break

    if not onnx_path:
        raise FileNotFoundError(f"No ONNX model found in {model_dir}")

    # Load ONNX model
    model_session = ort.InferenceSession(
        onnx_path,
        providers=['CPUExecutionProvider']
    )
    print(f"ONNX model loaded: {onnx_path}")

    # Print model info
    for inp in model_session.get_inputs():
        print(f"  Input: {inp.name} {inp.shape}")
    for out in model_session.get_outputs():
        print(f"  Output: {out.name} {out.shape}")

    # Load config
    config_path = os.path.join(model_dir, 'config.json')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
        print(f"Config loaded: vocab_size={config.get('vocab_size')}")

    # Load tokenizer
    tokenizer_path = os.path.join(model_dir, 'tokenizer.pkl')
    with open(tokenizer_path, 'rb') as f:
        data = pickle.load(f)

    tokenizer = SimpleTokenizer(
        data['word2idx'],
        data.get('max_length', 256),
        data.get('max_char_length', 512)
    )
    print(f"Tokenizer loaded: {len(data['word2idx'])} tokens")

    # Initialize pattern extractor
    pattern_extractor = ThreatPatternExtractor()
    print("Pattern extractor initialized (30 features)")

    return model_session


def input_fn(request_body: str, request_content_type: str) -> Dict[str, Any]:
    """Deserialize input data."""
    if request_content_type == 'application/json':
        return json.loads(request_body)
    raise ValueError(f'Unsupported content type: {request_content_type}')


def predict_fn(input_data: Dict[str, Any], model) -> Dict[str, Any]:
    """Run ONNX inference on input data."""
    global tokenizer, pattern_extractor

    text = input_data.get('text', '')
    if not text:
        return {"error": "No text provided"}

    # Tokenize
    encoded = tokenizer.encode(text)

    # Extract pattern features
    pattern_features = pattern_extractor.extract(text).reshape(1, -1)

    # Run ONNX inference
    binary_logits, class_logits = model.run(
        None,
        {
            'input_ids': encoded['input_ids'],
            'char_ids': encoded['char_ids'],
            'pattern_features': pattern_features
        }
    )

    # Process binary classification
    binary_probs = softmax(binary_logits[0])
    binary_is_threat = bool(binary_probs[1] > 0.5)
    binary_confidence = float(binary_probs[1])

    # Process multi-class
    class_probs = softmax(class_logits[0])
    predicted_class = int(np.argmax(class_probs))
    class_confidence = float(class_probs[predicted_class])

    # Final decision
    multiclass_threat_type = THREAT_TYPES[predicted_class]
    multiclass_is_threat = predicted_class != 0 and class_confidence > 0.9

    if multiclass_is_threat:
        is_threat = True
        threat_type = multiclass_threat_type
        confidence = class_confidence
    else:
        is_threat = binary_is_threat
        threat_type = multiclass_threat_type if is_threat else "benign"
        confidence = binary_confidence

    # Get top 3 threats
    top_k = min(3, len(THREAT_TYPES))
    top_indices = np.argsort(class_probs)[-top_k:][::-1]
    top_threats = [
        {"type": THREAT_TYPES[i], "confidence": float(class_probs[i])}
        for i in top_indices
    ]

    return {
        "is_threat": is_threat,
        "confidence": confidence,
        "threat_type": threat_type,
        "threat_type_confidence": class_confidence,
        "top_threats": top_threats,
        "mitre_attack": MITRE_MAPPING.get(threat_type, []),
        "recommendations": get_recommendations(threat_type),
        "root_cause": get_root_cause(threat_type),
        "model_info": {
            "architecture": "onnx",
            "char_cnn_enabled": True,
            "pattern_features_enabled": True
        }
    }


def output_fn(prediction: Dict[str, Any], accept: str) -> str:
    """Serialize prediction output."""
    return json.dumps(prediction)


def softmax(x: np.ndarray) -> np.ndarray:
    """Compute softmax."""
    exp_x = np.exp(x - np.max(x))
    return exp_x / exp_x.sum()


def get_recommendations(threat_type: str) -> List[str]:
    """Get security recommendations based on threat type."""
    recommendations = {
        "sql_injection": [
            "Use parameterized queries or prepared statements",
            "Implement input validation and sanitization",
            "Enable AWS WAF SQL injection rule set"
        ],
        "xss": [
            "Implement Content Security Policy (CSP) headers",
            "Sanitize and encode all user input before rendering",
            "Enable AWS WAF XSS rule set"
        ],
        "command_injection": [
            "Avoid using shell commands with user input",
            "Use language-specific APIs instead of shell execution",
            "Implement strict input validation with allowlists"
        ],
        "path_traversal": [
            "Validate and canonicalize file paths",
            "Use allowlists for permitted file locations",
            "Implement chroot jails for file access"
        ],
        "ssrf": [
            "Validate and sanitize all URLs before making requests",
            "Block access to internal IP ranges",
            "Use allowlists for permitted external domains"
        ],
        "xxe": [
            "Disable external entity processing in XML parsers",
            "Use less complex data formats like JSON when possible",
            "Validate and sanitize XML input"
        ],
        "ldap_injection": [
            "Use parameterized LDAP queries",
            "Escape special characters in LDAP filters",
            "Implement input validation with strict allowlists"
        ],
        "nosql_injection": [
            "Use parameterized queries for NoSQL databases",
            "Validate and sanitize all user input",
            "Disable JavaScript execution in MongoDB queries"
        ],
        "malware_signature": [
            "Quarantine and analyze the detected payload",
            "Scan all systems for similar signatures",
            "Update antivirus/EDR definitions"
        ],
        "red_team_tool": [
            "Implement endpoint detection and response (EDR)",
            "Monitor for lateral movement indicators",
            "Restrict PowerShell execution policies"
        ],
        "network_intrusion": [
            "Implement network segmentation",
            "Enable IDS/IPS monitoring",
            "Review firewall rules and access controls"
        ],
        "data_exfiltration": [
            "Implement DLP (Data Loss Prevention) controls",
            "Monitor and restrict outbound data transfers",
            "Enable logging for sensitive data access"
        ],
        "benign": ["Continue monitoring for anomalies"]
    }
    return recommendations.get(threat_type, ["Review security logs"])


def get_root_cause(threat_type: str) -> str:
    """Get root cause explanation based on threat type."""
    root_causes = {
        "sql_injection": "SQL injection patterns detected",
        "xss": "Cross-site scripting patterns detected",
        "command_injection": "Command injection patterns detected",
        "path_traversal": "Path traversal patterns detected",
        "ssrf": "Server-Side Request Forgery indicators detected",
        "xxe": "XML External Entity injection patterns detected",
        "ldap_injection": "LDAP injection patterns detected",
        "nosql_injection": "NoSQL injection patterns detected",
        "malware_signature": "Known malware signatures detected",
        "red_team_tool": "Red team tool signatures detected",
        "network_intrusion": "Network intrusion indicators detected",
        "data_exfiltration": "Data exfiltration indicators detected",
        "benign": "No threat patterns detected"
    }
    return root_causes.get(threat_type, "Threat detected by ML model")


# ============================================================================
# LOCAL TESTING
# ============================================================================

if __name__ == "__main__":
    import sys

    # For local testing, point to model directory
    model_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    print("=" * 60)
    print("Testing ONNX SageMaker Inference Handler")
    print("=" * 60)

    # Load model
    model = model_fn(model_dir)

    # Test cases
    test_texts = [
        "SELECT * FROM users WHERE id=1 OR 1=1--",
        "<script>alert('xss')</script>",
        "GET /api/users HTTP/1.1 Host: example.com",
        "Hello, this is a normal request"
    ]

    for text in test_texts:
        input_data = {"text": text}
        result = predict_fn(input_data, model)

        print(f"\nInput: {text[:50]}...")
        print(f"  Threat: {result['is_threat']}")
        print(f"  Type: {result['threat_type']}")
        print(f"  Confidence: {result['confidence']:.3f}")

    print("\n" + "=" * 60)
    print("Test complete!")

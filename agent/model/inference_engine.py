# Copyright (c) 2026 Aether Protect Contributors. MIT License. See license.txt.
"""
Aether Protect - Inference Engine

ONNX-based threat detection backend:
  - Custom Transformer+CharCNN ONNX model (fast, CPU-optimized)
"""

import json
import os
import re
import sys
from abc import ABC, abstractmethod
from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

ONNX_THREAT_TYPES = [
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
    "data_exfiltration": ["T1041", "T1567"],
}

RECOMMENDATIONS = {
    "sql_injection": [
        "Use parameterized queries or prepared statements",
        "Implement input validation and sanitization",
        "Enable AWS WAF SQL injection rule set",
    ],
    "xss": [
        "Implement Content Security Policy (CSP) headers",
        "Sanitize and encode all user input before rendering",
        "Enable AWS WAF XSS rule set",
    ],
    "command_injection": [
        "Avoid using shell commands with user input",
        "Use language-specific APIs instead of shell execution",
        "Implement strict input validation with allowlists",
    ],
    "path_traversal": [
        "Validate and canonicalize file paths",
        "Use allowlists for permitted file locations",
        "Implement chroot jails for file access",
    ],
    "ssrf": [
        "Validate and sanitize all URLs before making requests",
        "Block access to internal IP ranges",
        "Use allowlists for permitted external domains",
    ],
    "xxe": [
        "Disable external entity processing in XML parsers",
        "Use less complex data formats like JSON when possible",
        "Validate and sanitize XML input",
    ],
    "ldap_injection": [
        "Use parameterized LDAP queries",
        "Escape special characters in LDAP filters",
        "Implement input validation with strict allowlists",
    ],
    "nosql_injection": [
        "Use parameterized queries for NoSQL databases",
        "Validate and sanitize all user input",
        "Disable JavaScript execution in MongoDB queries",
    ],
    "malware_signature": [
        "Quarantine and analyze the detected payload",
        "Scan all systems for similar signatures",
        "Update antivirus/EDR definitions",
    ],
    "crypto_miner": [
        "Block mining pool connections at the firewall",
        "Monitor CPU usage for abnormal spikes",
        "Scan for unauthorized mining software",
    ],
    "red_team_tool": [
        "Implement endpoint detection and response (EDR)",
        "Monitor for lateral movement indicators",
        "Restrict PowerShell execution policies",
    ],
    "network_intrusion": [
        "Implement network segmentation",
        "Enable IDS/IPS monitoring",
        "Review firewall rules and access controls",
    ],
    "data_exfiltration": [
        "Implement DLP (Data Loss Prevention) controls",
        "Monitor and restrict outbound data transfers",
        "Enable logging for sensitive data access",
    ],
    "benign": ["Continue monitoring for anomalies"],
}

ROOT_CAUSES = {
    "sql_injection": "SQL injection patterns detected in input",
    "xss": "Cross-site scripting patterns detected",
    "command_injection": "Command injection patterns detected",
    "path_traversal": "Path traversal patterns detected",
    "ssrf": "Server-Side Request Forgery indicators detected",
    "xxe": "XML External Entity injection patterns detected",
    "ldap_injection": "LDAP injection patterns detected",
    "nosql_injection": "NoSQL injection patterns detected",
    "malware_signature": "Known malware signatures detected",
    "crypto_miner": "Cryptocurrency mining activity detected",
    "red_team_tool": "Red team tool signatures detected",
    "network_intrusion": "Network intrusion indicators detected",
    "data_exfiltration": "Data exfiltration indicators detected",
    "benign": "No threat patterns detected",
}


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class InferenceBackend(ABC):
    """Common interface for inference backends."""

    @abstractmethod
    def load(self, model_dir: str) -> None:
        """Load model artifacts from directory."""

    @abstractmethod
    def predict(self, text: str) -> Dict[str, Any]:
        """Run inference and return standardized result."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Return backend identifier."""

    @property
    @abstractmethod
    def threat_types(self) -> List[str]:
        """Return list of threat type labels."""

    def _build_result(self, is_threat: bool, threat_type: str, confidence: float,
                      top_threats: List[Dict] = None) -> Dict[str, Any]:
        """Build standardized result dict."""
        return {
            "is_threat": is_threat,
            "confidence": confidence,
            "threat_type": threat_type,
            "threat_type_confidence": confidence,
            "top_threats": top_threats or [],
            "mitre_attack": MITRE_MAPPING.get(threat_type, []),
            "recommendations": RECOMMENDATIONS.get(threat_type, ["Review security logs"]),
            "root_cause": ROOT_CAUSES.get(threat_type, "Threat detected by ML model"),
            "model_info": {
                "backend": self.backend_name,
                "num_classes": len(self.threat_types),
            },
        }


# ---------------------------------------------------------------------------
# ONNX Backend
# ---------------------------------------------------------------------------

class OnnxBackend(InferenceBackend):
    """Custom Transformer+CharCNN ONNX model."""

    ONNX_FILENAMES = (
        "aether_protect_fp16.onnx", "aether_protect_fp32.onnx", "aether_protect.onnx",
        "earendel_fp16.onnx", "earendel_fp32.onnx", "earendel.onnx", "model.onnx",
    )

    def __init__(self):
        self._session = None
        self._tokenizer = None
        self._pattern_extractor = None
        self._is_hybrid = False
        self._config = {}

    @property
    def backend_name(self) -> str:
        return "onnx"

    @property
    def threat_types(self) -> List[str]:
        return ONNX_THREAT_TYPES

    def load(self, model_dir: str) -> None:
        import pickle
        import numpy as np
        import onnxruntime as ort

        # Find ONNX file
        onnx_path = None
        for name in self.ONNX_FILENAMES:
            p = os.path.join(model_dir, name)
            if os.path.exists(p):
                onnx_path = p
                break
        if not onnx_path:
            raise FileNotFoundError(f"No ONNX model found in {model_dir}")

        self._session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])

        input_names = [inp.name for inp in self._session.get_inputs()]
        self._is_hybrid = "char_ids" in input_names and "pattern_features" in input_names

        # Tokenizer
        tok_path = os.path.join(model_dir, "tokenizer.pkl")
        with open(tok_path, "rb") as f:
            tok_data = pickle.load(f)
        self._tokenizer = tok_data

        # Config
        cfg_path = os.path.join(model_dir, "config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path) as f:
                self._config = json.load(f)

        # Pattern extractor
        if self._is_hybrid:
            self._pattern_extractor = _ThreatPatternExtractor()

        print(f"ONNX backend loaded: {onnx_path} (hybrid={self._is_hybrid})", file=sys.stderr)

    def predict(self, text: str) -> Dict[str, Any]:
        import numpy as np

        w2i = self._tokenizer["word2idx"]
        max_len = self._tokenizer.get("max_length", 256)
        max_char = self._tokenizer.get("max_char_length", 512)

        # Tokenize
        tokens = ["[CLS]"] + re.findall(r'\b\w+\b|[^\w\s]', text.lower()) + ["[SEP]"]
        if len(tokens) > max_len:
            tokens = tokens[:max_len - 1] + ["[SEP]"]
        ids = [w2i.get(t, 1) for t in tokens] + [0] * (max_len - len(tokens))
        input_ids = np.array([ids[:max_len]], dtype=np.int64)

        inputs = {"input_ids": input_ids}

        if self._is_hybrid:
            char_ids = [min(ord(c), 255) for c in text[:max_char]]
            char_ids += [0] * (max_char - len(char_ids))
            inputs["char_ids"] = np.array([char_ids], dtype=np.int64)

            pf = self._pattern_extractor.extract(text).reshape(1, -1)
            precision = self._config.get("precision", "fp32")
            if precision == "fp16":
                pf = pf.astype(np.float16)
            inputs["pattern_features"] = pf

        binary_logits, class_logits = self._session.run(None, inputs)

        binary_probs = _softmax(binary_logits[0])
        class_probs = _softmax(class_logits[0])
        pred_class = int(np.argmax(class_probs))
        class_conf = float(class_probs[pred_class])

        multi_threat = pred_class != 0 and class_conf > 0.9
        if multi_threat:
            is_threat = True
            threat_type = ONNX_THREAT_TYPES[pred_class]
            confidence = class_conf
        else:
            is_threat = bool(binary_probs[1] > 0.5)
            threat_type = ONNX_THREAT_TYPES[pred_class] if is_threat else "benign"
            confidence = float(binary_probs[1]) if is_threat else class_conf

        top_k = min(3, len(ONNX_THREAT_TYPES))
        top_idx = np.argsort(class_probs)[-top_k:][::-1]
        top_threats = [{"type": ONNX_THREAT_TYPES[i], "confidence": float(class_probs[i])} for i in top_idx]

        return self._build_result(is_threat, threat_type, confidence, top_threats)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def detect_backend(model_dir: str) -> str:
    """Detect backend from model directory contents."""
    for name in OnnxBackend.ONNX_FILENAMES:
        if os.path.exists(os.path.join(model_dir, name)):
            return "onnx"

    raise FileNotFoundError(f"No recognized model artifacts in {model_dir}")


def create_backend(model_dir: str, backend: str = None) -> InferenceBackend:
    """Create and load the inference backend.

    Args:
        model_dir: Path to model artifacts.
        backend: "onnx" or None for auto-detection.
    """
    if backend is None:
        backend = os.environ.get("MODEL_BACKEND", "").lower()
    if not backend:
        backend = detect_backend(model_dir)

    if backend == "onnx":
        engine = OnnxBackend()
    else:
        raise ValueError(f"Unknown backend: {backend}. Use 'onnx'.")

    engine.load(model_dir)
    return engine


# ---------------------------------------------------------------------------
# Helpers (shared)
# ---------------------------------------------------------------------------

def _softmax(x):
    import numpy as np
    e = np.exp(x - np.max(x))
    return e / e.sum()


class _ThreatPatternExtractor:
    """Extract 30 hand-crafted features for ONNX hybrid model."""

    MITRE_TACTICS = [
        'reconnaissance', 'resource_development', 'initial_access', 'execution',
        'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
        'discovery', 'lateral_movement', 'collection', 'command_and_control',
        'exfiltration', 'impact',
    ]
    THREAT_KEYWORDS = [
        'malware', 'trojan', 'backdoor', 'ransomware', 'exploit', 'payload',
        'shellcode', 'dropper', 'rat', 'rootkit', 'vulnerability', 'attack',
        'threat', 'adversary', 'intrusion',
    ]
    PLATFORMS = ['windows', 'linux', 'macos', 'cloud', 'network']
    ATTACK_INDICATORS = [
        'sql', 'xss', 'injection', 'overflow', 'traversal', 'bypass',
        'escalat', 'exfil', 'lateral', 'beacon',
    ]

    def __init__(self):
        self._tech = re.compile(r'T1\d{3}(?:\.\d{3})?')
        self._cve = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    def extract(self, text: str):
        import numpy as np
        f = []
        tl = text.lower()
        for t in self.MITRE_TACTICS: f.append(min(tl.count(t), 5) / 5.0)
        f.append(min(sum(tl.count(k) for k in self.THREAT_KEYWORDS), 10) / 10.0)
        for p in self.PLATFORMS: f.append(min(tl.count(p), 5) / 5.0)
        f.append(min(len(text) / 1000.0, 1.0))
        f.append(min(len(self._tech.findall(text)), 10) / 10.0)
        f.append(min(len(self._cve.findall(text)), 5) / 5.0)
        sc = sum(1 for c in text if not c.isalnum() and c != ' ')
        f.append(min(sc / max(len(text), 1) * 5, 1.0))
        f.append(min(sum(tl.count(i) for i in self.ATTACK_INDICATORS), 10) / 10.0)
        f.append(min(len(re.findall(r'(?:0x[0-9a-f]+|\\x[0-9a-f]{2})', tl)), 10) / 10.0)
        f.append(min(len(re.findall(r'%[0-9a-f]{2}', tl)), 20) / 20.0)
        f.append(1.0 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text) else 0.0)
        f.append(min(len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)), 5) / 5.0)
        f.append(min(len(re.findall(r'(?:;|\||&&|\$\(|`)', text)), 10) / 10.0)
        return np.array(f, dtype=np.float32)

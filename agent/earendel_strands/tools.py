"""
Aether Protect agent tools - Strands @tool decorated functions.

These tools are available to the Strands agent for security analysis.
"""

import os
import sys
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from strands import tool
from scanner.scanner import analyze_with_sagemaker, scan, check_waf


@tool
def scan_threat(text: str) -> Dict[str, Any]:
    """
    Analyze text for security threats using the Aether Protect ML model.

    Use this tool to detect potential security threats in:
    - HTTP requests
    - SQL queries
    - Log entries
    - Network traffic
    - Shell commands
    - Any suspicious text

    Args:
        text: The text to analyze for security threats

    Returns:
        Analysis result containing:
        - is_threat: Whether a threat was detected
        - confidence: Confidence score (0-1)
        - threat_type: Type of threat (sql_injection, xss, etc.)
        - mitre_attack: List of MITRE ATT&CK technique IDs
        - recommendations: Security recommendations
        - root_cause: Explanation of why this is/isn't a threat
    """
    return analyze_with_sagemaker(text)


@tool
def full_scan(text: str, source_ip: str = "unknown") -> Dict[str, Any]:
    """
    Perform a full security scan with structured output.

    Similar to scan_threat but returns a more structured result
    with timestamp, IP tracking, and decision metadata.

    Args:
        text: The text to scan for security threats
        source_ip: Optional source IP for logging/tracking

    Returns:
        Structured scan result with:
        - text: The analyzed text (truncated)
        - ip: Source IP
        - timestamp: When the scan was performed
        - ml_result: Detailed ML analysis
        - decision: ALLOW or BLOCK with reason
    """
    return scan(text, ip=source_ip)


@tool
def explain_mitre_technique(technique_id: str) -> str:
    """
    Explain a MITRE ATT&CK technique.

    Args:
        technique_id: MITRE technique ID (e.g., T1190, T1059)

    Returns:
        Explanation of the technique
    """
    techniques = {
        "T1190": "Exploit Public-Facing Application: Adversaries exploit vulnerabilities in internet-facing systems to gain initial access.",
        "T1059": "Command and Scripting Interpreter: Adversaries abuse command-line interfaces and scripting languages to execute commands.",
        "T1059.007": "JavaScript: Adversaries abuse JavaScript for execution, often in XSS attacks.",
        "T1189": "Drive-by Compromise: Adversaries gain access through users visiting compromised websites.",
        "T1203": "Exploitation for Client Execution: Adversaries exploit software vulnerabilities to execute code.",
        "T1083": "File and Directory Discovery: Adversaries enumerate files and directories to find sensitive data.",
        "T1005": "Data from Local System: Adversaries search local system sources for data of interest.",
        "T1552": "Unsecured Credentials: Adversaries search for insecurely stored credentials.",
        "T1055": "Process Injection: Adversaries inject code into processes to evade detection.",
        "T1003": "OS Credential Dumping: Adversaries dump credentials from the operating system.",
        "T1204": "User Execution: Adversaries rely on users to execute malicious code.",
        "T1046": "Network Service Discovery: Adversaries scan for running services on remote hosts.",
        "T1595": "Active Scanning: Adversaries scan victim infrastructure to gather information.",
    }
    return techniques.get(technique_id, f"Unknown technique: {technique_id}. Refer to attack.mitre.org for details.")


@tool
def waf_check(payload: str) -> Dict[str, Any]:
    """
    Test a payload against real AWS WAF managed rules (Layer 2 defense).

    Use this tool as a second layer of defense when the ML model (scan_threat)
    says the input is benign. AWS WAF checks for:
    - SQL Injection patterns
    - Cross-Site Scripting (XSS)
    - Known bad inputs (Log4j, etc.)
    - Path traversal attacks
    - OS command injection

    IMPORTANT: Always use scan_threat first. Only use waf_check when:
    1. scan_threat says the input is NOT a threat
    2. You want to double-check with AWS WAF rules

    Args:
        payload: The text/payload to test against WAF rules

    Returns:
        WAF check result containing:
        - would_block: Whether AWS WAF would block this payload
        - waf_response: HTTP response details
        - matched_rule: Which WAF rule matched (if blocked)
        - rule_group: The AWS Managed Rule Group that matched
    """
    return check_waf(payload)

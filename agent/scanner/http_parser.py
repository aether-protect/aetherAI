"""
HTTP/Curl Request Parser for Aether Protect

Parses raw HTTP requests and curl commands to extract
text components for security threat analysis.
"""

import re
import shlex
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, unquote


# Headers that are interesting for security analysis
INTERESTING_HEADERS = {
    'authorization', 'x-auth-token', 'x-api-key', 'api-key',
    'user-agent', 'x-forwarded-for', 'x-real-ip',
    'referer', 'origin', 'cookie', 'content-type',
    'x-custom-header', 'x-requested-with'
}


class ParsedRequest:
    """Structured representation of a parsed HTTP request or curl command."""

    def __init__(self):
        self.method: Optional[str] = None
        self.path: Optional[str] = None
        self.query_params: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.body: Optional[str] = None
        self.client_ip: Optional[str] = None
        self.raw_input: str = ""
        self.input_type: str = "raw"

    @property
    def combined_text(self) -> str:
        """
        Combine all security-relevant fields into a single text string
        for threat analysis.
        """
        parts = []

        # Path (may contain path traversal)
        if self.path:
            parts.append(self.path)

        # Query parameters (common injection point)
        for key, value in self.query_params.items():
            parts.append(f"{key}={value}")

        # Interesting headers
        for name, value in self.headers.items():
            if name.lower() in INTERESTING_HEADERS:
                parts.append(f"{name}: {value}")

        # Body (POST data, JSON payloads)
        if self.body:
            parts.append(self.body)

        return " ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "method": self.method,
            "path": self.path,
            "query_params": self.query_params,
            "headers": self.headers,
            "body": self.body,
            "client_ip": self.client_ip,
            "input_type": self.input_type,
            "combined_text": self.combined_text
        }


def detect_input_format(text: str) -> str:
    """
    Detect the format of user input.

    Returns:
        "http" - Raw HTTP request
        "curl" - curl command
        "raw"  - Plain text (pass directly to agent)
    """
    stripped = text.strip()
    lower = stripped.lower()

    # Check for curl command
    if lower.startswith('curl ') or lower.startswith('curl\t'):
        return "curl"

    # Check for HTTP request line
    http_methods = ('get ', 'post ', 'put ', 'delete ', 'patch ', 'head ', 'options ')
    if any(lower.startswith(m) for m in http_methods):
        return "http"

    # Check for HTTP version string anywhere
    if 'http/1.' in lower or 'http/2' in lower:
        return "http"

    return "raw"


def parse_http_request(raw: str) -> ParsedRequest:
    """
    Parse a raw HTTP request.

    Example input:
        GET /api/users?id=1 HTTP/1.1
        Host: example.com
        Authorization: Bearer token123

        {"data": "test"}

    Returns:
        ParsedRequest with extracted components
    """
    result = ParsedRequest()
    result.raw_input = raw
    result.input_type = "http"

    lines = raw.split('\n')
    lines = [line.rstrip('\r') for line in lines]

    if not lines:
        return result

    # Parse request line: METHOD /path?query HTTP/1.1
    request_line = lines[0]
    request_match = re.match(r'^(\w+)\s+([^\s]+)(?:\s+HTTP/[\d.]+)?', request_line, re.IGNORECASE)

    if request_match:
        result.method = request_match.group(1).upper()
        full_path = request_match.group(2)

        # Split path and query string
        if '?' in full_path:
            path, query_string = full_path.split('?', 1)
            result.path = path

            # Parse query parameters
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    try:
                        result.query_params[unquote(key)] = unquote(value)
                    except Exception:
                        result.query_params[key] = value
                else:
                    result.query_params[param] = ""
        else:
            result.path = full_path

    # Parse headers until empty line
    body_start = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if line == '':
            body_start = i + 1
            break

        colon_idx = line.find(':')
        if colon_idx > 0:
            header_name = line[:colon_idx].strip()
            header_value = line[colon_idx + 1:].strip()
            result.headers[header_name] = header_value

    # Extract body (everything after empty line)
    if body_start < len(lines):
        body_lines = lines[body_start:]
        result.body = '\n'.join(body_lines).strip()
        if not result.body:
            result.body = None

    # Extract client IP from headers if present
    result.client_ip = (
        result.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
        result.headers.get('X-Real-IP') or
        None
    )

    return result


def parse_curl_command(cmd: str) -> ParsedRequest:
    """
    Parse a curl command.

    Example input:
        curl -X POST http://example.com/api \
            -H "Content-Type: application/json" \
            -d '{"user": "admin"}'

    Handles:
        -X, --request: HTTP method
        -H, --header: Headers
        -d, --data, --data-raw, --data-binary: Request body
        -u, --user: Basic auth
        -b, --cookie: Cookies
        URL (positional)

    Returns:
        ParsedRequest with extracted components
    """
    result = ParsedRequest()
    result.raw_input = cmd
    result.input_type = "curl"
    result.method = "GET"  # Default

    # Normalize line continuations
    normalized = re.sub(r'\\\n\s*', ' ', cmd).strip()

    # Tokenize using shlex (handles quotes properly)
    try:
        tokens = shlex.split(normalized)
    except ValueError:
        # Fallback to simple split if shlex fails (unmatched quotes)
        tokens = normalized.split()

    # Skip 'curl' command itself
    if tokens and tokens[0].lower() == 'curl':
        tokens = tokens[1:]

    i = 0
    while i < len(tokens):
        token = tokens[i]
        next_token = tokens[i + 1] if i + 1 < len(tokens) else None

        if token in ('-X', '--request') and next_token:
            result.method = next_token.upper()
            i += 2
            continue

        if token in ('-H', '--header') and next_token:
            colon_idx = next_token.find(':')
            if colon_idx > 0:
                header_name = next_token[:colon_idx].strip()
                header_value = next_token[colon_idx + 1:].strip()
                result.headers[header_name] = header_value
            i += 2
            continue

        if token in ('-d', '--data', '--data-raw', '--data-binary', '--data-urlencode') and next_token:
            result.body = next_token
            if result.method == "GET":
                result.method = "POST"
            i += 2
            continue

        if token in ('-u', '--user') and next_token:
            # Basic auth - add as Authorization header
            import base64
            try:
                encoded = base64.b64encode(next_token.encode()).decode()
                result.headers['Authorization'] = f"Basic {encoded}"
            except Exception:
                result.headers['Authorization'] = f"Basic {next_token}"
            i += 2
            continue

        if token in ('-b', '--cookie') and next_token:
            result.headers['Cookie'] = next_token
            i += 2
            continue

        if token in ('-A', '--user-agent') and next_token:
            result.headers['User-Agent'] = next_token
            i += 2
            continue

        if token in ('-e', '--referer') and next_token:
            result.headers['Referer'] = next_token
            i += 2
            continue

        # Check if it's a URL
        if token.startswith('http://') or token.startswith('https://'):
            try:
                parsed = urlparse(token)
                result.path = parsed.path or '/'

                # Parse query string
                if parsed.query:
                    for key, values in parse_qs(parsed.query).items():
                        result.query_params[key] = values[0] if values else ""

                # Extract host as header
                if parsed.netloc:
                    result.headers['Host'] = parsed.netloc
            except Exception:
                result.path = token
            i += 1
            continue

        # Skip unknown flags with arguments
        if token.startswith('-') and next_token and not next_token.startswith('-'):
            i += 2
            continue

        # Skip unknown flags without arguments
        if token.startswith('-'):
            i += 1
            continue

        # Unknown positional - might be URL without scheme
        if '/' in token or '.' in token:
            result.path = token

        i += 1

    return result


def parse_input(text: str) -> ParsedRequest:
    """
    Detect format and parse input accordingly.

    Args:
        text: Raw input (HTTP request, curl command, or plain text)

    Returns:
        ParsedRequest with extracted components
    """
    input_type = detect_input_format(text)

    if input_type == "http":
        return parse_http_request(text)
    elif input_type == "curl":
        return parse_curl_command(text)
    else:
        # Raw text - wrap in ParsedRequest
        result = ParsedRequest()
        result.raw_input = text
        result.input_type = "raw"
        result.body = text
        return result

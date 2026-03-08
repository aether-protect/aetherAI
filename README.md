# Aether Protect

**ML-powered security threat detection for HTTP requests**

Aether Protect detects security threats in HTTP requests using a hybrid machine learning model that combines transformer-based text analysis with character-level pattern detection.

## Features

- **14 Threat Classes**: SQL injection, XSS, command injection, path traversal, SSRF, XXE, LDAP injection, NoSQL injection, malware signatures, crypto miners, red team tools, network intrusions, data exfiltration
- **Two-Layer Defense**: ML model + AWS WAF managed rules
- **MITRE ATT&CK Mapping**: Threats mapped to MITRE techniques
- **Web UI**: React dashboard for testing and scan history
- **Agent Integration**: Strands agent with Claude for AI-powered analysis

## Quick Start

### Prerequisites

- AWS CLI configured with valid credentials
- AWS CDK (`npm install -g aws-cdk`)
- Python 3.11+
- Bun or npm

### Deploy Everything

```bash
git clone https://github.com/jinnius1/earendel.git aether-protect
cd aether-protect
./deploy.sh
```

The deploy script will:
1. Bootstrap CDK
2. Deploy agent infrastructure (S3, SageMaker, AgentCore)
3. Build agent container via CodeBuild
4. Deploy WAF test endpoint (Layer 2 defense)
5. Deploy web UI (CloudFront, Lambda, DynamoDB)
6. Build and upload the React frontend

Deployment takes ~15-20 minutes. At the end, you'll see the CloudFront URL.

### Deployment Options

```bash
./deploy.sh --web-only    # Only deploy web UI (faster)
./deploy.sh --skip-agent  # Skip agent infrastructure
./deploy.sh --skip-waf    # Skip WAF test endpoint
./deploy.sh --help        # Show all options
```

### Destroy

```bash
./destroy.sh              # Tear down all infrastructure
./destroy.sh --force      # Skip confirmation
```

## Project Structure

```
aether-protect/
├── agent/
│   ├── scanner/           # Core scanning logic
│   ├── sagemaker/         # SageMaker ONNX inference
│   ├── earendel_strands/  # Strands agent (Claude integration)
│   └── cdk/               # Agent CDK stack
│
├── web/
│   ├── frontend/          # React + Vite app
│   ├── lambda/            # API handlers
│   └── cdk/               # Web CDK stack
│
└── waf/                   # WAF test endpoint stack
```

## Usage

### Web UI

Access the deployed CloudFront URL and log in with demo credentials:
- Username: `admin` / Password: `admin`
- Username: `demo` / Password: `demo`

### API

```bash
# Login to get token
curl -X POST https://YOUR_API/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Scan a request
curl -X POST https://YOUR_API/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"raw_request": "SELECT * FROM users WHERE id=1 OR 1=1"}'
```

### Response Format

```json
{
  "is_threat": true,
  "confidence": 0.95,
  "threat_type": "sql_injection",
  "mitre_attack": ["T1190", "T1059"],
  "decision": {
    "action": "BLOCK",
    "reason": "ML detected: sql_injection"
  }
}
```

## Model Information

| Metric | Value |
|--------|-------|
| Threat Classes | 14 |
| Accuracy | 94.02% |
| Model Size | ~8MB (ONNX) |
| Inference | ~50ms (CPU) |

Download the pre-trained model from [GitHub Releases](https://github.com/jinnius1/earendel/releases/download/v1.0.0/model.tar.gz).

### Threat Types

| ID | Type | MITRE Techniques |
|----|------|------------------|
| 0 | benign | - |
| 1 | sql_injection | T1190, T1059 |
| 2 | xss | T1189, T1059.007 |
| 3 | command_injection | T1059, T1203 |
| 4 | path_traversal | T1083, T1005 |
| 5 | ssrf | T1090, T1071 |
| 6 | xxe | T1059, T1005 |
| 7 | ldap_injection | T1087, T1069 |
| 8 | nosql_injection | T1190, T1059 |
| 9 | malware_signature | T1204, T1105 |
| 10 | crypto_miner | T1496 |
| 11 | red_team_tool | T1055, T1003, T1059 |
| 12 | network_intrusion | T1071, T1095 |
| 13 | data_exfiltration | T1041, T1567 |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTCORE_RUNTIME_ARN` | AgentCore runtime ARN | Auto-discovered |
| `SAGEMAKER_ENDPOINT_NAME` | SageMaker endpoint | `aether-protect-threat-detector` |
| `SCANS_TABLE` | DynamoDB table name | `aether-protect-scans` |
| `AUTH_USERS` | User credentials (user:pass,user2:pass2) | `admin:admin,demo:demo` |
| `TOKEN_SECRET` | Secret for signing auth tokens | Auto-generated |
| `TOKEN_EXPIRY_HOURS` | Token validity period | `24` |

### Production Configuration

For production deployments, set custom credentials:

```bash
export AUTH_USERS="myuser:secure-password-here"
export TOKEN_SECRET="your-256-bit-secret-key"
./deploy.sh
```

## Development

### Local Testing

```bash
# Run frontend dev server
cd web/frontend
bun run dev

# Test ONNX inference locally
cd web/lambda
python onnx_handler.py
```

### Requirements

- Python 3.11+
- Node.js 18+ / Bun
- AWS CDK 2.170+
- AWS account with Bedrock access

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

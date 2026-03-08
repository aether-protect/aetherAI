# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Aether Protect, please report it responsibly.

**Do not open public issues for security vulnerabilities.**

### How to Report

1. **GitHub Security Advisories** (Preferred): Use the "Security" tab in the repository to privately report the vulnerability.

2. **Email**: If security advisories are not available, contact the maintainers directly.

### What to Include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Depends on severity

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | Yes                |
| < 1.0   | No                 |

## Security Best Practices

When deploying Aether Protect:

1. **Authentication**: Change default credentials immediately after deployment
2. **Network**: Restrict API access to trusted networks where possible
3. **IAM**: Follow least-privilege principles for AWS IAM roles
4. **Updates**: Keep dependencies updated
5. **Logging**: Enable CloudWatch logging for audit trails

## Known Limitations

- The default authentication uses simple token-based auth suitable for demos
- For production, consider implementing:
  - AWS Cognito integration
  - API Gateway authorizers
  - VPC endpoints for private access

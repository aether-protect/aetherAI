# Contributing to Aether Protect

Thank you for your interest in contributing to Aether Protect! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment (see below)
4. Create a feature branch from `main`

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+ or Bun
- AWS CLI configured with valid credentials
- AWS CDK (`npm install -g aws-cdk`)

### Local Development

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/earendel.git aether-protect
cd aether-protect

# Set up Python virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r agent/requirements.txt
pip install -r agent/cdk/requirements.txt

# Set up frontend
cd web/frontend
npm install  # or: bun install
```

## Making Changes

### Code Style

- **Python**: Follow PEP 8 guidelines
- **TypeScript/JavaScript**: Use the existing code style (Prettier recommended)
- **Commits**: Use clear, descriptive commit messages

### Testing

Before submitting a pull request:

1. Ensure all existing tests pass
2. Add tests for new functionality
3. Test deployment locally if infrastructure changes are made

### Pull Request Process

1. Update documentation if needed
2. Ensure your code follows the existing style
3. Write a clear PR description explaining:
   - What changes were made
   - Why the changes were necessary
   - How to test the changes
4. Link any related issues

## Types of Contributions

### Bug Reports

When filing a bug report, include:

- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, etc.)
- Relevant logs or error messages

### Feature Requests

When proposing a feature:

- Describe the use case
- Explain why this feature would be useful
- Consider implementation complexity

### Code Contributions

We welcome contributions for:

- Bug fixes
- New threat detection patterns
- Performance improvements
- Documentation improvements
- Test coverage improvements

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Please report security issues privately by emailing the maintainers or using the repository's security advisory feature. See [SECURITY.md](SECURITY.md) for details.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## Questions?

If you have questions about contributing, feel free to open a discussion or issue.

Thank you for contributing!

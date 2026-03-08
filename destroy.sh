#!/bin/bash
#
# Aether Protect Destroy Script
#
# Tears down all Aether Protect infrastructure.
#
# Usage:
#   ./destroy.sh              # Destroy everything (with confirmation)
#   ./destroy.sh --force      # Destroy without confirmation
#   ./destroy.sh --web-only   # Only destroy web stack
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="us-east-1"
APP_NAME="Aether Protect"
APP_SLUG="aether-protect"
AGENT_STACK="AetherProtectAgentStack"
AGENTCORE_STACK="AetherProtectAgentCoreStack"
WEB_STACK="AetherProtectWebStack"
WAF_STACK="AetherProtectWAFTestStack"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Flags
FORCE=false
WEB_ONLY=false

print_step() { echo -e "\n${GREEN}==>${NC} $1"; }
print_warn() { echo -e "${YELLOW}Warning:${NC} $1"; }
print_error() { echo -e "${RED}Error:${NC} $1"; exit 1; }

show_help() {
    echo "$APP_NAME Destroy Script"
    echo ""
    echo "Usage: ./destroy.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --force       Skip confirmation prompt"
    echo "  --web-only    Only destroy web stack"
    echo "  --help        Show this help message"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force) FORCE=true; shift ;;
        --web-only) WEB_ONLY=true; shift ;;
        --help) show_help ;;
        *) print_error "Unknown option: $1" ;;
    esac
done

echo ""
echo "=========================================="
echo "       $APP_NAME Destroy Script"
echo "=========================================="
echo ""

# Confirmation
if [ "$FORCE" = false ]; then
    echo -e "${RED}WARNING: This will destroy all $APP_NAME infrastructure!${NC}"
    echo ""
    read -p "Are you sure you want to continue? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Get AWS account
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || \
    print_error "Failed to get AWS account. Check your credentials."

echo ""
echo "Destroying stacks in AWS Account: $AWS_ACCOUNT"

# =============================================================================
# DESTROY WEB STACK
# =============================================================================

print_step "Destroying Web Stack..."
cd "$SCRIPT_DIR/web/cdk"
pip install -q -r requirements.txt 2>/dev/null
cdk destroy "$WEB_STACK" --force 2>/dev/null || print_warn "Web stack not found or already destroyed"

if [ "$WEB_ONLY" = true ]; then
    echo ""
    echo "Web stack destroyed."
    exit 0
fi

# =============================================================================
# DESTROY WAF STACK
# =============================================================================

print_step "Destroying WAF Stack..."
cd "$SCRIPT_DIR/waf"
pip install -q aws-cdk-lib constructs python-dotenv 2>/dev/null
cdk destroy "$WAF_STACK" --force 2>/dev/null || print_warn "WAF stack not found or already destroyed"

# =============================================================================
# DESTROY AGENT STACKS
# =============================================================================

print_step "Destroying Agent Stacks..."
cd "$SCRIPT_DIR/agent/cdk"
pip install -q -r requirements.txt 2>/dev/null

# Destroy AgentCore first (depends on Agent stack)
cdk destroy "$AGENTCORE_STACK" --force 2>/dev/null || print_warn "AgentCore stack not found or already destroyed"

# Then destroy Agent stack
cdk destroy "$AGENT_STACK" --force 2>/dev/null || print_warn "Agent stack not found or already destroyed"

# =============================================================================
# CLEANUP
# =============================================================================

print_step "Checking for remaining resources..."

# Check for any remaining SageMaker endpoints
ENDPOINTS=$(aws sagemaker list-endpoints \
    --region $REGION \
    --query "Endpoints[?contains(EndpointName, '$APP_SLUG')].EndpointName" \
    --output text 2>/dev/null)

if [ -n "$ENDPOINTS" ] && [ "$ENDPOINTS" != "None" ]; then
    print_warn "Found SageMaker endpoints that may need manual cleanup: $ENDPOINTS"
    echo "  To delete: aws sagemaker delete-endpoint --endpoint-name <name> --region $REGION"
fi

echo ""
echo "=========================================="
echo "   $APP_NAME Destruction Complete!"
echo "=========================================="
echo ""

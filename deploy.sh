#!/bin/bash
#
# Aether Protect Deployment Script
#
# Deploys the entire Aether Protect security platform with one command.
#
# Usage:
#   ./deploy.sh              # Deploy everything
#   ./deploy.sh --skip-agent # Skip agent infrastructure
#   ./deploy.sh --web-only   # Only deploy web UI
#   ./deploy.sh --help       # Show help
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
MODEL_RELEASE_URL="${MODEL_RELEASE_URL:-https://github.com/aether-protect/aetherAI/releases/download/v1.0.0/model.tar.gz}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
SKIP_AGENT=false
SKIP_WAF=false
SKIP_WEB=false
WEB_ONLY=false

print_step() { echo -e "\n${GREEN}==>${NC} $1"; }
print_info() { echo -e "${BLUE}   ${NC} $1"; }
print_warn() { echo -e "${YELLOW}Warning:${NC} $1"; }
print_error() { echo -e "${RED}Error:${NC} $1"; exit 1; }

show_help() {
    echo "$APP_NAME Deployment Script"
    echo ""
    echo "Usage: ./deploy.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --skip-agent    Skip agent infrastructure (SageMaker, AgentCore)"
    echo "  --skip-waf      Skip WAF test endpoint"
    echo "  --skip-web      Skip web UI deployment"
    echo "  --web-only      Only deploy web UI (implies --skip-agent)"
    echo "  --help          Show this help message"
    echo ""
    echo "Prerequisites:"
    echo "  - AWS CLI configured with valid credentials"
    echo "  - AWS CDK CLI (npm install -g aws-cdk)"
    echo "  - Python 3.11+"
    echo "  - Bun or npm for frontend build"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-agent) SKIP_AGENT=true; shift ;;
        --skip-waf) SKIP_WAF=true; shift ;;
        --skip-web) SKIP_WEB=true; shift ;;
        --web-only) WEB_ONLY=true; SKIP_AGENT=true; shift ;;
        --help) show_help ;;
        *) print_error "Unknown option: $1" ;;
    esac
done

echo ""
echo "=========================================="
echo "       $APP_NAME Deployment Script"
echo "=========================================="
echo ""

# Check prerequisites
print_step "Checking prerequisites..."

command -v aws >/dev/null 2>&1 || print_error "AWS CLI not found. Install: https://aws.amazon.com/cli/"
command -v cdk >/dev/null 2>&1 || print_error "AWS CDK not found. Install: npm install -g aws-cdk"
command -v python3 >/dev/null 2>&1 || print_error "Python 3 not found"

# Use pip3 if pip is not available
if command -v pip3 &>/dev/null; then
    PIP_CMD="pip3"
elif command -v pip &>/dev/null; then
    PIP_CMD="pip"
else
    print_error "pip not found"
fi

if command -v bun &>/dev/null; then
    PKG_MANAGER="bun"
elif command -v npm &>/dev/null; then
    PKG_MANAGER="npm"
else
    print_error "Neither bun nor npm found. Install one for frontend build."
fi

print_info "Using $PKG_MANAGER for frontend build"

# Get AWS account
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || \
    print_error "Failed to get AWS account. Check your credentials."

print_info "AWS Account: $AWS_ACCOUNT"
print_info "Region: $REGION"

# Bootstrap CDK
print_step "Bootstrapping CDK..."
cdk bootstrap aws://$AWS_ACCOUNT/$REGION 2>/dev/null || true

# =============================================================================
# AGENT INFRASTRUCTURE
# =============================================================================

if [ "$SKIP_AGENT" = false ]; then
    print_step "Deploying Agent Stack Phase 1 (S3, ECR, CodeBuild)..."
    cd "$SCRIPT_DIR/agent/cdk"
    $PIP_CMD install -q -r requirements.txt 2>/dev/null
    cdk deploy "$AGENT_STACK" --require-approval never

    # Get stack outputs
    MODEL_BUCKET=$(aws cloudformation describe-stacks \
        --stack-name "$AGENT_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='ModelBucketName'].OutputValue" \
        --output text)

    INFERENCE_REPO_URI=$(aws cloudformation describe-stacks \
        --stack-name "$AGENT_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='InferenceRepoUri'].OutputValue" \
        --output text)

    INFERENCE_BUILD_PROJECT=$(aws cloudformation describe-stacks \
        --stack-name "$AGENT_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='InferenceBuildProject'].OutputValue" \
        --output text)

    # =========================================================================
    # BUILD ONNX INFERENCE CONTAINER
    # =========================================================================
    print_step "Building ONNX inference container via CodeBuild..."

    BUILD_ID=$(aws codebuild start-build \
        --project-name "$INFERENCE_BUILD_PROJECT" \
        --region $REGION \
        --query 'build.id' \
        --output text)

    print_info "Build started: $BUILD_ID"
    print_info "Waiting for build to complete..."

    # Wait for build with timeout (15 minutes max)
    for i in {1..30}; do
        STATUS=$(aws codebuild batch-get-builds \
            --ids "$BUILD_ID" \
            --region $REGION \
            --query 'builds[0].buildStatus' \
            --output text 2>/dev/null)

        if [ "$STATUS" = "SUCCEEDED" ]; then
            print_info "Inference container build completed!"
            break
        elif [ "$STATUS" = "FAILED" ] || [ "$STATUS" = "FAULT" ] || [ "$STATUS" = "STOPPED" ]; then
            print_error "Inference container build failed with status: $STATUS"
        fi

        echo -ne "\r   Build status: $STATUS (${i}/30)..."
        sleep 30
    done
    echo ""

    INFERENCE_IMAGE_URI="$INFERENCE_REPO_URI:latest"
    print_info "Inference image: $INFERENCE_IMAGE_URI"

    # =========================================================================
    # DOWNLOAD ONNX MODEL FROM GITHUB RELEASE
    # =========================================================================
    print_step "Downloading ONNX model from GitHub release..."
    MODEL_FILE="/tmp/${APP_SLUG}_model_$$.tar.gz"

    curl -sL "$MODEL_RELEASE_URL" -o "$MODEL_FILE" || print_error "Failed to download model.tar.gz"
    print_info "Downloaded model.tar.gz"

    # Upload to S3
    print_step "Uploading ONNX model to S3..."
    aws s3 cp "$MODEL_FILE" "s3://$MODEL_BUCKET/model/model.tar.gz" --region $REGION
    MODEL_S3_URI="s3://$MODEL_BUCKET/model/model.tar.gz"
    print_info "ONNX model uploaded to $MODEL_S3_URI"

    # Clean up
    rm -f "$MODEL_FILE"

    # =========================================================================
    # DEPLOY SAGEMAKER ENDPOINT WITH ONNX CONTAINER
    # =========================================================================
    print_step "Deploying Agent Stack Phase 2 (SageMaker endpoint with ONNX inference)..."
    cd "$SCRIPT_DIR/agent/cdk"
    MODEL_S3_URI="$MODEL_S3_URI" INFERENCE_IMAGE_URI="$INFERENCE_IMAGE_URI" \
        cdk deploy "$AGENT_STACK" --require-approval never

    # =========================================================================
    # AGENTCORE STACK
    # =========================================================================
    print_step "Deploying AgentCore Stack (Phase 1: ECR, CodeBuild)..."
    cdk deploy "$AGENTCORE_STACK" --require-approval never

    # Build agent container via CodeBuild
    print_step "Building AgentCore container via CodeBuild..."
    BUILD_PROJECT=$(aws cloudformation describe-stacks \
        --stack-name "$AGENTCORE_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='CodeBuildProjectName'].OutputValue" \
        --output text)

    if [ -n "$BUILD_PROJECT" ] && [ "$BUILD_PROJECT" != "None" ]; then
        BUILD_ID=$(aws codebuild start-build \
            --project-name "$BUILD_PROJECT" \
            --region $REGION \
            --query 'build.id' \
            --output text)

        print_info "Build started: $BUILD_ID"
        print_info "Waiting for build to complete (this may take 5-10 minutes)..."

        # Wait for build with timeout (30 minutes max)
        for i in {1..60}; do
            STATUS=$(aws codebuild batch-get-builds \
                --ids "$BUILD_ID" \
                --region $REGION \
                --query 'builds[0].buildStatus' \
                --output text 2>/dev/null)

            if [ "$STATUS" = "SUCCEEDED" ]; then
                print_info "Build completed successfully!"
                break
            elif [ "$STATUS" = "FAILED" ] || [ "$STATUS" = "FAULT" ] || [ "$STATUS" = "STOPPED" ]; then
                print_error "CodeBuild failed with status: $STATUS"
            fi

            echo -ne "\r   Build status: $STATUS (${i}/60)..."
            sleep 30
        done
        echo ""

        # Deploy AgentCore runtime
        print_step "Deploying AgentCore Runtime (Phase 2)..."
        CREATE_RUNTIME=true cdk deploy "$AGENTCORE_STACK" --require-approval never
    else
        print_warn "CodeBuild project not found, skipping container build"
    fi
fi

# =============================================================================
# WAF TEST ENDPOINT
# =============================================================================

if [ "$SKIP_WAF" = false ] && [ "$WEB_ONLY" = false ]; then
    print_step "Deploying WAF Test Stack (Layer 2 Defense)..."
    cd "$SCRIPT_DIR/waf"
    $PIP_CMD install -q aws-cdk-lib constructs python-dotenv 2>/dev/null
    cdk deploy "$WAF_STACK" --require-approval never
fi

# =============================================================================
# WEB UI
# =============================================================================

if [ "$SKIP_WEB" = false ]; then
    print_step "Deploying Web Stack (CloudFront, Lambda, DynamoDB)..."
    cd "$SCRIPT_DIR/web/cdk"
    $PIP_CMD install -q -r requirements.txt 2>/dev/null
    cdk deploy "$WEB_STACK" --require-approval never

    # Build and upload frontend
    print_step "Building frontend..."
    cd "$SCRIPT_DIR/web/frontend"

    if [ "$PKG_MANAGER" = "bun" ]; then
        bun install
        bun run build
    else
        npm install
        npm run build
    fi

    print_step "Uploading frontend to S3..."
    BUCKET=$(aws cloudformation describe-stacks \
        --stack-name "$WEB_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='FrontendBucketName'].OutputValue" \
        --output text)

    if [ -n "$BUCKET" ] && [ "$BUCKET" != "None" ]; then
        aws s3 sync dist/ "s3://$BUCKET/" --delete --region $REGION
        print_info "Frontend uploaded to s3://$BUCKET/"
    else
        print_warn "Could not find frontend bucket"
    fi
fi

# =============================================================================
# PRINT ENDPOINTS
# =============================================================================

echo ""
echo "=========================================="
echo "   $APP_NAME Deployment Complete!"
echo "=========================================="
echo ""

if [ "$SKIP_WEB" = false ]; then
    CLOUDFRONT_URL=$(aws cloudformation describe-stacks \
        --stack-name "$WEB_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" \
        --output text 2>/dev/null)

    if [ -n "$CLOUDFRONT_URL" ] && [ "$CLOUDFRONT_URL" != "None" ]; then
        echo "  Web UI:       $CLOUDFRONT_URL"
    fi
fi

if [ "$SKIP_WAF" = false ] && [ "$WEB_ONLY" = false ]; then
    WAF_ENDPOINT=$(aws cloudformation describe-stacks \
        --stack-name "$WAF_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='WAFTestEndpoint'].OutputValue" \
        --output text 2>/dev/null)

    if [ -n "$WAF_ENDPOINT" ] && [ "$WAF_ENDPOINT" != "None" ]; then
        echo "  WAF Endpoint: $WAF_ENDPOINT"
    fi
fi

if [ "$SKIP_AGENT" = false ]; then
    SAGEMAKER_ENDPOINT=$(aws cloudformation describe-stacks \
        --stack-name "$AGENT_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='SageMakerEndpointName'].OutputValue" \
        --output text 2>/dev/null)

    if [ -n "$SAGEMAKER_ENDPOINT" ] && [ "$SAGEMAKER_ENDPOINT" != "None" ]; then
        echo "  SageMaker:    $SAGEMAKER_ENDPOINT"
    fi

    RUNTIME_STATUS=$(aws cloudformation describe-stacks \
        --stack-name "$AGENTCORE_STACK" \
        --region $REGION \
        --query "Stacks[0].Outputs[?OutputKey=='AgentCoreRuntimeArn'].OutputValue" \
        --output text 2>/dev/null)

    if [ -z "$RUNTIME_STATUS" ] || [ "$RUNTIME_STATUS" = "None" ]; then
        RUNTIME_STATUS=$(aws cloudformation describe-stacks \
            --stack-name "$AGENTCORE_STACK" \
            --region $REGION \
            --query "Stacks[0].Outputs[?OutputKey=='AgentCoreRuntimeStatus'].OutputValue" \
            --output text 2>/dev/null)
    fi

    if [ -n "$RUNTIME_STATUS" ] && [ "$RUNTIME_STATUS" != "None" ]; then
        echo "  AgentCore:    $RUNTIME_STATUS"
    fi
fi

echo ""
echo "  Login:        Use credentials from AUTH_USERS env var"
echo "                Default: admin/admin, demo/demo"
echo ""
echo "  For production, set before deploying:"
echo "    export AUTH_USERS='myuser:secure-password'"
echo ""
echo "=========================================="
echo ""

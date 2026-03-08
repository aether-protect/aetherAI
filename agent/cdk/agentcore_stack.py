"""Aether Protect AgentCore stack - Strands agent deployment to Bedrock."""

import os
import sys
from pathlib import Path
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_ecr as ecr,
    aws_iam as iam,
    aws_s3 as s3,
    aws_s3_assets as s3_assets,
    aws_codebuild as codebuild,
)
from constructs import Construct

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import (
    AGENT_BUILD_PROJECT_NAME,
    AGENTCORE_ROLE_NAME,
    AGENTCORE_RUNTIME_NAME,
    AGENT_REPOSITORY_NAME,
    APP_NAME,
    DEFAULT_SAGEMAKER_ENDPOINT,
)

# Try to import AgentCore constructs (alpha)
try:
    from aws_cdk import aws_bedrock_agentcore_alpha as agentcore
    AGENTCORE_AVAILABLE = True
except ImportError:
    AGENTCORE_AVAILABLE = False
    print("Warning: aws_cdk.aws_bedrock_agentcore_alpha not available.")


class AetherProtectAgentCoreStack(Stack):
    """Aether Protect agent deployed to Bedrock AgentCore using CodeBuild"""

    def __init__(self, scope: Construct, construct_id: str,
                 model_bucket: s3.IBucket = None,
                 sagemaker_endpoint: str = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Configuration
        self.sagemaker_endpoint = sagemaker_endpoint or os.environ.get(
            'SAGEMAKER_ENDPOINT_NAME', DEFAULT_SAGEMAKER_ENDPOINT
        )
        region = os.environ.get('AWS_REGION', 'us-east-1')

        self.ecr_repository = ecr.Repository(
            self, "AetherProtectAgentRepository",
            repository_name=AGENT_REPOSITORY_NAME,
            removal_policy=RemovalPolicy.DESTROY,
            empty_on_delete=True,
            image_scan_on_push=True
        )

        self.agent_code_asset = s3_assets.Asset(
            self, "AgentCodeAsset",
            path=os.path.join(os.path.dirname(__file__), ".."),
            exclude=[
                "cdk",
                "cdk.out",
                ".venv",
                "__pycache__",
                "*.pyc",
                ".git",
                "node_modules",
                "model/trained/*.pt",
                "model/trained/*.pkl",
            ]
        )

        self.build_project = codebuild.Project(
            self, "AetherProtectAgentBuild",
            project_name=AGENT_BUILD_PROJECT_NAME,
            description=f"Build {APP_NAME} Strands Agent container (ARM64)",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxArmBuildImage.AMAZON_LINUX_2_STANDARD_3_0,
                privileged=True,  # Required for Docker builds
                compute_type=codebuild.ComputeType.LARGE
            ),
            environment_variables={
                "ECR_REPO_URI": codebuild.BuildEnvironmentVariable(
                    value=self.ecr_repository.repository_uri
                ),
                "AWS_ACCOUNT_ID": codebuild.BuildEnvironmentVariable(
                    value=self.account
                ),
                "AWS_REGION": codebuild.BuildEnvironmentVariable(
                    value=self.region
                )
            },
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "pre_build": {
                        "commands": [
                            "echo Logging in to Amazon ECR...",
                            "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
                        ]
                    },
                    "build": {
                        "commands": [
                            "echo Building Docker image...",
                            "docker build -t $ECR_REPO_URI:latest .",
                            "docker tag $ECR_REPO_URI:latest $ECR_REPO_URI:$CODEBUILD_BUILD_NUMBER"
                        ]
                    },
                    "post_build": {
                        "commands": [
                            "echo Pushing Docker image...",
                            "docker push $ECR_REPO_URI:latest",
                            "docker push $ECR_REPO_URI:$CODEBUILD_BUILD_NUMBER",
                            "echo Build completed on `date`"
                        ]
                    }
                },
                "artifacts": {
                    "files": ["**/*"]
                }
            }),
            source=codebuild.Source.s3(
                bucket=self.agent_code_asset.bucket,
                path=self.agent_code_asset.s3_object_key
            ),
            timeout=Duration.minutes(30)
        )

        self.ecr_repository.grant_pull_push(self.build_project)
        self.agent_code_asset.grant_read(self.build_project)

        self.agentcore_role = iam.Role(
            self, "AgentCoreExecutionRole",
            role_name=AGENTCORE_ROLE_NAME,
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
                iam.ServicePrincipal("bedrock.amazonaws.com")
            )
        )

        self.agentcore_role.add_to_policy(iam.PolicyStatement(
            sid="InvokeSageMaker",
            actions=["sagemaker:InvokeEndpoint"],
            resources=[
                f"arn:aws:sagemaker:{region}:*:endpoint/{self.sagemaker_endpoint}"
            ]
        ))

        self.agentcore_role.add_to_policy(iam.PolicyStatement(
            sid="InvokeBedrockModels",
            actions=[
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            resources=[
                f"arn:aws:bedrock:{region}:*:inference-profile/us.anthropic.*",
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5*",
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet*"
            ]
        ))

        self.agentcore_role.add_to_policy(iam.PolicyStatement(
            sid="CloudWatchLogs",
            actions=[
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            resources=["arn:aws:logs:*:*:*"]
        ))

        self.agentcore_role.add_to_policy(iam.PolicyStatement(
            sid="MarketplaceModelAccess",
            actions=[
                "aws-marketplace:ViewSubscriptions",
                "aws-marketplace:Subscribe"
            ],
            resources=["*"]
        ))

        self.ecr_repository.grant_pull(self.agentcore_role)

        create_runtime = os.environ.get('CREATE_RUNTIME', 'false').lower() == 'true'

        if AGENTCORE_AVAILABLE and create_runtime:
            agent_artifact = agentcore.AgentRuntimeArtifact.from_ecr_repository(
                self.ecr_repository,
                "latest"
            )

            self.runtime = agentcore.Runtime(
                self, "AetherProtectRuntime",
                runtime_name=AGENTCORE_RUNTIME_NAME,
                agent_runtime_artifact=agent_artifact,
                execution_role=self.agentcore_role,
                description=f"{APP_NAME} AI Security Agent - ML threat detection with LLM analysis",
                environment_variables={
                    "AWS_REGION": region,
                    "SAGEMAKER_ENDPOINT": self.sagemaker_endpoint,
                    "WAF_TEST_ENDPOINT": os.environ.get('WAF_TEST_ENDPOINT', ''),
                    "LOG_LEVEL": "INFO"
                },
                lifecycle_configuration=agentcore.LifecycleConfiguration(
                    idle_runtime_session_timeout=Duration.minutes(15),
                    max_lifetime=Duration.hours(2)
                )
            )

            # The runtime ARN is constructed from the physical resource ID
            # Format: arn:aws:bedrock-agentcore:{region}:{account}:runtime/{physical_id}
            from aws_cdk import Fn
            runtime_arn = Fn.sub(
                "arn:aws:bedrock-agentcore:${AWS::Region}:${AWS::AccountId}:runtime/${RuntimeId}",
                {"RuntimeId": self.runtime.node.default_child.ref}
            )
            CfnOutput(self, "AgentCoreRuntimeArn",
                      value=runtime_arn,
                      description="AgentCore runtime ARN")
        else:
            CfnOutput(self, "AgentCoreRuntimeStatus",
                      value="Run CodeBuild first, then redeploy with CREATE_RUNTIME=true",
                      description="AgentCore runtime status")

        CfnOutput(self, "ECRRepositoryUri",
                  value=self.ecr_repository.repository_uri,
                  description="ECR repository URI for agent container")

        CfnOutput(self, "CodeBuildProjectName",
                  value=self.build_project.project_name,
                  description="CodeBuild project to build the agent container")

        CfnOutput(self, "AgentCoreRoleArn",
                  value=self.agentcore_role.role_arn,
                  description="AgentCore execution role ARN")

        CfnOutput(self, "SageMakerEndpointName",
                  value=self.sagemaker_endpoint,
                  description="SageMaker endpoint used by agent")

        CfnOutput(self, "BuildCommand",
                  value=f"aws codebuild start-build --project-name {self.build_project.project_name} --region {region}",
                  description="Command to trigger container build")

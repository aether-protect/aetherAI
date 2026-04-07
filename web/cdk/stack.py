"""Aether Protect web CDK stack - CloudFront, Lambda, DynamoDB."""

import os
import secrets
import sys
from pathlib import Path
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_s3 as s3,
    aws_s3_deployment as s3_deploy,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_lambda as lambda_,
    aws_apigateway as apigw,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
)
from constructs import Construct

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))

from project_config import (
    AGENTCORE_RUNTIME_NAME,
    AGENTCORE_STACK_NAME,
    APP_NAME,
    APP_SLUG,
    DEFAULT_AUTH_USERS,
    DEFAULT_SCANS_TABLE,
    PRIMARY_REGION,
    WEB_API_FUNCTION_NAME,
    WEB_API_NAME,
    WEB_UI_OAI_COMMENT,
)


class AetherProtectWebStack(Stack):
    """Aether Protect web infrastructure stack"""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Get the AgentCore runtime ARN from environment or fetch from stack output
        self.agentcore_runtime_arn = os.environ.get('AGENTCORE_RUNTIME_ARN', '')
        if not self.agentcore_runtime_arn:
            # Try to get from AgentCore stack output via SSM or use the known format
            import boto3
            try:
                cfn = boto3.client('cloudformation', region_name=PRIMARY_REGION)
                response = cfn.describe_stacks(StackName=AGENTCORE_STACK_NAME)
                for output in response['Stacks'][0].get('Outputs', []):
                    if output['OutputKey'] == 'AgentCoreRuntimeArn':
                        self.agentcore_runtime_arn = output['OutputValue']
                        break
            except Exception:
                pass
            if not self.agentcore_runtime_arn:
                self.agentcore_runtime_arn = f'arn:aws:bedrock-agentcore:{PRIMARY_REGION}:{self.account}:runtime/{AGENTCORE_RUNTIME_NAME}'
        self.table_name = os.environ.get('DYNAMODB_TABLE_NAME', DEFAULT_SCANS_TABLE)
        self.price_class = os.environ.get('CLOUDFRONT_PRICE_CLASS', 'PriceClass_100')

        self.scans_table = dynamodb.Table(
            self, "ScansTable",
            table_name=self.table_name,
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl"
        )

        self.scans_table.add_global_secondary_index(
            index_name="threat-index",
            partition_key=dynamodb.Attribute(
                name="threat_detected",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Auth configuration from environment (defaults for demo only)
        auth_users = os.environ.get('AUTH_USERS', DEFAULT_AUTH_USERS)
        token_secret = os.environ.get('TOKEN_SECRET', secrets.token_hex(32))
        token_expiry = os.environ.get('TOKEN_EXPIRY_HOURS', '24')

        self.api_lambda = lambda_.Function(
            self, "WebUIApiFunction",
            function_name=WEB_API_FUNCTION_NAME,
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("../lambda"),
            timeout=Duration.seconds(120),  # Longer timeout for AI agent
            memory_size=512,
            environment={
                "AGENTCORE_RUNTIME_ARN": self.agentcore_runtime_arn,
                "SCANS_TABLE": self.scans_table.table_name,
                "AWS_REGION_NAME": self.region,
                "AUTH_USERS": auth_users,
                "TOKEN_SECRET": token_secret,
                "TOKEN_EXPIRY_HOURS": token_expiry
            }
        )

        self.scans_table.grant_read_write_data(self.api_lambda)
        self.api_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["bedrock-agentcore:InvokeAgentRuntime"],
            resources=[
                self.agentcore_runtime_arn,
                f"{self.agentcore_runtime_arn}/*"
            ]
        ))
        self.api_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=["sagemaker:InvokeEndpoint"],
            resources=[f"arn:aws:sagemaker:{self.region}:{self.account}:endpoint/{APP_SLUG}-*"]
        ))

        # CORS: Allow all origins for demo. In production, restrict to your domain:
        # allow_origins=["https://yourdomain.com"]
        self.api = apigw.RestApi(
            self, "WebUIApi",
            rest_api_name=WEB_API_NAME,
            description=f"{APP_NAME} Web UI API",
            default_cors_preflight_options=apigw.CorsOptions(
                allow_origins=apigw.Cors.ALL_ORIGINS,
                allow_methods=["GET", "POST", "OPTIONS"],
                allow_headers=["Content-Type", "Authorization"]
            )
        )

        lambda_integration = apigw.LambdaIntegration(
            self.api_lambda,
            request_templates={"application/json": '{"statusCode": 200}'}
        )

        api_resource = self.api.root.add_resource("api")

        login_resource = api_resource.add_resource("login")
        login_resource.add_method("POST", lambda_integration)

        scan_resource = api_resource.add_resource("scan")
        scan_resource.add_method("POST", lambda_integration)

        scans_resource = api_resource.add_resource("scans")
        scans_resource.add_method("GET", lambda_integration)

        scan_id_resource = scans_resource.add_resource("{id}")
        scan_id_resource.add_method("GET", lambda_integration)

        stats_resource = api_resource.add_resource("stats")
        stats_resource.add_method("GET", lambda_integration)

        health_resource = api_resource.add_resource("health")
        health_resource.add_method("GET", lambda_integration)

        self.frontend_bucket = s3.Bucket(
            self, "FrontendBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED
        )

        oai = cloudfront.OriginAccessIdentity(
            self, "OAI",
            comment=WEB_UI_OAI_COMMENT
        )

        self.frontend_bucket.grant_read(oai)

        self.distribution = cloudfront.Distribution(
            self, "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(
                    self.frontend_bucket,
                    origin_access_identity=oai
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED
            ),
            additional_behaviors={
                "/api/*": cloudfront.BehaviorOptions(
                    origin=origins.RestApiOrigin(self.api),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL
                )
            },
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_page_path="/index.html",
                    response_http_status=200,
                    ttl=Duration.seconds(0)
                ),
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_page_path="/index.html",
                    response_http_status=200,
                    ttl=Duration.seconds(0)
                )
            ]
        )

        CfnOutput(
            self, "CloudFrontURL",
            value=f"https://{self.distribution.distribution_domain_name}",
            description="Web UI URL"
        )

        CfnOutput(
            self, "ApiURL",
            value=self.api.url,
            description="API Gateway URL"
        )

        CfnOutput(
            self, "FrontendBucketName",
            value=self.frontend_bucket.bucket_name,
            description="S3 bucket for frontend deployment"
        )

        CfnOutput(
            self, "ScansTableName",
            value=self.scans_table.table_name,
            description="DynamoDB table for scan history"
        )

        CfnOutput(
            self, "ApiLambdaName",
            value=self.api_lambda.function_name,
            description="Backend Lambda function name"
        )

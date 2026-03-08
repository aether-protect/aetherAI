"""
Aether Protect WAF test endpoint CDK stack

Creates a test API endpoint with AWS WAF attached.
Used for Layer 2 defense - testing payloads against real AWS WAF managed rules.

The endpoint accepts any payload and returns 200 OK.
If WAF blocks the request, the caller receives 403 Forbidden.

Usage:
    cd waf
    cdk deploy AetherProtectWAFTestStack
"""

import sys
from pathlib import Path

from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    aws_lambda as lambda_,
    aws_apigateway as apigw,
    aws_wafv2 as wafv2,
    aws_ssm as ssm,
)
from constructs import Construct
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from project_config import (
    APP_NAME,
    WAF_TEST_ACL_NAME,
    WAF_TEST_API_NAME,
    WAF_TEST_ENDPOINT_PARAM,
    WAF_TEST_FUNCTION_NAME,
    WAF_TEST_METRIC_NAME,
)


class AetherProtectWAFTestStack(Stack):
    """Aether Protect WAF test endpoint infrastructure for layer 2 defense"""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # =================================================================
        # LAMBDA: Simple echo function (just returns 200)
        # =================================================================

        self.test_lambda = lambda_.Function(
            self, "WAFTestFunction",
            function_name=WAF_TEST_FUNCTION_NAME,
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import json

def handler(event, context):
    '''Simple handler that returns 200 OK - WAF does the blocking'''
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'waf_passed': True,
            'message': 'Request passed WAF inspection'
        })
    }
"""),
            timeout=Duration.seconds(10),
            memory_size=128
        )

        # =================================================================
        # API GATEWAY
        # =================================================================

        self.api = apigw.RestApi(
            self, "WAFTestApi",
            rest_api_name=WAF_TEST_API_NAME,
            description=f"WAF test endpoint for {APP_NAME} layer 2 defense",
            default_cors_preflight_options=apigw.CorsOptions(
                allow_origins=apigw.Cors.ALL_ORIGINS,
                allow_methods=apigw.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "Authorization", "X-Test-Payload"]
            )
        )

        # Lambda integration
        lambda_integration = apigw.LambdaIntegration(self.test_lambda)

        # POST /test endpoint
        test_resource = self.api.root.add_resource("test")
        test_resource.add_method("POST", lambda_integration)
        test_resource.add_method("GET", lambda_integration)

        # =================================================================
        # WAF WEB ACL with AWS Managed Rules
        # =================================================================

        self.web_acl = wafv2.CfnWebACL(
            self, "WAFTestWebACL",
            name=WAF_TEST_ACL_NAME,
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=WAF_TEST_METRIC_NAME,
                sampled_requests_enabled=True
            ),
            rules=[
                # Rule 1: AWS Common Rule Set (general protections)
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesCommonRuleSet",
                    priority=1,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="CommonRuleSet",
                        sampled_requests_enabled=True
                    )
                ),
                # Rule 2: SQL Injection Rules
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesSQLiRuleSet",
                    priority=2,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesSQLiRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="SQLiRuleSet",
                        sampled_requests_enabled=True
                    )
                ),
                # Rule 3: Known Bad Inputs (Log4j, etc.)
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesKnownBadInputsRuleSet",
                    priority=3,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesKnownBadInputsRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="KnownBadInputsRuleSet",
                        sampled_requests_enabled=True
                    )
                ),
                # Rule 4: Linux OS Rules (path traversal, etc.)
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesLinuxRuleSet",
                    priority=4,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesLinuxRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="LinuxRuleSet",
                        sampled_requests_enabled=True
                    )
                ),
                # Rule 5: Unix OS Rules
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesUnixRuleSet",
                    priority=5,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesUnixRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="UnixRuleSet",
                        sampled_requests_enabled=True
                    )
                ),
            ]
        )

        # =================================================================
        # ASSOCIATE WAF WITH API GATEWAY
        # =================================================================

        # Get the API Gateway stage ARN
        stage_arn = f"arn:aws:apigateway:{self.region}::/restapis/{self.api.rest_api_id}/stages/{self.api.deployment_stage.stage_name}"

        self.waf_association = wafv2.CfnWebACLAssociation(
            self, "WAFAssociation",
            resource_arn=stage_arn,
            web_acl_arn=self.web_acl.attr_arn
        )

        # Ensure WAF is created before association
        self.waf_association.add_dependency(self.web_acl)

        # =================================================================
        # SSM PARAMETER FOR ENDPOINT URL
        # =================================================================

        # Store endpoint URL in SSM so web lambda can read it
        self.endpoint_param = ssm.StringParameter(
            self, "WAFTestEndpointParam",
            parameter_name=WAF_TEST_ENDPOINT_PARAM,
            string_value=f"{self.api.url}test",
            description=f"WAF test endpoint URL for {APP_NAME} layer 2 defense"
        )

        # =================================================================
        # OUTPUTS
        # =================================================================

        CfnOutput(
            self, "WAFTestEndpoint",
            value=f"{self.api.url}test",
            description="WAF Test Endpoint URL"
        )

        CfnOutput(
            self, "WebACLArn",
            value=self.web_acl.attr_arn,
            description="WAF Web ACL ARN"
        )

        CfnOutput(
            self, "WAFTestApiId",
            value=self.api.rest_api_id,
            description="API Gateway ID"
        )

        CfnOutput(
            self, "SSMParameterName",
            value=WAF_TEST_ENDPOINT_PARAM,
            description="SSM Parameter name for WAF endpoint"
        )

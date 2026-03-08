"""Aether Protect agent CDK stack - SageMaker ML endpoint and infrastructure."""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).parent / '.env'
load_dotenv(env_path)
ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR))
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    Size,
    aws_s3 as s3,
    aws_s3_assets as s3_assets,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_sagemaker as sagemaker,
    aws_stepfunctions as sfn,
    aws_ec2 as ec2,
    aws_stepfunctions_tasks as sfn_tasks,
    aws_ecr as ecr,
    aws_codebuild as codebuild,
    CfnOutput,
)
from constructs import Construct
from project_config import (
    DEFAULT_SAGEMAKER_ENDPOINT,
    ENDPOINT_CONFIG_PREFIX,
    FINETUNE_STATE_MACHINE_NAME,
    FINETUNE_TRIGGER_FUNCTION_NAME,
    INFERENCE_BUILD_PROJECT_NAME,
    INFERENCE_REPOSITORY_NAME,
    MODEL_NAME_PREFIX,
)


class AetherProtectAgentStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.endpoint_name = os.environ.get('SAGEMAKER_ENDPOINT_NAME', DEFAULT_SAGEMAKER_ENDPOINT)
        self.instance_type = os.environ.get('SAGEMAKER_INSTANCE_TYPE', 'ml.t2.medium')
        bucket_name = os.environ.get('MODEL_BUCKET_NAME', '')

        bucket_props = {
            "removal_policy": RemovalPolicy.DESTROY,
            "auto_delete_objects": True,
            "versioned": True,
            "encryption": s3.BucketEncryption.S3_MANAGED
        }
        if bucket_name:
            bucket_props["bucket_name"] = bucket_name

        self.model_bucket = s3.Bucket(self, "ModelBucket", **bucket_props)

        self.inference_repo = ecr.Repository(
            self, "InferenceRepo",
            repository_name=INFERENCE_REPOSITORY_NAME,
            removal_policy=RemovalPolicy.DESTROY,
            empty_on_delete=True
        )

        sagemaker_dir = os.path.join(os.path.dirname(__file__), '..', 'sagemaker')
        self.sagemaker_asset = s3_assets.Asset(
            self, "SageMakerAsset",
            path=sagemaker_dir
        )

        self.inference_build = codebuild.Project(
            self, "InferenceBuild",
            project_name=INFERENCE_BUILD_PROJECT_NAME,
            source=codebuild.Source.s3(
                bucket=self.sagemaker_asset.bucket,
                path=self.sagemaker_asset.s3_object_key
            ),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                compute_type=codebuild.ComputeType.SMALL
            ),
            environment_variables={
                "AWS_ACCOUNT_ID": codebuild.BuildEnvironmentVariable(
                    value=self.account
                ),
                "AWS_DEFAULT_REGION": codebuild.BuildEnvironmentVariable(
                    value=self.region
                ),
                "ECR_REPO_NAME": codebuild.BuildEnvironmentVariable(
                    value=self.inference_repo.repository_name
                )
            },
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "pre_build": {
                        "commands": [
                            "echo Logging in to Amazon ECR...",
                            "aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com",
                            "REPOSITORY_URI=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com/$ECR_REPO_NAME",
                            "IMAGE_TAG=${CODEBUILD_RESOLVED_SOURCE_VERSION:=latest}"
                        ]
                    },
                    "build": {
                        "commands": [
                            "echo Build started on `date`",
                            "echo Building ONNX inference container...",
                            "docker build -t $REPOSITORY_URI:latest .",
                            "docker tag $REPOSITORY_URI:latest $REPOSITORY_URI:$IMAGE_TAG"
                        ]
                    },
                    "post_build": {
                        "commands": [
                            "echo Build completed on `date`",
                            "echo Pushing the Docker image...",
                            "docker push $REPOSITORY_URI:latest",
                            "docker push $REPOSITORY_URI:$IMAGE_TAG",
                            "echo $REPOSITORY_URI:latest > /tmp/image_uri.txt"
                        ]
                    }
                },
                "artifacts": {
                    "files": ["/tmp/image_uri.txt"],
                    "discard-paths": True
                }
            }),
            timeout=Duration.minutes(30)
        )

        self.sagemaker_asset.grant_read(self.inference_build)
        self.inference_repo.grant_pull_push(self.inference_build)

        self.sagemaker_role = iam.Role(
            self, "SageMakerRole",
            assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerFullAccess")
            ]
        )

        self.model_bucket.grant_read_write(self.sagemaker_role)

        self.trigger_lambda = lambda_.Function(
            self, "TriggerFinetuneFunction",
            function_name=FINETUNE_TRIGGER_FUNCTION_NAME,
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import json
import boto3
import os
from datetime import datetime

def handler(event, context):
    sfn = boto3.client('stepfunctions')

    execution = sfn.start_execution(
        stateMachineArn=os.environ['STATE_MACHINE_ARN'],
        name=f"finetune-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        input=json.dumps(event)
    )

    return {
        'statusCode': 200,
        'body': json.dumps({
            'execution_arn': execution['executionArn'],
            'timestamp': datetime.now().isoformat()
        })
    }
"""),
            timeout=Duration.seconds(30),
            environment={}
        )

        training_task = sfn_tasks.SageMakerCreateTrainingJob(
            self, "TrainingJob",
            training_job_name=sfn.JsonPath.string_at("$.training_job_name"),
            algorithm_specification=sfn_tasks.AlgorithmSpecification(
                training_image=sfn_tasks.DockerImage.from_registry(
                    "763104351884.dkr.ecr.us-east-1.amazonaws.com/huggingface-pytorch-training:2.0-transformers4.28-cpu-py310-ubuntu20.04"
                ),
                training_input_mode=sfn_tasks.InputMode.FILE
            ),
            input_data_config=[
                sfn_tasks.Channel(
                    channel_name="train",
                    data_source=sfn_tasks.DataSource(
                        s3_data_source=sfn_tasks.S3DataSource(
                            s3_location=sfn_tasks.S3Location.from_json_expression("$.s3_input")
                        )
                    )
                )
            ],
            output_data_config=sfn_tasks.OutputDataConfig(
                s3_output_location=sfn_tasks.S3Location.from_bucket(
                    self.model_bucket, "training-output"
                )
            ),
            resource_config=sfn_tasks.ResourceConfig(
                instance_count=1,
                instance_type=ec2.InstanceType.of(
                    ec2.InstanceClass.M5, ec2.InstanceSize.LARGE
                ),
                volume_size=Size.gibibytes(30)
            ),
            stopping_condition=sfn_tasks.StoppingCondition(
                max_runtime=Duration.hours(2)
            ),
            role=self.sagemaker_role
        )

        success = sfn.Succeed(self, "TrainingComplete")
        self.state_machine = sfn.StateMachine(
            self, "FinetuneStateMachine",
            state_machine_name=FINETUNE_STATE_MACHINE_NAME,
            definition=training_task.next(success),
            timeout=Duration.hours(3)
        )

        self.state_machine.grant_start_execution(self.trigger_lambda)
        self.trigger_lambda.add_environment("STATE_MACHINE_ARN", self.state_machine.state_machine_arn)

        CfnOutput(self, "ModelBucketName", value=self.model_bucket.bucket_name,
                  description="S3 bucket for model artifacts")

        inference_image_uri = os.environ.get('INFERENCE_IMAGE_URI', '')
        model_s3_uri = os.environ.get('MODEL_S3_URI', '')
        if not model_s3_uri and bucket_name:
            model_s3_uri = f"s3://{bucket_name}/model/model.tar.gz"

        if model_s3_uri and inference_image_uri:
            self.inference_repo.grant_pull(self.sagemaker_role)
            import hashlib
            suffix = hashlib.md5(self.stack_name.encode()).hexdigest()[:8]
            model_name = f"{MODEL_NAME_PREFIX}-{suffix}"
            config_name = f"{ENDPOINT_CONFIG_PREFIX}-{suffix}"

            self.model = sagemaker.CfnModel(
                self, "ThreatDetectorModel",
                model_name=model_name,
                execution_role_arn=self.sagemaker_role.role_arn,
                primary_container=sagemaker.CfnModel.ContainerDefinitionProperty(
                    image=inference_image_uri,
                    model_data_url=model_s3_uri
                )
            )

            # Endpoint Configuration
            self.endpoint_config = sagemaker.CfnEndpointConfig(
                self, "ThreatDetectorEndpointConfig",
                endpoint_config_name=config_name,
                production_variants=[
                    sagemaker.CfnEndpointConfig.ProductionVariantProperty(
                        variant_name="AllTraffic",
                        model_name=model_name,
                        initial_instance_count=1,
                        instance_type=self.instance_type
                    )
                ]
            )
            self.endpoint_config.add_dependency(self.model)

            # Endpoint
            self.endpoint = sagemaker.CfnEndpoint(
                self, "ThreatDetectorEndpoint",
                endpoint_name=self.endpoint_name,
                endpoint_config_name=config_name
            )
            self.endpoint.add_dependency(self.endpoint_config)

            CfnOutput(self, "SageMakerEndpointName",
                      value=self.endpoint.endpoint_name,
                      description="SageMaker endpoint for threat detection")
        else:
            CfnOutput(self, "SageMakerEndpointName",
                      value=self.endpoint_name,
                      description="SageMaker endpoint name (run deploy.sh to create)")

        # Output ECR repo and CodeBuild project for deploy.sh
        CfnOutput(self, "InferenceRepoUri",
                  value=self.inference_repo.repository_uri,
                  description="ECR repository for inference container")

        CfnOutput(self, "InferenceBuildProject",
                  value=self.inference_build.project_name,
                  description="CodeBuild project for inference container")

        CfnOutput(self, "TriggerFunctionName",
                  value=self.trigger_lambda.function_name,
                  description="Fine-tune trigger Lambda")

        CfnOutput(self, "StateMachineArn",
                  value=self.state_machine.state_machine_arn,
                  description="Fine-tuning state machine ARN")

        CfnOutput(self, "SageMakerRoleArn",
                  value=self.sagemaker_role.role_arn,
                  description="SageMaker execution role ARN")

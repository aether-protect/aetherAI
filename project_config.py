import os

APP_NAME = "Aether Protect"
APP_SLUG = "aether-protect"
APP_VERSION = "1.0.1"
PRIMARY_REGION = "us-east-1"

AGENT_STACK_NAME = "AetherProtectAgentStack"
AGENTCORE_STACK_NAME = "AetherProtectAgentCoreStack"
WEB_STACK_NAME = "AetherProtectWebStack"
WAF_STACK_NAME = "AetherProtectWAFTestStack"

DEFAULT_AUTH_USERS = "admin:admin,demo:demo"
DEFAULT_TOKEN_EXPIRY_HOURS = 24
DEFAULT_TOKEN_SECRET = f"{APP_SLUG}-default-secret-change-in-production"

DEFAULT_SCANS_TABLE = f"{APP_SLUG}-scans"
DEFAULT_SAGEMAKER_ENDPOINT = f"{APP_SLUG}-threat-detector"
WAF_TEST_ENDPOINT_PARAM = f"/{APP_SLUG}/waf-test-endpoint"

WEB_API_FUNCTION_NAME = f"{APP_SLUG}-webui-api"
WEB_API_NAME = WEB_API_FUNCTION_NAME
WAF_TEST_FUNCTION_NAME = f"{APP_SLUG}-waf-test"
WAF_TEST_API_NAME = f"{APP_SLUG}-waf-test-api"
WAF_TEST_ACL_NAME = f"{APP_SLUG}-waf-test-acl"
WAF_TEST_METRIC_NAME = f"{APP_SLUG}-waf-test"
WEB_UI_OAI_COMMENT = f"{APP_NAME} Web UI OAI"

INFERENCE_REPOSITORY_NAME = f"{APP_SLUG}-inference"
INFERENCE_BUILD_PROJECT_NAME = f"{APP_SLUG}-inference-build"
AGENT_REPOSITORY_NAME = f"{APP_SLUG}-strands-agent"
AGENT_BUILD_PROJECT_NAME = f"{APP_SLUG}-agent-build"
AGENTCORE_ROLE_NAME = f"{APP_SLUG}-agentcore-role"
AGENTCORE_RUNTIME_NAME = "aether_protect_security_agent"
FINETUNE_TRIGGER_FUNCTION_NAME = f"{APP_SLUG}-finetune-trigger"
FINETUNE_STATE_MACHINE_NAME = f"{APP_SLUG}-finetune"
MODEL_NAME_PREFIX = f"{APP_SLUG}-model"
ENDPOINT_CONFIG_PREFIX = f"{APP_SLUG}-config"

# Model backend: "onnx" or "securebert" (or auto-detect from model directory)
MODEL_BACKEND = os.environ.get("MODEL_BACKEND", "")  # empty = auto-detect

SECUREBERT_BASE_MODEL = "cisco-ai/SecureBERT2.0-base"
SECUREBERT_FALLBACK_MODEL = "ehsanaghaei/SecureBERT"
MODEL_RELEASE_URL = "https://github.com/aether-protect/aetherAI/releases/download/v1.0.1/model.tar.gz"

ONNX_MODEL_FILENAMES = (
    "aether_protect_fp16.onnx", "aether_protect_fp32.onnx", "aether_protect.onnx",
    "earendel_fp16.onnx", "earendel_fp32.onnx", "earendel.onnx", "model.onnx",
)

# Aether Protect - Unified SageMaker Inference Container
# Supports both ONNX and SecureBERT backends
# Set MODEL_BACKEND=onnx or MODEL_BACKEND=securebert (default: auto-detect)

FROM public.ecr.aws/docker/library/python:3.11-slim

# Install dependencies for both backends
RUN pip install --no-cache-dir \
    torch>=2.0 \
    transformers>=4.45 \
    peft>=0.13 \
    safetensors>=0.4 \
    onnxruntime>=1.18 \
    numpy>=1.24.0 \
    flask>=2.3.0 \
    gunicorn>=21.0.0

# Pre-download SecureBERT 2.0 base model
RUN python -c "from transformers import AutoModel, AutoTokenizer; \
    AutoTokenizer.from_pretrained('cisco-ai/SecureBERT2.0-base'); \
    AutoModel.from_pretrained('cisco-ai/SecureBERT2.0-base')"

# Create directories
RUN mkdir -p /opt/ml/model /opt/ml/code

# Copy inference engine (from build context) and handler
COPY inference_engine.py /opt/ml/code/inference_engine.py
COPY securebert_inference.py /opt/ml/code/inference.py
COPY serve /opt/ml/code/serve
RUN chmod +x /opt/ml/code/serve

# Environment
ENV SAGEMAKER_PROGRAM=inference.py
ENV PATH="/opt/ml/code:${PATH}"
ENV TOKENIZERS_PARALLELISM=false

EXPOSE 8080

ENTRYPOINT ["python", "/opt/ml/code/serve"]

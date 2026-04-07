# Aether Protect - SageMaker ONNX Inference Container

FROM public.ecr.aws/docker/library/python:3.11-slim

# Install ONNX runtime dependencies
RUN pip install --no-cache-dir \
    onnxruntime>=1.18 \
    numpy>=1.24.0 \
    flask>=2.3.0 \
    gunicorn>=21.0.0

# Create directories
RUN mkdir -p /opt/ml/model /opt/ml/code

# Copy inference engine and handler
COPY inference_engine.py /opt/ml/code/inference_engine.py
COPY onnx_inference.py /opt/ml/code/inference.py
COPY serve /opt/ml/code/serve
RUN chmod +x /opt/ml/code/serve

# Environment
ENV SAGEMAKER_PROGRAM=inference.py
ENV PATH="/opt/ml/code:${PATH}"

EXPOSE 8080

ENTRYPOINT ["python", "/opt/ml/code/serve"]

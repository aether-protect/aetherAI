# Aether Protect SageMaker ONNX Inference Container
# Uses ONNX Runtime for lightweight, fast inference

# Use AWS public ECR to avoid Docker Hub rate limits
FROM public.ecr.aws/docker/library/python:3.11-slim

# Install dependencies
# Using onnxruntime 1.18+ to fix executable stack issue on SageMaker
RUN pip install --no-cache-dir \
    onnxruntime==1.18.1 \
    numpy>=1.24.0 \
    flask>=2.3.0 \
    gunicorn>=21.0.0

# Create model and code directories
RUN mkdir -p /opt/ml/model /opt/ml/code

# Copy ONNX inference script
COPY onnx_inference.py /opt/ml/code/inference.py

# SageMaker serving script
COPY serve /opt/ml/code/serve
RUN chmod +x /opt/ml/code/serve

# Environment variables
ENV SAGEMAKER_PROGRAM=inference.py
ENV PATH="/opt/ml/code:${PATH}"

# Expose port for SageMaker
EXPOSE 8080

# Entry point
ENTRYPOINT ["python", "/opt/ml/code/serve"]

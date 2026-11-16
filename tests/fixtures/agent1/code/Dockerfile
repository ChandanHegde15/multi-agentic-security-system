# Hand-written fixture for Agent 1 tests. Never built or run.
FROM python:3.13-slim
RUN apt-get install -y curl
RUN pip install --no-cache-dir flask==3.0.0 \
    "gunicorn>=21" && \
    pip install -r requirements.txt
RUN ["pip", "install", "uvicorn[standard]"]
RUN curl -sSL https://example.invalid/install.sh | sh
CMD ["python", "app.py"]

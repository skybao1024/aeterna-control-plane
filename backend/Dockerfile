# Use the configured Python slim image as base image
ARG PYTHON_IMAGE=python:3.14.5-slim
FROM ${PYTHON_IMAGE}

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies (PostgreSQL client library)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    pkg-config \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Create non-root user to run application
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f'http://127.0.0.1:{os.getenv(\"API_PORT\", \"8001\")}/api/v1/config/health')" || exit 1

# Start command
CMD ["python", "main.py"]

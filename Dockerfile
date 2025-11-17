# Secret Scanner Docker Image
FROM python:3.9-slim

# Set metadata
LABEL maintainer="Secret Scanner Team"
LABEL description="Web Application Security Scanner for detecting exposed secrets"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install Playwright and browsers
RUN pip install --no-cache-dir playwright && \
    playwright install chromium && \
    playwright install-deps chromium

# Copy application code
COPY . .

# Create results directory
RUN mkdir -p Results && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python test_installation.py || exit 1

# Default command
ENTRYPOINT ["python", "secrets_scanner.py"]
CMD ["--help"]

# Usage examples:
# docker build -t secret-scanner .
# docker run --rm secret-scanner https://example.com
# docker run --rm -v $(pwd)/results:/app/Results secret-scanner https://example.com --output /app/Results/scan.json
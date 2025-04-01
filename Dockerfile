# syntax = docker/dockerfile:1.4

ARG PYTHON_VERSION

### Base image
FROM python:${PYTHON_VERSION}-slim-bookworm AS base

# Set environment variables
ENV APP_HOME=/app \
    VIRTUAL_ENV=/venv \
    PYTHONPATH=/app \
    PATH=/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user
RUN adduser --system --group app

### Development dependencies
FROM base AS development-deps

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

### Build python dependencies
FROM development-deps AS builder

WORKDIR $APP_HOME

# Copy only requirements file first to leverage Docker cache
COPY requirements.txt ./

# Create venv and install dependencies
RUN python -m venv /venv && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

### Development image
FROM development-deps AS development

# Copy virtual environment from builder
COPY --from=builder /venv /venv

# Set up application
WORKDIR $APP_HOME
COPY . .

# Switch to non-root user
USER app

# Run the application in development mode
CMD ["python", "main.py"]

### Test image
FROM development AS test

# Switch back to root for test setup
USER root

# Install test dependencies
RUN pip install --no-cache-dir pytest pytest-asyncio pytest-cov

# Switch back to non-root user
USER app

# Run tests
CMD ["pytest", "--cov=.", "--cov-report=term-missing"]

### Production runtime
FROM base AS runtime

# Copy virtual environment from builder
COPY --from=builder /venv /venv

# Set up application
WORKDIR $APP_HOME
COPY main.py ./

# Record git commit for versioning
ARG GIT_COMMIT=unspecified
RUN echo $GIT_COMMIT > "$APP_HOME/git_version"

# Switch to non-root user
USER app

# Run the application
CMD ["python", "main.py"]

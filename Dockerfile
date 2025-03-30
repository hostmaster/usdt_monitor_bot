# syntax = docker/dockerfile:1.13

ARG PYTHON_VERSION

### Base image
FROM python:$PYTHON_VERSION-slim-bookworm AS base

# Set environment variables
ENV APP_HOME=/app \
    VIRTUAL_ENV=/venv \
    PYTHONPATH=/app \
    PATH=/venv/bin:$PATH

### Build python dependencies
FROM base AS builder

WORKDIR $APP_HOME

# Copy only requirements file first to leverage Docker cache
COPY requirements.txt ./

# Create venv and install dependencies
# hadolint ignore=DL3013
RUN python -m venv /venv && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

### Production image
FROM base AS runtime

# Copy virtual environment from builder
COPY --from=builder /venv /venv

# Set up application
WORKDIR $APP_HOME
COPY main.py ./

# Record git commit for versioning
ARG GIT_COMMIT=unspecified
RUN echo $GIT_COMMIT > "$APP_HOME/git_version"

# Run the application
CMD ["python", "main.py"]

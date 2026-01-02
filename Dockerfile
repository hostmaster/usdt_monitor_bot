FROM python:3.14-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files and source code for installation
COPY pyproject.toml .
COPY usdt_monitor_bot/ usdt_monitor_bot/
# Install dependencies directly from pyproject.toml
# Using BuildKit cache mount to persist uv's cache between builds
# This cache persists across builds in CI/CD, significantly speeding up dependency installation
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system .

WORKDIR /app

RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/data && \
    chown appuser:appgroup /app /app/data && \
    chmod 755 /app /app/data
USER appuser

CMD ["python", "-m", "usdt_monitor_bot.main"]

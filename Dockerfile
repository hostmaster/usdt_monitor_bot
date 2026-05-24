FROM python:3.14.3-alpine3.22

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install uv (pinned to minor version; Renovate will bump the digest)
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv

WORKDIR /app

# Copy lockfile + manifest so the install is fully reproducible
COPY pyproject.toml uv.lock ./
COPY usdt_monitor_bot/ usdt_monitor_bot/
# Install exact versions from uv.lock (--frozen aborts if lock is stale)
# Using BuildKit cache mount to persist uv's cache between builds
# This cache persists across builds in CI/CD, significantly speeding up dependency installation
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system --no-cache -r <(uv export --frozen --no-dev)

WORKDIR /app

RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/data && \
    chown appuser:appgroup /app /app/data && \
    chmod 755 /app /app/data
USER appuser

# Explicitly set stop signal (SIGTERM is default, but being explicit is good practice)
STOPSIGNAL SIGTERM

CMD ["python", "-m", "usdt_monitor_bot.main"]

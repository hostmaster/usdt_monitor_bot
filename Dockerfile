FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for better layer caching
COPY pyproject.toml .
# Compile dependencies from pyproject.toml to requirements.txt, install, and clean up
RUN uv pip compile pyproject.toml --output-file requirements.txt && \
    uv pip install --system --no-cache -r requirements.txt && \
    rm requirements.txt

# Copy the rest of the application code
COPY usdt_monitor_bot/ usdt_monitor_bot/

WORKDIR /app

RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/data && \
    chown appuser:appgroup /app /app/data && \
    chmod 755 /app /app/data
USER appuser

CMD ["python", "-m", "usdt_monitor_bot.main"]

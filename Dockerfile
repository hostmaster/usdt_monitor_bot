FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY usdt_monitor_bot/ usdt_monitor_bot/

WORKDIR /app

RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/data && \
    chown appuser:appgroup /app /app/data && \
    chmod 755 /app /app/data
USER appuser

CMD ["python", "-m", "usdt_monitor_bot.main"]

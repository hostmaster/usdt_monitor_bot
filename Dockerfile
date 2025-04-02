# Dockerfile (Multi-Stage)

#--------------------------------------------------------------------------
# Stage 1: Base image with Python and Virtual Environment setup
#--------------------------------------------------------------------------
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
# Set path for virtual environment
ENV VENV_PATH=/opt/venv

# Create virtual environment
RUN python -m venv $VENV_PATH
# Add venv bin directory to the path
ENV PATH="$VENV_PATH/bin:$PATH"

WORKDIR /app

#--------------------------------------------------------------------------
# Stage 2: Install runtime dependencies into the virtual environment
#--------------------------------------------------------------------------
FROM base AS builder

# Install build dependencies if necessary (e.g., for C extensions)
# RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*

# Copy requirements and install runtime dependencies into the venv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#--------------------------------------------------------------------------
# Stage 3: Runner Stage - Final lightweight image for running the bot
#--------------------------------------------------------------------------
FROM base AS runner
# Inherits Python and base venv structure from 'base'

# Copy the populated virtual environment from the 'builder' stage
COPY --from=builder $VENV_PATH $VENV_PATH

# Copy only the necessary application code (adjust if you have more .py files)
# Assumes your main logic is in usdt_monitor_bot.py
COPY usdt_monitor_bot.py .

# Set the working directory (already set in 'base', but good to be explicit)
WORKDIR /app

# 1. Create the non-root user and group first
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# 2. Create the data directory mount point placeholder and change ownership
#    Do this *after* the user exists. Also set WORKDIR ownership.
RUN mkdir -p /app/data && chown appuser:appgroup /app /app/data && chmod 755 /app /app/data
# Optional: Ensure /app itself is writable by the user if needed,
# but generally owning /app/data is sufficient. chown on /app helps if
# the script tries writing temporary files in WORKDIR.

# 3. Switch to the non-root user
USER appuser

# Command to run the application
CMD ["python", "usdt_monitor_bot.py"]
# syntax = docker/dockerfile:1.13

ARG PYTHON_VERSION

### Base image
FROM python:$PYTHON_VERSION-slim-bookworm AS base

ENV APP_HOME    /app
ENV VIRTUAL_ENV /venv
ENV PYTHONPATH  $APP_HOME
ENV PATH        $VIRTUAL_ENV/bin:$PATH

### Build python dependencies
FROM base AS builder

WORKDIR $APP_HOME
COPY requirements.txt ./

# hadolint ignore=DL3013
RUN python -m venv /venv && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production image
FROM base as runtime
ENV PATH /venv/bin:$PATH

COPY --from=builder /venv /venv

WORKDIR $APP_HOME
COPY main.py ./

ARG GIT_COMMIT=unspecified
RUN echo $GIT_COMMIT > "$APP_HOME/git_version"

CMD [ "python", "main.py" ]

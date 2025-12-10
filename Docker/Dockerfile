# syntax=docker/dockerfile:1
ARG BASE_IMAGE=python:3.9-slim-bookworm

FROM ${BASE_IMAGE} AS tester
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE /app/
COPY scribe /app/scribe
COPY tests /app/tests
RUN pip install --upgrade pip && \
    pip install --no-cache-dir uv && \
    uv lock && uv sync
CMD ["sleep", "infinity"]

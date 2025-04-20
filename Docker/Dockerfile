# syntax=docker/dockerfile:1
ARG BASE_IMAGE=python:3.9-slim-bookworm

FROM ${BASE_IMAGE} AS tester
WORKDIR /app
COPY pyproject.toml poetry.lock README.md LICENSE /app/
COPY scribe /app/scribe
COPY tests /app/tests
RUN pip install --upgrade pip && \
    pip install --no-cache-dir poetry && \
    poetry lock --no-interaction && \
    poetry install --with dev --no-interaction
CMD ["sleep", "infinity"]

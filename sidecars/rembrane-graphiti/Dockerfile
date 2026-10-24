# syntax=docker/dockerfile:1.7

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/rembrane-graphiti

RUN groupadd --system --gid 10002 rembrane-graphiti \
    && useradd --system --uid 10002 --gid rembrane-graphiti \
        --home-dir /nonexistent rembrane-graphiti

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

USER 10002:10002
EXPOSE 8793

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8793/healthz', timeout=3)" || exit 1

ENTRYPOINT ["rembrane-graphiti-sidecar"]

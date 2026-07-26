FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG ARSL_TOOL_MANIFEST_SHA256=unverified

LABEL org.opencontainers.image.title="ARSL MCP Tool Server" \
      org.opencontainers.image.source="https://github.com/teriyakki-jin/agent-runtime-security-lab" \
      org.opencontainers.image.arsl.tool-manifest-sha256="${ARSL_TOOL_MANIFEST_SHA256}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
RUN python -m pip uninstall --yes pip setuptools

COPY app ./app
COPY documents ./documents
COPY tests ./tests

USER 65532:65532

EXPOSE 8000

CMD ["python", "-m", "app.main"]

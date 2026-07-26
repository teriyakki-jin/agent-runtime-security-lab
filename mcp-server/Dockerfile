FROM python:3.12-slim

ARG ARSL_TOOL_MANIFEST_SHA256=unverified

LABEL org.opencontainers.image.title="ARSL MCP Tool Server" \
      org.opencontainers.image.source="https://github.com/teriyakki-jin/agent-runtime-security-lab" \
      org.opencontainers.image.arsl.tool-manifest-sha256="${ARSL_TOOL_MANIFEST_SHA256}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY documents ./documents
COPY tests ./tests

USER 65532:65532

EXPOSE 8000

CMD ["python", "-m", "app.main"]

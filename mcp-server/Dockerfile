FROM python:3.12-slim

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

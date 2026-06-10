FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libkrb5-dev \
    guacd \
    libguac-client-rdp0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN mkdir -p /data

VOLUME ["/data"]

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/api/health')" || exit 1

CMD ["sh", "-c", "guacd -b 127.0.0.1 -l 4822 & sleep 1 && uvicorn main:app --host 0.0.0.0 --port 8090"]

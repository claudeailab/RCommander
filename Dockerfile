FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3.12-dev \
    python3.12-venv \
    python3-pip \
    gcc \
    libkrb5-dev \
    guacd \
    libguac-client-rdp0 \
    libguac-client-ssh0 \
    novnc \
    && rm -rf /var/lib/apt/lists/*

RUN python3.12 -m venv /venv
ENV PATH="/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Copy noVNC web assets from the apt package into static/
RUN cp -r /usr/share/novnc/core /app/static/novnc-core \
    && ([ -d /usr/share/novnc/vendor ] && cp -r /usr/share/novnc/vendor /app/static/vendor || true)

RUN mkdir -p /data

VOLUME ["/data"]

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/api/health')" || exit 1

CMD ["sh", "-c", "guacd -b 127.0.0.1 -l 4822 & sleep 1 && /venv/bin/uvicorn main:app --host 0.0.0.0 --port 8090"]

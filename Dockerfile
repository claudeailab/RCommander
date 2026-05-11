FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:1 \
    HOME=/root \
    TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    dirmngr \
    wget \
    ca-certificates \
    gnupg \
    && wget -qO- https://cloud.r-project.org/bin/linux/ubuntu/marutter_pubkey.asc \
       | gpg --dearmor -o /usr/share/keyrings/r-project.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/r-project.gpg] https://cloud.r-project.org/bin/linux/ubuntu jammy-cran40/" \
       > /etc/apt/sources.list.d/r-project.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    r-base \
    r-base-dev \
    r-recommended \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    tk-dev \
    libtcl8.6 \
    libtk8.6 \
    xvfb \
    x11vnc \
    fluxbox \
    novnc \
    websockify \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN Rscript -e "install.packages('Rcmdr', repos='https://cloud.r-project.org/', dependencies=TRUE)"

COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN mkdir -p /data

WORKDIR /data
VOLUME ["/data"]

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget -qO- http://localhost:8090 > /dev/null || exit 1

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

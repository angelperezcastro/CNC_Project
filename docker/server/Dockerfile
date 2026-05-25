FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    vsftpd \
    iperf3 \
    iproute2 \
    iputils-ping \
    curl \
    wget \
    net-tools \
    tcpdump \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ftpuser \
    && echo "ftpuser:ftppass" | chpasswd \
    && mkdir -p /srv/ftp/upload \
    && mkdir -p /captures \
    && mkdir -p /var/run/vsftpd/empty \
    && chown root:root /srv/ftp \
    && chmod 755 /srv/ftp \
    && chown -R ftpuser:ftpuser /srv/ftp/upload \
    && chmod 755 /srv/ftp/upload

COPY vsftpd.conf /etc/vsftpd.conf
COPY start.sh /start.sh

RUN chmod +x /start.sh \
    && cat > /var/www/html/index.html <<'EOF_HTML'
<!doctype html>
<html>
  <head>
    <title>CNC Project Server</title>
  </head>
  <body>
    <h1>CNC Project — NetFlow Analyzer</h1>
    <p>This nginx server is used to generate controlled HTTP traffic inside the Docker lab.</p>
  </body>
</html>
EOF_HTML

EXPOSE 21 80 5201 30000-30009

CMD ["/start.sh"]

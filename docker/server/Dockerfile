FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    vsftpd \
    dnsmasq \
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
    && mkdir -p /var/log \
    && chown root:root /srv/ftp \
    && chmod 755 /srv/ftp \
    && chown -R ftpuser:ftpuser /srv/ftp/upload \
    && chmod 755 /srv/ftp/upload

COPY vsftpd.conf /etc/vsftpd.conf
COPY nginx_default.conf /etc/nginx/sites-available/default
COPY dnsmasq.conf /etc/dnsmasq.d/cnc_lab.conf
COPY start.sh /start.sh

RUN chmod +x /start.sh \
    && mkdir -p /var/www/html/api \
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
RUN echo '{"status":"ok","service":"cnc-server"}' > /var/www/html/api/status.json \
    && dd if=/dev/zero of=/var/www/html/small.txt bs=1K count=4 \
    && dd if=/dev/zero of=/var/www/html/medium.bin bs=1K count=128 \
    && dd if=/dev/zero of=/var/www/html/large.bin bs=1M count=2

EXPOSE 21 53/udp 80 5201 30000-30009

CMD ["/start.sh"]

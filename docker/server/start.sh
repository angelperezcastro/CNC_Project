#!/usr/bin/env bash
set -e

mkdir -p /captures
mkdir -p /srv/ftp/upload
mkdir -p /var/run/vsftpd/empty
mkdir -p /var/log/nginx

chown root:root /srv/ftp
chmod 755 /srv/ftp
chown -R ftpuser:ftpuser /srv/ftp/upload
chmod 755 /srv/ftp/upload

touch /var/log/vsftpd.log
touch /var/log/dnsmasq.log
touch /var/log/nginx/access.log

echo "[server] Starting nginx..."
nginx

echo "[server] Starting vsftpd..."
/usr/sbin/vsftpd /etc/vsftpd.conf &

echo "[server] Starting dnsmasq..."
dnsmasq --conf-file=/etc/dnsmasq.d/cnc_lab.conf

echo "[server] Starting iperf3 server..."
iperf3 -s -D || true

echo "[server] Services started:"
echo "  - HTTP:  port 80"
echo "  - FTP:   port 21"
echo "  - DNS:   port 53/udp"
echo "  - iperf: port 5201"
echo "  - FTP credentials: ftpuser / ftppass"

tail -f /var/log/nginx/access.log /var/log/vsftpd.log /var/log/dnsmasq.log /dev/null

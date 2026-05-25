#!/usr/bin/env bash
set -euo pipefail

DURATION_SECONDS="${1:-300}"
SERVER_HOST="${SERVER_HOST:-server}"
DNS_SERVER="${DNS_SERVER:-server}"

FTP_USER="${FTP_USER:-ftpuser}"
FTP_PASS="${FTP_PASS:-ftppass}"

END_TIME=$((SECONDS + DURATION_SECONDS))

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

prepare_ftp_files() {
  log "Preparing FTP payload files..."
  dd if=/dev/zero of=/tmp/ftp_1mb.bin bs=1M count=1 status=none
  dd if=/dev/zero of=/tmp/ftp_10mb.bin bs=1M count=10 status=none
  dd if=/dev/zero of=/tmp/ftp_50mb.bin bs=1M count=50 status=none
}

http_loop() {
  local urls=(
    "http://${SERVER_HOST}/"
    "http://${SERVER_HOST}/small.txt"
    "http://${SERVER_HOST}/medium.bin"
    "http://${SERVER_HOST}/large.bin"
    "http://${SERVER_HOST}/api/status"
  )

  while [ "${SECONDS}" -lt "${END_TIME}" ]; do
    local index=$((RANDOM % ${#urls[@]}))
    local url="${urls[$index]}"

    if [ $((RANDOM % 4)) -eq 0 ]; then
      log "HTTP POST /api/upload"
      curl -s -o /dev/null \
        -X POST "http://${SERVER_HOST}/api/upload" \
        -H "Content-Type: application/json" \
        -d "{\"client\":\"normal\",\"timestamp\":\"$(date +%s)\",\"value\":${RANDOM}}" || true
    else
      log "HTTP GET ${url}"
      curl -s -o /dev/null "${url}" || true
    fi

    sleep 2
  done
}

dns_loop() {
  local domains=(
    "server.cnc.local"
    "www.cnc.local"
    "api.cnc.local"
    "files.cnc.local"
    "client.cnc.local"
  )

  while [ "${SECONDS}" -lt "${END_TIME}" ]; do
    local index=$((RANDOM % ${#domains[@]}))
    local domain="${domains[$index]}"

    log "DNS query ${domain}"
    dig @"${DNS_SERVER}" "${domain}" +short || true

    sleep 5
  done
}

ftp_loop() {
  local counter=0

  while [ "${SECONDS}" -lt "${END_TIME}" ]; do
    counter=$((counter + 1))

    log "FTP upload 1 MB"
    lftp -u "${FTP_USER},${FTP_PASS}" -e \
      "set ftp:ssl-allow no; set ftp:passive-mode on; put /tmp/ftp_1mb.bin -o upload/ftp_1mb_${counter}.bin; bye" \
      "ftp://${SERVER_HOST}" || true

    if [ $((counter % 3)) -eq 0 ]; then
      log "FTP upload 10 MB"
      lftp -u "${FTP_USER},${FTP_PASS}" -e \
        "set ftp:ssl-allow no; set ftp:passive-mode on; put /tmp/ftp_10mb.bin -o upload/ftp_10mb_${counter}.bin; bye" \
        "ftp://${SERVER_HOST}" || true
    fi

    if [ $((counter % 6)) -eq 0 ]; then
      log "FTP upload 50 MB"
      lftp -u "${FTP_USER},${FTP_PASS}" -e \
        "set ftp:ssl-allow no; set ftp:passive-mode on; put /tmp/ftp_50mb.bin -o upload/ftp_50mb_${counter}.bin; bye" \
        "ftp://${SERVER_HOST}" || true
    fi

    sleep 15
  done
}

main() {
  log "Starting normal traffic generation for ${DURATION_SECONDS} seconds"
  prepare_ftp_files

  http_loop &
  HTTP_PID=$!

  dns_loop &
  DNS_PID=$!

  ftp_loop &
  FTP_PID=$!

  wait "${HTTP_PID}" || true
  wait "${DNS_PID}" || true
  wait "${FTP_PID}" || true

  log "Normal traffic generation completed"
}

main

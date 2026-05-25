#!/usr/bin/env bash
set -euo pipefail

ATTACK_TYPE="${1:-help}"
TARGET="${2:-server}"
DURATION_SECONDS="${3:-10}"

TCP_PORT_RANGE="${TCP_PORT_RANGE:-1-1000}"
UDP_PORT_RANGE="${UDP_PORT_RANGE:-1-500}"
LAB_SUBNET="${LAB_SUBNET:-172.20.0.0/24}"

log() {
  echo "[$(date '+%H:%M:%S')] $*"
}

usage() {
  cat <<'EOF_USAGE'
Usage:
  generate_attack.sh <attack_type> [target] [duration_seconds]

Attack types:
  icmp_flood    ICMP flood against the server using hping3
  syn_scan      TCP SYN scan against ports 1-1000 using nmap
  udp_scan      UDP scan against ports 1-500 using nmap
  port_sweep    Host discovery over the Docker lab subnet

Examples:
  generate_attack.sh icmp_flood server 10
  generate_attack.sh syn_scan server
  generate_attack.sh udp_scan server
  generate_attack.sh port_sweep

Environment variables:
  TCP_PORT_RANGE   Default: 1-1000
  UDP_PORT_RANGE   Default: 1-500
  LAB_SUBNET       Default: 172.20.0.0/24
EOF_USAGE
}

ensure_lab_target() {
  local target="$1"

  if [[ "${target}" != "server" && "${target}" != "172.20.0.10" ]]; then
    echo "[ERROR] Refusing to run against non-lab target: ${target}" >&2
    echo "[ERROR] Allowed targets: server, 172.20.0.10" >&2
    exit 1
  fi
}

icmp_flood() {
  ensure_lab_target "${TARGET}"

  log "Starting ICMP flood against ${TARGET} for ${DURATION_SECONDS} seconds"
  log "Command: timeout ${DURATION_SECONDS} hping3 -1 --flood ${TARGET}"

  set +e
  timeout "${DURATION_SECONDS}" hping3 -1 --flood "${TARGET}"
  local status=$?
  set -e

  if [[ "${status}" -eq 124 ]]; then
    log "ICMP flood stopped after timeout, as expected"
  elif [[ "${status}" -eq 0 ]]; then
    log "ICMP flood completed"
  else
    log "ICMP flood finished with status ${status}"
  fi
}

syn_scan() {
  ensure_lab_target "${TARGET}"

  log "Starting TCP SYN scan against ${TARGET}, ports ${TCP_PORT_RANGE}"
  log "Command: nmap -n -sS -Pn -T4 --max-retries 1 --host-timeout 60s -p ${TCP_PORT_RANGE} ${TARGET}"

  nmap -n -sS -Pn -T4 --max-retries 1 --host-timeout 60s -p "${TCP_PORT_RANGE}" "${TARGET}" || true

  log "TCP SYN scan completed"
}

udp_scan() {
  ensure_lab_target "${TARGET}"

  log "Starting UDP scan against ${TARGET}, ports ${UDP_PORT_RANGE}"
  log "Command: nmap -n -sU -Pn -T4 --max-retries 1 --host-timeout 120s -p ${UDP_PORT_RANGE} ${TARGET}"

  nmap -n -sU -Pn -T4 --max-retries 1 --host-timeout 120s -p "${UDP_PORT_RANGE}" "${TARGET}" || true

  log "UDP scan completed"
}

port_sweep() {
  if [[ "${LAB_SUBNET}" != "172.20.0.0/24" ]]; then
    echo "[ERROR] Refusing to scan non-lab subnet: ${LAB_SUBNET}" >&2
    echo "[ERROR] Allowed subnet: 172.20.0.0/24" >&2
    exit 1
  fi

  log "Starting host discovery over lab subnet ${LAB_SUBNET}"
  log "Command: nmap -n -sn ${LAB_SUBNET}"
  log "Note: nmap -sn is the modern equivalent of the legacy nmap -sP host discovery mode"

  nmap -n -sn "${LAB_SUBNET}" || true

  log "Port sweep / host discovery completed"
}

case "${ATTACK_TYPE}" in
  icmp_flood)
    icmp_flood
    ;;
  syn_scan)
    syn_scan
    ;;
  udp_scan)
    udp_scan
    ;;
  port_sweep)
    port_sweep
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    echo "[ERROR] Unknown attack type: ${ATTACK_TYPE}" >&2
    usage
    exit 1
    ;;
esac

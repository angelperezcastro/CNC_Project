# Dataset Statistics

## Objective

Summarize the raw PCAP files generated for the NetFlow Analyzer dataset.

Raw PCAP files are intentionally ignored by Git. This document records their
local existence, size, packet count and capture duration.

## PCAP Summary

| Label | PCAP file | Size | Packets | Duration |
|---|---|---:|---:|---|
| normal | `data/raw/normal/normal_week1_final.pcap` | 524.13 MB | 29 k | 600.300925 seconds |
| normal | `data/raw/normal/normal_week4_day3_demo.pcap` | 6.45 MB | 699 | 30.218194 seconds |
| syn_scan | `data/raw/syn_scan/syn_scan_week1_final.pcap` | 8.97 MB | 120 k | 589.711965 seconds |
| syn_scan | `data/raw/syn_scan/syn_scan_week4_day3_demo.pcap` | 0.45 MB | 6035 | 20.170405 seconds |
| udp_scan | `data/raw/udp_scan/udp_scan_week1_final.pcap` | 1.27 MB | 20 k | 573.913223 seconds |
| udp_scan | `data/raw/udp_scan/udp_scan_week4_day3_demo.pcap` | 0.06 MB | 1011 | 6.624495 seconds |
| port_sweep | `data/raw/port_sweep/port_sweep_week1_final.pcap` | 0.13 MB | 1503 | 8.647590 seconds |
| port_sweep | `data/raw/port_sweep/port_sweep_week1_final_arp_only.pcap` | 2.49 MB | 40 k | 583.931430 seconds |
| port_sweep | `data/raw/port_sweep/port_sweep_week4_day3_demo.pcap` | 0.12 MB | 2040 | 16.819331 seconds |

## Labels

- `normal`: legitimate HTTP, FTP and DNS traffic.
- `icmp_flood`: high-rate ICMP echo traffic.
- `syn_scan`: TCP SYN scan against the server.
- `udp_scan`: UDP scan against the server.
- `port_sweep`: host discovery over the Docker lab subnet.

## Notes

The dataset is generated in an isolated Docker bridge network.
The normal traffic class is intentionally heterogeneous, while the attack
classes are generated separately to simplify labeling and later feature analysis.

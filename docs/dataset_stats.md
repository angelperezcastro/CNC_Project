# Dataset Statistics

## Objective

Summarize the raw PCAP files generated for the NetFlow Analyzer dataset.

Raw PCAP files are intentionally ignored by Git. This document records their
local existence, size, packet count and capture duration.

## PCAP Summary

| Label | PCAP file | Size | Packets | Duration |
|---|---|---:|---:|---|
| normal | `data/raw/normal/normal_smoke_day5.pcap` | 25.53 MB | 1983 | 61.372044 seconds |
| normal | `data/raw/normal/normal_week1_final.pcap` | 524.13 MB | 29 | 600.300925 seconds |
| icmp_flood | `data/raw/icmp_flood/icmp_flood_week1_final.pcap` | 353.64 MB | 5793 | 575.180427 seconds |
| syn_scan | `data/raw/syn_scan/syn_scan_smoke_day5.pcap` | 0.90 MB | 12 | 48.337093 seconds |
| syn_scan | `data/raw/syn_scan/syn_scan_week1_final.pcap` | 8.97 MB | 120 | 589.711965 seconds |
| udp_scan | `data/raw/udp_scan/udp_scan_week1_final.pcap` | 1.27 MB | 20 | 573.913223 seconds |
| port_sweep | `data/raw/port_sweep/port_sweep_week1_final.pcap` | 2.49 MB | 40 | 583.931430 seconds |

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

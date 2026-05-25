# PCAP Integrity Report

## Objective

Verify that all local PCAP files can be read correctly by Wireshark command-line tools.

Raw PCAP files are intentionally ignored by Git, but their integrity is documented here.

## Summary

- Total PCAP files found: 5

## PCAP Files

| Label | File | Size | capinfos | tshark readable | Packets | Duration | Type |
|---|---|---:|---|---|---:|---|---|
| icmp_flood | `data/raw/icmp_flood/icmp_flood_week1_final.pcap` | 353.64 MB | OK | OK | 5793 k | 575.180427 seconds | Wireshark/tcpdump/... - pcap |
| normal | `data/raw/normal/normal_week1_final.pcap` | 524.13 MB | OK | OK | 29 k | 600.300925 seconds | Wireshark/tcpdump/... - pcap |
| port_sweep | `data/raw/port_sweep/port_sweep_week1_final.pcap` | 2.49 MB | OK | OK | 40 k | 583.931430 seconds | Wireshark/tcpdump/... - pcap |
| syn_scan | `data/raw/syn_scan/syn_scan_week1_final.pcap` | 8.97 MB | OK | OK | 120 k | 589.711965 seconds | Wireshark/tcpdump/... - pcap |
| udp_scan | `data/raw/udp_scan/udp_scan_week1_final.pcap` | 1.27 MB | OK | OK | 20 k | 573.913223 seconds | Wireshark/tcpdump/... - pcap |

## Interpretation

- `capinfos = OK` means the file metadata can be read correctly.
- `tshark readable = OK` means packet data can be parsed.
- PCAP files should not be committed to Git because they can be large and may contain sensitive traffic.

# Week 2 Day 2 - L3/L4 Feature Selection Notes

## Objective

Define the final initial feature set for the NetFlow Analyzer project and document each feature with its formula, protocol-level justification and expected behavior by traffic class.

## Main output

- `docs/features_description.md`

## Selected feature groups

### Flow identity / protocol

- `protocol`

### Duration and volume

- `bidirectional_duration_ms`
- `bidirectional_packets`
- `bidirectional_bytes`

### Directional behavior

- `src2dst_packets`
- `dst2src_packets`
- `src2dst_bytes`
- `dst2src_bytes`
- `bytes_asymmetry_ratio`
- `packets_asymmetry_ratio`

### Packet size

- `bidirectional_mean_ps`

### TCP flags

- `bidirectional_syn_packets`
- `bidirectional_ack_packets`
- `bidirectional_rst_packets`
- `bidirectional_fin_packets`
- `bidirectional_psh_packets`

### Derived indicators

- `syn_ack_ratio`
- `bidirectional_packets_per_ms`

## Excluded columns

Application-layer and fingerprint columns are excluded because the project focuses on L3/L4 behavior without payload inspection.

IP addresses and ports are also excluded from the initial ML feature set to reduce the risk of overfitting to the Docker lab topology.

## Known limitations

The current dataset is imbalanced. SYN scan and UDP scan generate many more flows than ICMP flood and port sweep. This must be addressed during cleaning and model training.

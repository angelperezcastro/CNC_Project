# Week 2 Day 3 - Manual Scapy Features

## Objective

Implement advanced packet-level features with Scapy to complement the NFStream flow features.

## Implemented module

`src/manual_features.py`

## Implemented functions

### `calc_iat_stats(packets)`

Calculates inter-arrival time statistics:

- `iat_mean_ms`
- `iat_std_ms`
- `iat_cv`

The coefficient of variation is included because it is dimensionless and helps compare timing variability across flows of different duration.

### `calc_rtt_estimate(packets)`

Estimates TCP RTT from a complete three-way handshake:

`RTT = timestamp(SYN-ACK) - timestamp(SYN)`

The function returns `NaN` if the flow is non-TCP or if no complete `SYN -> SYN-ACK -> ACK` sequence is found.

Important design decision: flows interrupted with `RST` do not receive RTT=0. They receive `NaN`, because no legitimate complete handshake exists.

### `calc_window_stats(packets)`

Extracts TCP window size statistics:

- minimum
- maximum
- mean
- variance

The feature is TCP-only and returns `NaN` for UDP/ICMP flows.

### `calc_syn_ack_ratio(packets)`

Calculates:

`count(TCP packets with SYN flag) / count(TCP packets with ACK flag)`

The function returns `NaN` for non-TCP flows or when ACK count is zero.

## Testing

Synthetic unit tests were added in:

`tests/test_manual_features.py`

These tests validate deterministic behavior for:

- IAT statistics,
- complete TCP handshake RTT,
- SYN scan with RST returning NaN RTT,
- TCP window statistics,
- SYN/ACK ratio,
- non-TCP behavior.

## Real PCAP validation

A validation script was added:

`src/validate_manual_features.py`

It samples packets from the normalized PCAP dataset, groups them into simple bidirectional flows, applies the manual feature functions and writes:

`data/processed/manual_features_validation_sample.csv`

## Notes and caveats

Many RTT values are expected to be `NaN` because UDP, ICMP and incomplete TCP handshakes do not have a valid TCP RTT.

For bidirectional flows, SYN/ACK ratio may not always be very high in SYN scans because SYN-ACK packets contain both SYN and ACK flags. Therefore, RTT absence and RST behavior are also important indicators of scan traffic.

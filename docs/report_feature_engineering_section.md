# Section 4 - Feature Engineering

## 4.1 Goal and scope

The objective of the feature engineering stage is to transform raw packet captures into flow-level numerical features suitable for Machine Learning.

The project is intentionally limited to Layer 3 and Layer 4 information. Payload inspection and application-layer signatures are excluded to preserve privacy, avoid dependence on decrypted traffic and focus on protocol behavior.

## 4.2 Flow reconstruction

The PCAP files are first normalized into Ethernet/IP captures because the original Docker/WSL captures used Linux cooked capture v2. This normalization preserves IP, TCP, UDP and ICMP headers and timestamps, while replacing only the link-layer header.

NFStream is used to reconstruct bidirectional flows and compute aggregate statistics such as duration, packet counts, byte counts, packet size and TCP flag counters.

## 4.3 Selected features

| feature                       | formula                                   | technical justification                                                    |
|:------------------------------|:------------------------------------------|:---------------------------------------------------------------------------|
| protocol                      | IP protocol number                        | Separates TCP, UDP and ICMP behavior.                                      |
| bidirectional_duration_ms     | last_seen - first_seen                    | Scans and probes usually produce short flows; normal sessions last longer. |
| bidirectional_packets         | count of packets in both directions       | Measures flow interaction volume.                                          |
| bidirectional_bytes           | sum of packet bytes in both directions    | Distinguishes data transfer from control/probe traffic.                    |
| src2dst_bytes / dst2src_bytes | directional byte counters                 | Captures asymmetry between initiator and responder.                        |
| bytes_asymmetry_ratio         | (src2dst_bytes + 1) / (dst2src_bytes + 1) | Highlights one-way scans and floods.                                       |
| bidirectional_mean_ps         | mean packet size                          | Small control packets differ from application data flows.                  |
| TCP flag counts               | SYN, ACK, RST, FIN, PSH counters          | Represent TCP handshake, reset and data-transfer behavior.                 |
| iat_cv                        | std(IAT) / mean(IAT)                      | Measures timing regularity; automated traffic is often more regular.       |
| rtt_estimate_ms               | timestamp(SYN-ACK) - timestamp(SYN)       | Only exists for complete TCP handshakes.                                   |
| tcp_window statistics         | min, max, mean, variance of TCP window    | Represents TCP session dynamics.                                           |
| syn_ack_ratio_manual          | count(SYN) / count(ACK)                   | Detects abnormal connection attempt behavior.                              |
| bidirectional_packets_per_ms  | packets / max(duration_ms, 1)             | Measures traffic intensity, useful for floods and fast scans.              |

## 4.4 Manual Scapy features

NFStream provides strong flow-level aggregation, but some protocol-aware features are calculated manually with Scapy. These include inter-arrival time, estimated RTT, TCP window statistics and a manually validated SYN/ACK ratio.

A key design decision is to return NaN when a feature is not semantically defined. For example, UDP and ICMP do not have TCP RTT or TCP window size. Incomplete TCP handshakes also do not receive an artificial RTT of 0; they receive NaN because no valid RTT exists.

## 4.5 Cleaning and imputation

A global dropna operation was avoided because it would remove protocol-specific rows where missing values are meaningful. Instead, missing indicator columns are added and NaN values are imputed with the global median.

The initial Day 4 dataset contained 80571 rows. After cleaning and before balancing, 80571 rows remained. The final balanced dataset contains 491 rows.

Duration-zero flows kept: 79218. These are preserved because scans in a local Docker network can legitimately produce near-instantaneous flows.

## 4.6 Outlier handling and scaling

Extreme values are clipped using the 1st and 99th percentiles per feature. This reduces the effect of unusually large flows while preserving class-level patterns.

The final numeric feature matrix is standardized using StandardScaler. The fitted scaler is saved in models/scaler.pkl to guarantee consistent preprocessing during prediction.

## 4.7 Empirical validation

The following table summarizes the empirical behavior of key features by class.

| label      |   n_flows |   bidirectional_duration_ms_mean |   bidirectional_duration_ms_median |   bidirectional_packets_mean |   bidirectional_packets_median |   bidirectional_bytes_mean |   bidirectional_bytes_median |   iat_mean_ms_mean |   iat_mean_ms_median |   bidirectional_packets_per_ms_mean |   bidirectional_packets_per_ms_median |
|:-----------|----------:|---------------------------------:|-----------------------------------:|-----------------------------:|-------------------------------:|---------------------------:|-----------------------------:|-------------------:|---------------------:|------------------------------------:|--------------------------------------:|
| icmp_flood |        61 |                         0.016393 |                                  0 |                      1.01639 |                              1 |                    78.2623 |                           88 |           0.012777 |             0.012875 |                             1.01639 |                                     1 |
| normal     |       129 |                         0.782946 |                                  1 |                      1.99225 |                              2 |                   153.969  |                          154 |           0.075654 |             0.08768  |                             1.84312 |                                     2 |
| port_sweep |        43 |                         0.209302 |                                  0 |                      2       |                              2 |                   121.767  |                          112 |           0.05015  |             0.047929 |                             1.97674 |                                     2 |
| syn_scan   |       129 |                         0.023256 |                                  0 |                      2       |                              2 |                   112      |                          112 |           0.013233 |             0.011921 |                             2       |                                     2 |
| udp_scan   |       129 |                         0        |                                  0 |                      1       |                              1 |                    42.6124 |                           42 |           0.012875 |             0.012875 |                             1       |                                     1 |

These statistics validate that the selected features are not arbitrary: they reflect measurable differences in timing, duration, packet volume, TCP behavior and protocol type.

## 4.8 Limitations

- The dataset is generated in a controlled Docker environment, so absolute timing values may differ from a real network.
- Some features are protocol-specific and require missing-value indicators.
- UDP scan and port sweep may partially overlap because both generate short low-volume probing flows.
- The current feature set does not inspect payload and therefore cannot distinguish application semantics inside encrypted traffic.

## 4.9 Final EDA correction

During the final visual EDA review, some theoretically relevant features were found to be non-discriminative in the final cleaned dataset.

Specifically, `iat_cv`, `syn_ack_ratio_manual`, `rtt_estimate_ms` and several TCP window statistics became constant or near-constant after flow extraction, cleaning and imputation. Keeping zero-variance columns would not help the Machine Learning models and could make the analysis misleading.

For this reason, zero-variance features were removed from the final ML feature list. This decision is documented in `data/processed/cleaning_report.json` under `dropped_constant_features`.

The final empirical validation relies mainly on PCA 2D, byte volume, packet size, duration, protocol, TCP flag counters and missing-value indicators.

# Week 2 Day 5 - Dataset Cleaning, Balancing, Scaling and EDA

## Objective

Prepare the final dataset for Machine Learning from data/processed/dataset_features_day4.csv.

## Important cleaning decision

A global dropna() was intentionally avoided. Some NaN values are semantically valid:

- rtt_estimate_ms is NaN for UDP, ICMP and incomplete TCP handshakes.
- TCP window statistics are NaN for non-TCP flows.
- SYN/ACK ratio is NaN for non-TCP flows or flows without ACK packets.

Instead, the pipeline adds missing-value indicator columns and imputes numeric NaNs with global medians. This preserves protocol information without deleting entire traffic classes.

## Cleaning summary

{
  "input_path": "data/processed/dataset_features_day4.csv",
  "initial_rows": 80571,
  "initial_columns": 58,
  "rows_removed_unknown_label": 0,
  "available_base_features": [
    "protocol",
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "dst2src_packets",
    "src2dst_bytes",
    "dst2src_bytes",
    "bidirectional_mean_ps",
    "bidirectional_syn_packets",
    "bidirectional_ack_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
    "bidirectional_psh_packets",
    "bytes_asymmetry_ratio",
    "packets_asymmetry_ratio",
    "bidirectional_packets_per_ms",
    "bytes_per_packet",
    "syn_ack_ratio_nfstream",
    "manual_packet_count",
    "iat_mean_ms",
    "iat_std_ms",
    "iat_cv",
    "rtt_estimate_ms",
    "tcp_window_min",
    "tcp_window_max",
    "tcp_window_mean",
    "tcp_window_var",
    "syn_ack_ratio_manual"
  ],
  "missing_base_features": [],
  "rows_removed_critical_nan": 0,
  "rows_removed_invalid_packets_bytes_duration": 0,
  "duration_zero_rows_kept": 79218,
  "imputation_report": {
    "syn_ack_ratio_nfstream": {
      "missing_count": 20113,
      "missing_pct": 24.9631,
      "imputation_value": 1.0,
      "indicator_column": "syn_ack_ratio_nfstream_missing"
    },
    "iat_mean_ms": {
      "missing_count": 19802,
      "missing_pct": 24.5771,
      "imputation_value": 0.0128746032714843,
      "indicator_column": "iat_mean_ms_missing"
    },
    "iat_std_ms": {
      "missing_count": 19802,
      "missing_pct": 24.5771,
      "imputation_value": 0.0,
      "indicator_column": "iat_std_ms_missing"
    },
    "iat_cv": {
      "missing_count": 19802,
      "missing_pct": 24.5771,
      "imputation_value": 0.0,
      "indicator_column": "iat_cv_missing"
    },
    "rtt_estimate_ms": {
      "missing_count": 80149,
      "missing_pct": 99.4762,
      "imputation_value": 0.0269412994384765,
      "indicator_column": "rtt_estimate_ms_missing"
    },
    "tcp_window_min": {
      "missing_count": 20113,
      "missing_pct": 24.9631,
      "imputation_value": 0.0,
      "indicator_column": "tcp_window_min_missing"
    },
    "tcp_window_max": {
      "missing_count": 20113,
      "missing_pct": 24.9631,
      "imputation_value": 1024.0,
      "indicator_column": "tcp_window_max_missing"
    },
    "tcp_window_mean": {
      "missing_count": 20113,
      "missing_pct": 24.9631,
      "imputation_value": 512.0,
      "indicator_column": "tcp_window_mean_missing"
    },
    "tcp_window_var": {
      "missing_count": 20113,
      "missing_pct": 24.9631,
      "imputation_value": 262144.0,
      "indicator_column": "tcp_window_var_missing"
    },
    "syn_ack_ratio_manual": {
      "missing_count": 20113,
      "missing_pct": 24.9631,
      "imputation_value": 1.0,
      "indicator_column": "syn_ack_ratio_manual_missing"
    }
  },
  "rows_after_cleaning_before_balancing": 80571,
  "rows_after_balancing": 491,
  "final_feature_count": 40,
  "output_dataset": "data/processed/dataset.csv",
  "output_scaled_dataset": "data/processed/dataset_scaled.csv",
  "scaler_path": "models/scaler.pkl"
}

## Class balance report

| label      |   count_before |   count_after |   removed_by_balancing |
|:-----------|---------------:|--------------:|-----------------------:|
| icmp_flood |             61 |            61 |                      0 |
| normal     |            546 |           129 |                    417 |
| port_sweep |             43 |            43 |                      0 |
| syn_scan   |          60120 |           129 |                  59991 |
| udp_scan   |          19801 |           129 |                  19672 |

## Outlier clipping report

Stored in data/processed/outlier_clipping_report.csv

Top clipped features:

| feature                      |   lower_q |   upper_q |     lower_value |    upper_value |   n_clipped_low |   n_clipped_high |   n_clipped_total |   pct_clipped_total |
|:-----------------------------|----------:|----------:|----------------:|---------------:|----------------:|-----------------:|------------------:|--------------------:|
| bytes_asymmetry_ratio        |      0.01 |      0.99 |      1.07273    |     43         |             419 |              727 |              1146 |              1.4223 |
| iat_mean_ms                  |      0.01 |      0.99 |      0.00691414 |      0.0876798 |              10 |              806 |               816 |              1.0128 |
| bidirectional_mean_ps        |      0.01 |      0.99 |     42          |     81.5       |               0 |              803 |               803 |              0.9966 |
| bytes_per_packet             |      0.01 |      0.99 |     42          |     81.5       |               0 |              803 |               803 |              0.9966 |
| bidirectional_bytes          |      0.01 |      0.99 |     42          |    154         |               0 |              777 |               777 |              0.9644 |
| src2dst_packets              |      0.01 |      0.99 |      1          |      1         |               0 |              775 |               775 |              0.9619 |
| dst2src_bytes                |      0.01 |      0.99 |      0          |     54         |               0 |              729 |               729 |              0.9048 |
| src2dst_bytes                |      0.01 |      0.99 |     42          |    112         |               0 |              633 |               633 |              0.7856 |
| manual_packet_count          |      0.01 |      0.99 |      1          |      2         |               2 |              614 |               616 |              0.7645 |
| bidirectional_packets        |      0.01 |      0.99 |      1          |      2         |               0 |              615 |               615 |              0.7633 |
| iat_std_ms                   |      0.01 |      0.99 |      0          |      0         |               0 |              614 |               614 |              0.7621 |
| iat_cv                       |      0.01 |      0.99 |      0          |      0         |               0 |              614 |               614 |              0.7621 |
| bidirectional_packets_per_ms |      0.01 |      0.99 |      1          |      2         |              66 |              547 |               613 |              0.7608 |
| syn_ack_ratio_manual         |      0.01 |      0.99 |      1          |      1         |             422 |              183 |               605 |              0.7509 |
| tcp_window_var               |      0.01 |      0.99 | 262144          | 262144         |               0 |              605 |               605 |              0.7509 |

## Feature statistics by label

Stored in data/processed/feature_stats_by_label.csv

Excerpt:

| label      | feature                      |       mean |     median |       std |        min |        max |   null_pct |
|:-----------|:-----------------------------|-----------:|-----------:|----------:|-----------:|-----------:|-----------:|
| icmp_flood | bidirectional_duration_ms    |   0.016393 |   0        |  0.128037 |   0        |   1        |          0 |
| normal     | bidirectional_duration_ms    |   0.782946 |   1        |  0.413847 |   0        |   1        |          0 |
| port_sweep | bidirectional_duration_ms    |   0.209302 |   0        |  0.411625 |   0        |   1        |          0 |
| syn_scan   | bidirectional_duration_ms    |   0.023256 |   0        |  0.151302 |   0        |   1        |          0 |
| udp_scan   | bidirectional_duration_ms    |   0        |   0        |  0        |   0        |   0        |          0 |
| icmp_flood | bidirectional_bytes          |  78.2623   |  88        | 14.7715   |  66        | 154        |          0 |
| normal     | bidirectional_bytes          | 153.969    | 154        |  0.35218  | 150        | 154        |          0 |
| port_sweep | bidirectional_bytes          | 121.767    | 112        | 17.9534   | 112        | 154        |          0 |
| syn_scan   | bidirectional_bytes          | 112        | 112        |  0        | 112        | 112        |          0 |
| udp_scan   | bidirectional_bytes          |  42.6124   |  42        |  4.89947  |  42        |  82        |          0 |
| icmp_flood | bidirectional_packets_per_ms |   1.01639  |   1        |  0.128037 |   1        |   2        |          0 |
| normal     | bidirectional_packets_per_ms |   1.84312  |   2        |  0.360077 |   1        |   2        |          0 |
| port_sweep | bidirectional_packets_per_ms |   1.97674  |   2        |  0.152499 |   1        |   2        |          0 |
| syn_scan   | bidirectional_packets_per_ms |   2        |   2        |  0        |   2        |   2        |          0 |
| udp_scan   | bidirectional_packets_per_ms |   1        |   1        |  0        |   1        |   1        |          0 |
| icmp_flood | iat_mean_ms                  |   0.012777 |   0.012875 |  0.000763 |   0.006914 |   0.012875 |          0 |
| normal     | iat_mean_ms                  |   0.075654 |   0.08768  |  0.021947 |   0.012875 |   0.08768  |          0 |
| port_sweep | iat_mean_ms                  |   0.05015  |   0.047929 |  0.030337 |   0.006914 |   0.08768  |          0 |
| syn_scan   | iat_mean_ms                  |   0.013233 |   0.011921 |  0.006695 |   0.006914 |   0.067949 |          0 |
| udp_scan   | iat_mean_ms                  |   0.012875 |   0.012875 |  0        |   0.012875 |   0.012875 |          0 |
| icmp_flood | iat_cv                       |   0        |   0        |  0        |   0        |   0        |          0 |
| normal     | iat_cv                       |   0        |   0        |  0        |   0        |   0        |          0 |
| port_sweep | iat_cv                       |   0        |   0        |  0        |   0        |   0        |          0 |
| syn_scan   | iat_cv                       |   0        |   0        |  0        |   0        |   0        |          0 |
| udp_scan   | iat_cv                       |   0        |   0        |  0        |   0        |   0        |          0 |
| icmp_flood | syn_ack_ratio_manual         |   1        |   1        |  0        |   1        |   1        |          0 |
| normal     | syn_ack_ratio_manual         |   1        |   1        |  0        |   1        |   1        |          0 |
| port_sweep | syn_ack_ratio_manual         |   1        |   1        |  0        |   1        |   1        |          0 |
| syn_scan   | syn_ack_ratio_manual         |   1        |   1        |  0        |   1        |   1        |          0 |
| udp_scan   | syn_ack_ratio_manual         |   1        |   1        |  0        |   1        |   1        |          0 |

## Final feature columns

Total final ML features: 40

- protocol
- bidirectional_duration_ms
- bidirectional_packets
- bidirectional_bytes
- src2dst_packets
- dst2src_packets
- src2dst_bytes
- dst2src_bytes
- bidirectional_mean_ps
- bidirectional_syn_packets
- bidirectional_ack_packets
- bidirectional_rst_packets
- bidirectional_fin_packets
- bidirectional_psh_packets
- bytes_asymmetry_ratio
- packets_asymmetry_ratio
- bidirectional_packets_per_ms
- bytes_per_packet
- syn_ack_ratio_nfstream
- manual_packet_count
- iat_mean_ms
- iat_std_ms
- iat_cv
- rtt_estimate_ms
- tcp_window_min
- tcp_window_max
- tcp_window_mean
- tcp_window_var
- syn_ack_ratio_manual
- duration_zero_flag
- syn_ack_ratio_nfstream_missing
- iat_mean_ms_missing
- iat_std_ms_missing
- iat_cv_missing
- rtt_estimate_ms_missing
- tcp_window_min_missing
- tcp_window_max_missing
- tcp_window_mean_missing
- tcp_window_var_missing
- syn_ack_ratio_manual_missing

## Generated files

- data/processed/dataset_clean_unbalanced.csv
- data/processed/dataset.csv
- data/processed/dataset_scaled.csv
- data/processed/feature_columns.json
- data/processed/cleaning_report.json
- data/processed/outlier_clipping_report.csv
- data/processed/class_balance_report.csv
- data/processed/feature_stats_by_label.csv
- models/scaler.pkl

## Next step

Use dataset_scaled.csv for K-Means clustering and dataset.csv or dataset_scaled.csv for supervised classification experiments.

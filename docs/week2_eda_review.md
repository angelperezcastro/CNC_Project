# Week 2 EDA Review

## Objective

This document reviews the final Week 2 dataset before starting the Machine Learning phase.

The review checks data integrity, class balance, feature separability, PCA visualization and the relationship between protocol-aware features.

## Dataset integrity

- dataset.csv shape: (491, 29)
- dataset_scaled.csv shape: (491, 29)
- number of ML features: 28
- NaN values in dataset.csv: 0
- NaN values in dataset_scaled.csv: 0
- max/min class ratio: 3.000

## Class distribution

| label      |   n_flows |
|:-----------|----------:|
| udp_scan   |       129 |
| normal     |       129 |
| syn_scan   |       129 |
| icmp_flood |        61 |
| port_sweep |        43 |

## Cleaning summary

- Initial rows: 80571
- Rows after cleaning before balancing: 80571
- Rows after balancing: 491
- Duration-zero rows kept: 79218
- Rows removed due to critical NaNs: 0
- Rows removed due to invalid packets/bytes/duration: 0

## Feature statistics by class

| label      |   n_flows |   bidirectional_duration_ms_mean |   bidirectional_duration_ms_median |   bidirectional_packets_mean |   bidirectional_packets_median |   bidirectional_bytes_mean |   bidirectional_bytes_median |   iat_mean_ms_mean |   iat_mean_ms_median |   bidirectional_packets_per_ms_mean |   bidirectional_packets_per_ms_median |
|:-----------|----------:|---------------------------------:|-----------------------------------:|-----------------------------:|-------------------------------:|---------------------------:|-----------------------------:|-------------------:|---------------------:|------------------------------------:|--------------------------------------:|
| icmp_flood |        61 |                         0.016393 |                                  0 |                      1.01639 |                              1 |                    78.2623 |                           88 |           0.012777 |             0.012875 |                             1.01639 |                                     1 |
| normal     |       129 |                         0.782946 |                                  1 |                      1.99225 |                              2 |                   153.969  |                          154 |           0.075654 |             0.08768  |                             1.84312 |                                     2 |
| port_sweep |        43 |                         0.209302 |                                  0 |                      2       |                              2 |                   121.767  |                          112 |           0.05015  |             0.047929 |                             1.97674 |                                     2 |
| syn_scan   |       129 |                         0.023256 |                                  0 |                      2       |                              2 |                   112      |                          112 |           0.013233 |             0.011921 |                             2       |                                     2 |
| udp_scan   |       129 |                         0        |                                  0 |                      1       |                              1 |                    42.6124 |                           42 |           0.012875 |             0.012875 |                             1       |                                     1 |

## PCA 2D review

- PCA explained variance PC1: 0.7007
- PCA explained variance PC2: 0.1800
- PCA total explained variance: 0.8807
- True-label silhouette score on scaled features: 0.6318

Generated figure:

- docs/figures/week2_review_pca_2d_with_centroids.png

## IAT CV vs SYN/ACK ratio review

Generated figure:

- docs/figures/week2_review_iat_cv_vs_syn_ack.png

Interpretation notes:

- Non-TCP traffic may have imputed SYN/ACK-related values plus missing indicators.
- SYN scan and port sweep can overlap in SYN/ACK ratio because both are probing behaviors.
- Full separability is not required before ML, but complete overlap would indicate a feature extraction issue.
- The PCA plot should be used as a qualitative check before K-Means.

## Verdict

The final Week 2 dataset is clean, balanced, scaled and ready for the Machine Learning phase.

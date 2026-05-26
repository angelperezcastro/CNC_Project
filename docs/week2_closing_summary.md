# Week 2 Closing Summary

## Status

Week 2 is complete. The project now has a cleaned, balanced and scaled flow-level dataset ready for Machine Learning.

## Main deliverables

- notebooks/01_nfstream_exploration.ipynb
- docs/features_description.md
- src/manual_features.py
- src/pipeline.py
- src/prepare_dataset.py
- notebooks/02_eda.ipynb
- data/processed/dataset.csv
- data/processed/dataset_scaled.csv
- models/scaler.pkl
- docs/week2_eda_review.md
- docs/report_feature_engineering_section.md

## Final dataset

- dataset.csv shape: (491, 29)
- dataset_scaled.csv shape: (491, 29)
- feature count: 28

## Class distribution

| label      |   n_flows |
|:-----------|----------:|
| udp_scan   |       129 |
| normal     |       129 |
| syn_scan   |       129 |
| icmp_flood |        61 |
| port_sweep |        43 |

## Next step

Start Week 3 with unsupervised clustering using K-Means on data/processed/dataset_scaled.csv.

# Week 4 Day 1 — Streamlit Dashboard Base

## Goal

Build the first functional Streamlit dashboard for NetFlow Analyzer.

## Implemented features

- PCAP/PCAPNG upload from the sidebar.
- "Analizar" button to execute the existing prediction pipeline.
- Integration with `src.predict.predict_pcap()`.
- Four dashboard metrics:
  - Total flows.
  - Normal flows.
  - Anomalous flows.
  - Most frequent attack.
- Classified flow table.
- Raw prediction output available for debugging.
- Basic error handling for invalid PCAP files.

## Technical decision

The dashboard does not reload the model manually and does not duplicate the ML pipeline.

Instead, it calls the existing `predict_pcap()` function from `src/predict.py` through `src/dashboard_adapter.py`.

This keeps `src/predict.py` as the single source of truth for:

- PCAP normalization.
- Feature extraction.
- Feature schema alignment.
- Scaling.
- Random Forest prediction.
- Anomaly decision based on normal probability.

## Validation evidence

### Test PCAP

`data/test/mixed_day5.pcap`

### Dashboard metrics observed

| Metric | Value |
|---|---:|
| Total flows | 2027 |
| Normal flows | 39 |
| Anomalous flows | 1988 |
| Most frequent attack | syn_scan |
| Table rows | 2027 |
| Table columns | 10 |

### Predicted class distribution

| Predicted class | Flows |
|---|---:|
| syn_scan | 986 |
| udp_scan | 973 |
| normal | 39 |
| port_sweep | 15 |
| icmp_flood | 14 |

### Prediction confidence

| Metric | Value |
|---|---:|
| Mean confidence | 0.7577 |
| Mean P(normal) | 0.0194 |

## Validation command

The dashboard adapter was validated with:

    python - <<'PY'
    from src.dashboard_adapter import analyze_pcap_for_dashboard, build_flow_table

    df = analyze_pcap_for_dashboard("data/test/mixed_day5.pcap")
    table = build_flow_table(df)

    print("Normalized shape:", df.shape)
    print("Dashboard table shape:", table.shape)
    print("Columns:", list(df.columns))
    print(table.head(5).to_string(index=False))
    PY

## Validation result

The adapter successfully executed the full prediction pipeline:

- Loaded `models/rf_optimized.pkl`.
- Loaded `models/scaler.pkl`.
- Loaded `models/label_encoder.pkl`.
- Loaded `models/feature_columns.json`.
- Loaded `data/processed/cleaning_report.json`.
- Normalized the PCAP for NFStream.
- Extracted 2027 flows.
- Scaled the features.
- Predicted the traffic classes.
- Saved predictions under `reports/predictions/`.

## Known limitations

- Advanced visualizations are planned for Week 4 Day 2.
- Processing time depends on PCAP size.
- The dashboard currently focuses on batch PCAP analysis, not live streaming.
- The current Day 1 version prioritizes functional integration over visual polish.

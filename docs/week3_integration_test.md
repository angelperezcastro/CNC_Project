# Week 3 Integration Test

## Objective

The objective of this integration test is to verify that the complete machine learning pipeline works end-to-end:

~~~text
Docker traffic generation → PCAP capture → NFStream-compatible normalization → flow extraction → feature alignment → scaling → Random Forest prediction → anomaly detection
~~~

## Environment

The test was executed in the Docker-based isolated network environment with three services:

| Service | Role |
|---|---|
| `server` | Target service exposing HTTP, FTP and DNS-like traffic |
| `client` | Generates normal HTTP, FTP and DNS traffic |
| `attacker` | Generates SYN scan and UDP scan traffic |

## Input PCAPs

Two new PCAP files were used for final validation:

| PCAP | Description |
|---|---|
| `data/test/normal_day5.pcap` | Normal HTTP, FTP and DNS traffic |
| `data/test/mixed_day5.pcap` | Normal traffic plus embedded SYN scan and UDP scan |

These captures were generated after model training and were not part of the training dataset.

## Commands executed

Normal PCAP prediction:

~~~bash
python src/predict.py data/test/normal_day5.pcap \
  --output reports/predictions/normal_day5_predictions.csv
~~~

Mixed PCAP prediction:

~~~bash
python src/predict.py data/test/mixed_day5.pcap \
  --output reports/predictions/mixed_day5_predictions.csv
~~~

## Prediction summary

### Normal PCAP

| Metric | Value |
|---|---:|
| Extracted flows | 64 |
| Predicted normal flows | 64 |
| Anomalous flows | 0 |
| Mean confidence | 0.9923 |
| Mean P(normal) | 0.9923 |

Interpretation:

The normal PCAP was classified correctly. All extracted flows were predicted as `normal`, and no flow was flagged as anomalous. This indicates that the anomaly threshold does not generate false positives in this controlled normal capture.

### Mixed PCAP

| Metric | Value |
|---|---:|
| Extracted flows | 2027 |
| Anomalous flows | 1988 |
| Non-anomalous flows | 39 |
| Mean confidence | 0.7577 |
| Mean P(normal) | 0.0194 |

Predicted class distribution:

| Predicted class | Flows |
|---|---:|
| `syn_scan` | 986 |
| `udp_scan` | 973 |
| `normal` | 39 |
| `port_sweep` | 15 |
| `icmp_flood` | 14 |

Interpretation:

The mixed PCAP was correctly identified as mostly anomalous. The two dominant predicted classes were `syn_scan` and `udp_scan`, which matches the attack traffic embedded during the test. The very low mean `P(normal)` confirms that the model considers most flows in this capture to be non-normal.

## Integration issues fixed

During the final integration test, several practical issues were identified and fixed:

1. **NFStream could not extract flows from raw Docker captures.**  
   Docker captures used Linux cooked capture format (`sll`). These files could be parsed by tshark, but NFStream returned zero flows.  
   Fix: `src/predict.py` now normalizes PCAPs before feature extraction using `src.normalize_pcaps_for_nfstream.normalize_pcap_for_nfstream()`.

2. **Prediction-time features did not fully match training-time features.**  
   The extracted flow DataFrame was missing derived features such as `duration_zero_flag`.  
   Fix: `src/predict.py` now reconstructs derived features before aligning the DataFrame with `models/feature_columns.json`.

3. **The scaler artifact was stored as a dictionary.**  
   `models/scaler.pkl` contains both the fitted scaler and the feature column list.  
   Fix: `src/predict.py` extracts the actual `StandardScaler` object from the dictionary before calling `.transform()`.

4. **The capture script required paths under `data/raw/`.**  
   `src/capture.py` rejects output paths outside `data/raw/`.  
   Fix: validation PCAPs were captured under `data/raw/day5_test/` and then copied to `data/test/`.

## Final conclusion

The complete machine learning inference pipeline works end-to-end from a new PCAP file. The normal capture produces no anomaly flags, while the mixed capture containing embedded attacks is detected as mostly anomalous.

This closes the Week 3 machine learning pipeline milestone.

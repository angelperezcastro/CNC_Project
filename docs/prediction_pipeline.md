# Prediction Pipeline

## Objective

The objective of `src/predict.py` is to classify network flows from a new PCAP file using the trained Random Forest model and the same feature-processing logic used during training.

This script is the first end-to-end inference component of the NetFlow Analyzer project. It connects packet capture, flow reconstruction, feature preparation, model inference and anomaly detection in a single command-line workflow.

## End-to-end flow

The prediction pipeline follows these steps:

1. Receive a PCAP file path as input.
2. Normalize the PCAP when needed so that NFStream can extract flows correctly.
3. Extract bidirectional flow-level L3/L4 features using `src.pipeline.process_pcap()`.
4. Recreate prediction-time derived features such as `duration_zero_flag`.
5. Apply missing-value indicators and imputation using `data/processed/cleaning_report.json`.
6. Align the extracted features with the training feature schema stored in `models/feature_columns.json`.
7. Apply the fitted scaler stored in `models/scaler.pkl`.
8. Load the optimized Random Forest model from `models/rf_optimized.pkl`.
9. Predict the class of each flow.
10. Compute class probabilities.
11. Flag anomalous flows using the rule `P(normal) < 0.4`.
12. Save the final prediction table as CSV under `reports/predictions/`.

## Command-line usage

Basic usage:

~~~bash
python src/predict.py data/test/new_capture.pcap
~~~

Example with explicit output path:

~~~bash
python src/predict.py data/test/mixed_day5.pcap \
  --output reports/predictions/mixed_day5_predictions.csv
~~~

Example using a custom anomaly threshold:

~~~bash
python src/predict.py data/test/mixed_day5.pcap \
  --normal-threshold 0.4
~~~

Example when the PCAP is already NFStream-compatible and does not need normalization:

~~~bash
python src/predict.py data/test/normalized/example_nfstream.pcap \
  --no-normalize
~~~

## Input artifacts

The script relies on the following trained artifacts:

| Artifact | Purpose |
|---|---|
| `models/rf_optimized.pkl` | Optimized Random Forest classifier |
| `models/scaler.pkl` | Fitted scaler used to transform features before prediction |
| `models/label_encoder.pkl` | Maps encoded class IDs back to class names |
| `models/feature_columns.json` | Ordered list of features expected by the model |
| `data/processed/cleaning_report.json` | Missing-value and imputation metadata from the training pipeline |

## Output columns

The prediction CSV includes the original extracted flow features plus prediction-related columns:

| Column | Meaning |
|---|---|
| `predicted_class` | Final class predicted by the Random Forest model |
| `confidence` | Maximum predicted class probability |
| `normal_probability` | Probability assigned to the `normal` class |
| `is_anomaly` | Boolean flag based on `P(normal) < 0.4` |
| `proba_icmp_flood` | Probability of class `icmp_flood` |
| `proba_normal` | Probability of class `normal` |
| `proba_port_sweep` | Probability of class `port_sweep` |
| `proba_syn_scan` | Probability of class `syn_scan` |
| `proba_udp_scan` | Probability of class `udp_scan` |

## Anomaly rule

A flow is considered anomalous when:

~~~text
P(normal) < 0.4
~~~

This rule is intentionally simple and explainable. Instead of relying only on the hard predicted class, it checks how confident the model is that a flow belongs to normal traffic.

If the probability of normal traffic is low, the flow is considered suspicious, even if the predicted attack class is not perfect. This is useful from a cybersecurity perspective because detecting that a flow is non-normal is often more important than perfectly identifying the exact attack family.

## PCAP normalization for NFStream

Some captures generated inside Docker/WSL use the Linux cooked capture link-layer format, shown by `tshark` as `sll`.

These PCAPs can be opened by Wireshark and tshark, but NFStream may fail to extract flows directly from them. This produced the error:

~~~text
NFStream extracted no flows
~~~

To solve this, `src/predict.py` automatically normalizes each input PCAP before feature extraction using:

~~~text
src.normalize_pcaps_for_nfstream.normalize_pcap_for_nfstream()
~~~

The normalized copies are stored under:

~~~text
data/test/normalized/
~~~

This makes the prediction pipeline robust when working with Docker/WSL captures.

## Day 5 test PCAPs

Two new PCAP files not used during training were generated for validation:

| PCAP | Description | Purpose |
|---|---|---|
| `data/test/normal_day5.pcap` | Normal HTTP, FTP and DNS traffic | Verify that normal flows are not incorrectly flagged as anomalous |
| `data/test/mixed_day5.pcap` | Normal traffic plus embedded SYN scan and UDP scan | Verify that attack-like flows are detected as anomalous |

Both PCAPs were captured from the Docker network environment and then processed through `src/predict.py`.

## Normal PCAP result

Command used:

~~~bash
python src/predict.py data/test/normal_day5.pcap \
  --output reports/predictions/normal_day5_predictions.csv
~~~

Result:

| Metric | Value |
|---|---:|
| Extracted flows | 64 |
| Predicted `normal` flows | 64 |
| Anomalous flows | 0 |
| Mean confidence | 0.9923 |
| Mean `P(normal)` | 0.9923 |

Interpretation:

The normal PCAP was correctly classified as benign traffic. All 64 extracted flows were predicted as `normal`, and no flow was flagged as anomalous. This confirms that the anomaly rule does not generate false positives on this controlled normal capture.

## Mixed PCAP result

Command used:

~~~bash
python src/predict.py data/test/mixed_day5.pcap \
  --output reports/predictions/mixed_day5_predictions.csv
~~~

Result:

| Metric | Value |
|---|---:|
| Extracted flows | 2027 |
| Anomalous flows | 1988 |
| Non-anomalous flows | 39 |
| Mean confidence | 0.7577 |
| Mean `P(normal)` | 0.0194 |

Predicted class distribution:

| Predicted class | Flows |
|---|---:|
| `syn_scan` | 986 |
| `udp_scan` | 973 |
| `normal` | 39 |
| `port_sweep` | 15 |
| `icmp_flood` | 14 |

Interpretation:

The mixed PCAP was correctly identified as mostly anomalous. The model detected a large number of `syn_scan` and `udp_scan` flows, which matches the attacks embedded during capture. Only 39 flows were considered normal.

The very low mean `P(normal)` value, approximately `0.0194`, confirms that the model sees the mixed capture as strongly non-normal. This validates the anomaly rule `P(normal) < 0.4` in an end-to-end setting.

## Smoke test result

Before validating new Day 5 PCAPs, a smoke test was performed using an existing UDP scan PCAP.

Result:

| Metric | Value |
|---|---:|
| Extracted flows | 19801 |
| Predicted `udp_scan` flows | 19461 |
| Anomalous flows | 19800 |
| Mean confidence | 0.9959 |
| Mean `P(normal)` | 0.0009 |

Interpretation:

The UDP scan smoke test validates the complete inference path. Almost all flows were predicted as attack traffic and flagged as anomalous, which is the expected behavior for a UDP scan capture.

## Generated files

Prediction outputs:

~~~text
reports/predictions/normal_day5_predictions.csv
reports/predictions/mixed_day5_predictions.csv
reports/predictions/smoke_udp_scan_predictions_from_raw.csv
~~~

Prediction summary:

~~~text
docs/prediction_test_results.json
~~~

Normalized PCAPs:

~~~text
data/test/normalized/normal_day5_nfstream.pcap
data/test/normalized/mixed_day5_nfstream.pcap
data/test/normalized/udp_scan_week1_final_nfstream.pcap
~~~

## Technical interpretation

The prediction pipeline behaves coherently from a network-protocol perspective.

For the normal PCAP, the extracted flows correspond mainly to HTTP, FTP and DNS traffic. These flows include legitimate bidirectional exchanges and larger byte volumes, especially due to file transfers. The model assigns high `P(normal)` values and does not flag anomalies.

For the mixed PCAP, the embedded SYN scan and UDP scan generate many short flows with low normal probability. The model assigns most of these flows to `syn_scan` and `udp_scan`, which matches the traffic generated by the attacker container. Since the anomaly rule is based on low `P(normal)`, these attack-like flows are correctly marked as anomalous.

## Limitations

The current anomaly rule is intentionally simple. It works well in the controlled Docker environment, but future improvements could include:

- Calibrating the `P(normal)` threshold using a validation set.
- Adding temporal aggregation features such as `unique_dst_ports_per_src`.
- Adding `unique_dst_hosts_per_src`.
- Adding `new_connection_rate`.
- Adding `dst_port_entropy`.
- Testing the prediction pipeline with larger unseen PCAPs.

These improvements would help distinguish isolated suspicious flows from broader scanning campaigns more reliably.

## Conclusion

The Day 5 milestone is completed. `src/predict.py` works end-to-end from a new PCAP file, extracts flow features, applies the trained preprocessing artifacts, predicts traffic classes and detects anomalies using `P(normal) < 0.4`.

The results show correct behavior on both a normal-only PCAP and a mixed PCAP containing embedded attacks.

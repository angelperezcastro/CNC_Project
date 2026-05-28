# Machine Learning Pipeline

## Pipeline objective

The objective of the Machine Learning pipeline is to classify network flows using only Layer 3 and Layer 4 features, without inspecting packet payloads. The system receives PCAP captures, reconstructs bidirectional flows, extracts protocol and statistical features, applies machine learning models, and returns one prediction per flow.

The pipeline supports two main tasks:

1. Supervised traffic classification into known classes.
2. Anomaly detection based on low probability of belonging to the `normal` class.

## General architecture

The complete workflow is:

~~~text
PCAP → normalization → flow reconstruction → feature extraction → cleaning/imputation → scaling → ML model → flow-level prediction
~~~

The implementation is divided into several modules:

| Module | Responsibility |
|---|---|
| `src/pipeline.py` | Processes PCAP files and generates a flow-level DataFrame with L3/L4 features |
| `src/manual_features.py` | Computes manual features with Scapy, such as IAT, RTT, TCP window values and SYN/ACK ratio |
| `src/prepare_dataset.py` | Cleans, imputes, scales and saves the final dataset |
| `notebooks/03_clustering.ipynb` | Applies K-Means for unsupervised analysis |
| `notebooks/04_classification.ipynb` | Trains the baseline Random Forest model |
| `notebooks/05_model_evaluation.ipynb` | Evaluates metrics, confusion matrix, ROC-AUC and error patterns |
| `notebooks/06_hyperparameter_optimization.ipynb` | Optimizes hyperparameters with RandomizedSearchCV |
| `src/predict.py` | Runs end-to-end inference on new PCAP files |

## Feature extraction

The system uses only network metadata features. Payload inspection is intentionally avoided. The most relevant features include:

| Feature | Interpretation |
|---|---|
| `protocol` | IP protocol number, such as TCP, UDP or ICMP |
| `bidirectional_duration_ms` | Total flow duration |
| `bidirectional_packets` | Total number of packets |
| `bidirectional_bytes` | Total number of bytes |
| `src2dst_bytes` / `dst2src_bytes` | Directional byte volume |
| `bidirectional_mean_ps` | Mean packet size |
| `bidirectional_syn_packets` | Number of TCP packets with SYN flag |
| `bidirectional_ack_packets` | Number of TCP packets with ACK flag |
| `bidirectional_rst_packets` | Number of TCP packets with RST flag |
| `iat_mean_ms` | Mean inter-arrival time |
| `duration_zero_flag` | Indicator for zero-duration flows |
| `bytes_per_packet` | Average bytes per packet |
| `bidirectional_packets_per_ms` | Packet rate per millisecond |

These features capture protocol-level behavior. For example, SYN scan traffic tends to generate very short TCP flows with low byte volume and SYN/RST-related behavior. UDP scan traffic generates many small UDP flows without a TCP handshake. Normal HTTP, FTP and DNS traffic tends to show more legitimate bidirectional exchanges and higher byte volumes.

## Cleaning and scaling

The dataset preparation stage applies the following steps:

1. Numeric column conversion.
2. Missing-value indicator creation.
3. Missing-value imputation.
4. Outlier clipping.
5. Dataset balancing.
6. Feature scaling with `StandardScaler`.
7. Reproducible artifact saving.

The main artifacts are:

| Artifact | Purpose |
|---|---|
| `data/processed/dataset.csv` | Clean dataset in original feature units |
| `data/processed/dataset_scaled.csv` | Scaled dataset used for ML |
| `data/processed/cleaning_report.json` | Cleaning and imputation metadata |
| `models/scaler.pkl` | Scaler used during training and inference |
| `models/feature_columns.json` | Exact feature order expected by the model |

Maintaining the same feature order and meaning between training and inference is critical. For this reason, `src/predict.py` validates the prediction-time DataFrame against `models/feature_columns.json`.

## Unsupervised clustering

K-Means was applied to the scaled dataset to study the natural structure of the flows. Values of K from 2 to 10 were evaluated using the Elbow Method and the Silhouette Score.

The best value according to the Silhouette Score was K=6. Although the dataset contains five real traffic labels, this difference is technically reasonable because K-Means is unsupervised and does not use labels during training. It can split one semantic class into several behavioral subgroups. For example, normal traffic can be divided into TCP-like and non-TCP-like flows, while scanning traffic can be grouped by protocol, duration and TCP flag behavior.

The clustering analysis confirmed that the extracted features capture meaningful network patterns, such as unidirectional UDP flows, SYN scan probes and bidirectional normal traffic.

## Supervised classification

Random Forest was selected for supervised classification. This model is suitable for the project for four main reasons:

1. It handles heterogeneous numerical network features well.
2. It is robust to irrelevant or weak features.
3. Its ensemble nature reduces overfitting compared with a single decision tree.
4. Its built-in feature importance helps validate whether the model is learning protocol-relevant patterns.

The baseline model obtained:

| Metric | Value |
|---|---:|
| Train accuracy | 0.9796 |
| Test accuracy | 0.9697 |
| Accuracy gap | 0.0099 |
| Weighted F1 | 0.9689 |

The gap between train and test accuracy is below 5%, so there is no strong evidence of overfitting.

## Model evaluation

The complete evaluation included per-class precision, recall and F1-score, confusion matrix analysis, 5-fold cross-validation, ROC-AUC one-vs-rest curves and comparison against a simple Decision Tree.

Main results:

| Metric | Value |
|---|---:|
| Mean weighted F1, 5-fold CV | 0.9676 |
| Std weighted F1, 5-fold CV | 0.0198 |
| Mean accuracy, 5-fold CV | 0.9694 |
| Std accuracy, 5-fold CV | 0.0171 |

The most difficult class was `port_sweep`. This is coherent from a network perspective because port sweep traffic can generate short, low-volume flows that resemble normal request-response flows or other reconnaissance traffic when each flow is analyzed in isolation.

From a security perspective, the most important result is that attack flows were not classified as `normal` in the main supervised test split. The remaining errors mainly affected exact attack-family identification, not the detection of malicious behavior.

## Hyperparameter optimization

RandomizedSearchCV was used with 20 iterations and 5-fold cross-validation. The search space was:

| Hyperparameter | Values |
|---|---|
| `n_estimators` | 50, 100, 200 |
| `max_depth` | None, 10, 20 |
| `min_samples_split` | 2, 5, 10 |
| `max_features` | sqrt, log2 |

The best configuration found was:

~~~text
n_estimators = 200
max_depth = 20
min_samples_split = 10
max_features = sqrt
~~~

The optimized model obtained:

| Metric | Baseline model | Optimized model |
|---|---:|---:|
| Test accuracy | 0.9697 | 0.9798 |
| Weighted F1 | 0.9689 | 0.9797 |
| Accuracy gap | 0.0099 | -0.0053 |

The optimized model improves held-out test performance while keeping the train-test gap below the 5% overfitting threshold.

## Inference on new PCAP files

The script `src/predict.py` allows inference on PCAP files that were not used during training.

The inference workflow is:

~~~text
New PCAP → NFStream normalization → process_pcap() → feature reconstruction → scaler → Random Forest → class probabilities → anomaly flag
~~~

The anomaly rule is:

~~~text
P(normal) < 0.4
~~~

This rule is interpretable: if the model assigns low probability to the normal class, the flow is flagged as suspicious, even if the exact attack label is not perfect.

## End-to-end validation

Two new PCAP files were generated:

| PCAP | Description |
|---|---|
| `normal_day5.pcap` | Normal HTTP, FTP and DNS traffic |
| `mixed_day5.pcap` | Normal traffic plus SYN scan and UDP scan |

Results:

| PCAP | Flows | Anomalies | Interpretation |
|---|---:|---:|---|
| `normal_day5.pcap` | 64 | 0 | All flows were classified as normal |
| `mixed_day5.pcap` | 2027 | 1988 | Attack traffic was detected massively |

In the normal PCAP, the mean probability of the `normal` class was 0.9923. In the mixed PCAP, the mean probability of the `normal` class was 0.0194. This confirms that the model clearly separates normal behavior from attack-like behavior in unseen captures.

## Integration issues solved

Several integration issues were solved during the final test:

1. Docker PCAPs used Linux cooked capture format (`sll`), which NFStream did not process correctly. Automatic PCAP normalization was added.
2. Prediction-time inference needed to reconstruct derived features such as `duration_zero_flag`.
3. The scaler was stored inside a dictionary together with metadata, so `src/predict.py` was adapted to extract the actual `StandardScaler`.
4. `src/capture.py` required captures to be stored under `data/raw/`, so test PCAPs were captured under `data/raw/day5_test/` and copied to `data/test/`.

## Limitations

The current system works correctly in a controlled Docker environment, but it has limitations:

1. The model was trained with synthetic and controlled traffic, so it should be validated with more diverse real-world PCAPs.
2. Some classes, especially `port_sweep`, can be confused with other reconnaissance patterns when only isolated per-flow features are used.
3. The system does not inspect payloads, which improves privacy and compatibility with encrypted traffic, but limits application-layer attack detection.
4. The threshold `P(normal) < 0.4` worked well in this validation, but should be calibrated with more data.
5. The current test environment focuses on IPv4 laboratory traffic.

## Future work

Future improvements include:

1. Adding temporal aggregation features:
   - `unique_dst_ports_per_src`
   - `unique_dst_hosts_per_src`
   - `new_connection_rate`
   - `dst_port_entropy`
2. Calibrating model probabilities with `CalibratedClassifierCV`.
3. Testing the pipeline on external real-world PCAP datasets.
4. Building a Streamlit dashboard to visualize flows, predictions and anomalies.
5. Adding automated tests for the prediction pipeline.

## Conclusion

The Machine Learning pipeline is complete and validated. The system processes new PCAP files, reconstructs flows, extracts L3/L4 features, applies the optimized Random Forest model and detects anomalies using an interpretable probability-based rule.

The results show that the pipeline correctly distinguishes normal traffic from anomalous traffic in unseen captures, closing the Machine Learning phase of the project.

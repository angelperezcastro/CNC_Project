# Week 3 Final Summary — Machine Learning Pipeline

## Completed milestones

During Week 3, the Machine Learning pipeline was completed:

1. K-Means clustering with PCA visualization and protocol-level interpretation.
2. Baseline Random Forest classifier.
3. Complete model evaluation with per-class metrics, confusion matrix, ROC-AUC and cross-validation.
4. Hyperparameter optimization with RandomizedSearchCV.
5. End-to-end prediction script for new PCAP files.
6. Final integration test from Docker traffic generation to prediction output.

## Main artifacts

| Artifact | Description |
|---|---|
| `notebooks/03_clustering.ipynb` | K-Means clustering |
| `notebooks/04_classification.ipynb` | Baseline Random Forest |
| `notebooks/05_model_evaluation.ipynb` | Complete evaluation |
| `notebooks/06_hyperparameter_optimization.ipynb` | Hyperparameter optimization |
| `src/predict.py` | End-to-end PCAP prediction |
| `models/kmeans.pkl` | K-Means model |
| `models/rf_model.pkl` | Baseline Random Forest |
| `models/rf_optimized.pkl` | Optimized Random Forest |
| `models/label_encoder.pkl` | Label encoder |
| `models/scaler.pkl` | Feature scaler |
| `models/feature_columns.json` | Final model feature schema |

## Key ML results

| Metric | Value |
|---|---:|
| Baseline RF test accuracy | 0.9697 |
| Baseline RF weighted F1 | 0.9689 |
| Optimized RF test accuracy | 0.9798 |
| Optimized RF weighted F1 | 0.9797 |
| 5-fold CV weighted F1 mean | 0.9676 |
| 5-fold CV weighted F1 std | 0.0198 |

## End-to-end prediction results

| PCAP | Flows | Anomalies | Result |
|---|---:|---:|---|
| `normal_day5.pcap` | 64 | 0 | Correctly classified as normal |
| `mixed_day5.pcap` | 2027 | 1988 | Attacks detected correctly |

## Integration fixes

The final integration exposed several practical issues that were fixed:

1. Docker captures were stored in Linux cooked capture format (`sll`), so PCAP normalization was added before NFStream extraction.
2. Prediction-time feature reconstruction was added for derived features such as `duration_zero_flag`.
3. The scaler artifact was loaded correctly from the dictionary stored in `models/scaler.pkl`.
4. Validation captures were generated under `data/raw/day5_test/` and copied to `data/test/`.

## Final status

Week 3 is complete. The project now has a functional Machine Learning pipeline that can classify flows from new PCAP captures and flag anomalous traffic using Random Forest probabilities.

The next phase is Week 4: building the Streamlit dashboard to visualize flows, predictions, anomalies and model outputs in an interactive interface.

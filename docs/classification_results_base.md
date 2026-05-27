# Random Forest Base Classification Results

## Model configuration

- Model: `RandomForestClassifier`

- Number of trees: `n_estimators=100`

- Random state: `42`

- Train/test split: 80/20 stratified by label

## Why Random Forest?

Random Forest is suitable for this network traffic classification task because (1) it handles heterogeneous numerical features without requiring strict distributional assumptions, (2) it is robust to irrelevant or weak features because they tend to receive low importance, (3) its ensemble nature reduces overfitting compared with a single decision tree, and (4) its built-in feature importance allows validating whether the most discriminative features match the expected TCP/IP protocol behavior.

## Dataset and labels

The dataset contains five traffic classes: `normal`, `icmp_flood`, `syn_scan`, `udp_scan` and `port_sweep`.

Label distribution:

| label      |   count |   percentage |
|:-----------|--------:|-------------:|
| udp_scan   |     129 |        26.27 |
| normal     |     129 |        26.27 |
| syn_scan   |     129 |        26.27 |
| icmp_flood |      61 |        12.42 |
| port_sweep |      43 |         8.76 |


## Train/test distribution

| label      |   train_count |   test_count |
|:-----------|--------------:|-------------:|
| icmp_flood |            49 |           12 |
| normal     |           103 |           26 |
| port_sweep |            34 |            9 |
| syn_scan   |           103 |           26 |
| udp_scan   |           103 |           26 |


## Accuracy

- Train accuracy: `0.9796`

- Test accuracy: `0.9697`

- Accuracy gap: `0.0099`

## Classification report

|              |   precision |   recall |   f1-score |   support |
|:-------------|------------:|---------:|-----------:|----------:|
| icmp_flood   |      0.9231 |   1      |     0.96   |   12      |
| normal       |      1      |   0.9615 |     0.9804 |   26      |
| port_sweep   |      1      |   0.7778 |     0.875  |    9      |
| syn_scan     |      0.9286 |   1      |     0.963  |   26      |
| udp_scan     |      1      |   1      |     1      |   26      |
| accuracy     |      0.9697 |   0.9697 |     0.9697 |    0.9697 |
| macro avg    |      0.9703 |   0.9479 |     0.9557 |   99      |
| weighted avg |      0.9719 |   0.9697 |     0.9689 |   99      |


## Confusion matrix

Saved figure: `reports/figures/rf_confusion_matrix_base.png`

## Top 10 feature importances

| feature                   |   importance |
|:--------------------------|-------------:|
| src2dst_bytes             |       0.1699 |
| iat_mean_ms               |       0.1456 |
| bytes_per_packet          |       0.1291 |
| bidirectional_mean_ps     |       0.119  |
| bidirectional_bytes       |       0.1142 |
| bidirectional_rst_packets |       0.0455 |
| iat_cv_missing            |       0.0304 |
| packets_asymmetry_ratio   |       0.0269 |
| dst2src_packets           |       0.0268 |
| iat_std_ms_missing        |       0.0248 |


## Preliminary technical interpretation

The feature importance ranking must be interpreted from a protocol perspective. If protocol, TCP flag counts, duration, packet size, packet rate, asymmetry ratios or missingness indicators appear among the most important variables, the model is learning L3/L4 behavior instead of inspecting payload. This is aligned with the project goal: classifying traffic using flow-level metadata only.

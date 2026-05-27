# Complete Model Evaluation

## Evaluation setup

- Model evaluated: `RandomForestClassifier(n_estimators=100, random_state=42)`

- Dataset: `data/processed/dataset_scaled.csv`

- Evaluation split: 80/20 stratified train/test split

- Cross-validation: 5-fold StratifiedKFold

- Classes: `icmp_flood`, `normal`, `port_sweep`, `syn_scan`, `udp_scan`

## Dataset distribution

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


## Train vs test accuracy

- Train accuracy: `0.9796`

- Test accuracy: `0.9697`

- Accuracy gap: `0.0099`

The train-test gap is below 5%, so there is no strong evidence of overfitting in the current split.

## Per-class metrics

|            |   precision |   recall |   f1-score |   support | quality_against_threshold   |
|:-----------|------------:|---------:|-----------:|----------:|:----------------------------|
| icmp_flood |      0.9231 |   1      |     0.96   |        12 | excellent                   |
| normal     |      1      |   0.9615 |     0.9804 |        26 | excellent                   |
| port_sweep |      1      |   0.7778 |     0.875  |         9 | acceptable                  |
| syn_scan   |      0.9286 |   1      |     0.963  |        26 | excellent                   |
| udp_scan   |      1      |   1      |     1      |        26 | excellent                   |


## Confusion matrix

- Absolute confusion matrix: `reports/figures/rf_confusion_matrix_eval.png`

- Normalized confusion matrix: `reports/figures/rf_confusion_matrix_normalized.png`


Absolute confusion matrix:

|            |   icmp_flood |   normal |   port_sweep |   syn_scan |   udp_scan |
|:-----------|-------------:|---------:|-------------:|-----------:|-----------:|
| icmp_flood |           12 |        0 |            0 |          0 |          0 |
| normal     |            1 |       25 |            0 |          0 |          0 |
| port_sweep |            0 |        0 |            7 |          2 |          0 |
| syn_scan   |            0 |        0 |            0 |         26 |          0 |
| udp_scan   |            0 |        0 |            0 |          0 |         26 |


## Confusion analysis

| true_label   | predicted_label   |   count |
|:-------------|:------------------|--------:|
| port_sweep   | syn_scan          |       2 |
| normal       | icmp_flood        |       1 |


From a network security perspective, false negatives where attack traffic is classified as `normal` are the most relevant errors. Confusions between two attack classes are less critical operationally, although they still indicate that the model has difficulty separating similar scanning patterns.

## Security-oriented false negatives

| attack_class   |   test_samples |   total_misclassified |   misclassified_as_normal | security_risk   |
|:---------------|---------------:|----------------------:|--------------------------:|:----------------|
| icmp_flood     |             12 |                     0 |                         0 | low             |
| port_sweep     |              9 |                     2 |                         0 | low             |
| syn_scan       |             26 |                     0 |                         0 | low             |
| udp_scan       |             26 |                     0 |                         0 | low             |


## Cross-validation

- F1 weighted scores: `[0.9691, 0.9682, 0.9799, 0.9896, 0.9313]`

- Mean F1 weighted: `0.9676`

- Std F1 weighted: `0.0198`

- Accuracy scores: `[0.9697, 0.9694, 0.9796, 0.9898, 0.9388]`

- Mean accuracy: `0.9694`

- Std accuracy: `0.0171`

The cross-validation results show that the model is stable across folds. The mean weighted F1-score is above 0.96 and the standard deviation is below 0.02, which indicates excellent and consistent performance despite the moderate class imbalance.

## ROC-AUC one-vs-rest

ROC figure: `reports/figures/rf_roc_curves_ovr.png`

|            |   auc_roc |
|:-----------|----------:|
| icmp_flood |    1      |
| normal     |    0.9989 |
| port_sweep |    0.9333 |
| syn_scan   |    0.9887 |
| udp_scan   |    1      |


## Random Forest vs Decision Tree

| model         |   train_accuracy |   test_accuracy |   accuracy_gap |   weighted_f1 |
|:--------------|-----------------:|----------------:|---------------:|--------------:|
| Random Forest |           0.9796 |          0.9697 |         0.0099 |        0.9689 |
| Decision Tree |           0.9796 |          0.9293 |         0.0503 |        0.933  |


Comparison figure: `reports/figures/rf_vs_decision_tree_comparison.png`

## Technical interpretation

The Random Forest model performs well because the selected L3/L4 features capture clear protocol-level differences between the traffic classes. The most separable classes are `udp_scan` and `icmp_flood`, both of which achieve perfect ROC-AUC values. UDP scan traffic is distinguished by protocol-level behavior and absence of TCP flags, while ICMP flood traffic is characterized by short control-like flows without TCP state. SYN scan traffic is also well detected because TCP reset behavior and low-volume handshake-like flows are strong indicators of half-open scanning.

## Error analysis and protocol-level explanation

The model produced only three errors on the test split. Two `port_sweep` flows were classified as `syn_scan`. This confusion is technically coherent: both classes can generate very short TCP flows with small packet sizes, SYN/ACK/RST behavior and no real payload transfer. In other words, at the isolated flow level, a port sweep probe can look very similar to a SYN scan probe. This is not a severe operational error because both labels correspond to reconnaissance-like attack traffic.

The remaining error corresponds to one `normal` flow classified as `icmp_flood`. The misclassified flow has zero duration, one packet, no destination-to-source bytes and no TCP flags. These properties make it geometrically similar to simple control or flood-like traffic in the feature space, even though its ground-truth label is normal. This illustrates a limitation of per-flow L3/L4 analysis: very short normal flows can resemble low-level control traffic when no temporal context is available.

From a security perspective, the most important result is that no attack flow was classified as `normal`. The `port_sweep` errors were classified as `syn_scan`, meaning the model still detected them as malicious reconnaissance-like behavior. Therefore, the remaining errors mostly affect attack type identification, not attack detection.

## Cross-validation interpretation

The 5-fold stratified cross-validation produced a mean weighted F1-score of `0.9676` with a standard deviation of `0.0198`. The mean accuracy was `0.9694` with a standard deviation of `0.0171`. These results show that the model is stable across different partitions of the dataset. This is especially relevant because the dataset is moderately imbalanced, with fewer samples for `port_sweep` and `icmp_flood`.

## Random Forest vs Decision Tree interpretation

Random Forest outperforms the single Decision Tree baseline. Both models achieve the same training accuracy, but the Decision Tree has lower test accuracy and a larger train-test gap. This confirms the expected advantage of the ensemble approach: averaging multiple trees reduces variance and improves generalization compared with a single tree.

## Limitations and improvements

The main limitation is that some scanning behaviors, especially `port_sweep`, can look similar to normal short request-response flows or SYN scan probes when each flow is analyzed in isolation. A concrete improvement would be to add temporal aggregation features such as `unique_dst_ports_per_src`, `unique_dst_hosts_per_src`, `new_connection_rate`, `dst_port_entropy` and `connection_attempts_per_second` over sliding windows. These features would capture scanning strategy more directly than per-flow statistics alone.

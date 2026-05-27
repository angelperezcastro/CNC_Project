# Random Forest Hyperparameter Optimization

## Objective

The objective of this stage is to evaluate whether the baseline Random Forest can be improved through hyperparameter optimization while keeping the model robust and avoiding overfitting.

## Search strategy

- Method: `RandomizedSearchCV`

- Number of sampled configurations: `n_iter=20`

- Cross-validation: `5-fold StratifiedKFold`

- Scoring metric: `f1_weighted`

- Reason for using weighted F1: the dataset is moderately imbalanced, especially for `port_sweep` and `icmp_flood`.

## Search space

| hyperparameter    | values           | technical meaning                                                                                  |
|:------------------|:-----------------|:---------------------------------------------------------------------------------------------------|
| n_estimators      | [50, 100, 200]   | Number of trees in the forest. More trees usually improve stability but increase training time.    |
| max_depth         | [None, 10, 20]   | Maximum depth of each decision tree. Limiting depth can reduce overfitting.                        |
| min_samples_split | [2, 5, 10]       | Minimum number of samples required to split a node. Larger values make trees more conservative.    |
| max_features      | ['sqrt', 'log2'] | Number of candidate features considered at each split. sqrt/log2 increase diversity between trees. |


## Best hyperparameters

- `n_estimators`: `200`

- `min_samples_split`: `10`

- `max_features`: `sqrt`

- `max_depth`: `20`

- Best cross-validated weighted F1 during search: `0.9519`

## Base vs optimized model

| model                   |   train_accuracy |   test_accuracy |   accuracy_gap |   weighted_f1 |
|:------------------------|-----------------:|----------------:|---------------:|--------------:|
| Random Forest Base      |           0.9796 |          0.9697 |         0.0099 |        0.9689 |
| Random Forest Optimized |           0.9745 |          0.9798 |        -0.0053 |        0.9797 |


Comparison figure: `reports/figures/rf_base_vs_optimized.png`

## Optimized model confusion matrix

|            |   icmp_flood |   normal |   port_sweep |   syn_scan |   udp_scan |
|:-----------|-------------:|---------:|-------------:|-----------:|-----------:|
| icmp_flood |           12 |        0 |            0 |          0 |          0 |
| normal     |            1 |       25 |            0 |          0 |          0 |
| port_sweep |            0 |        0 |            8 |          1 |          0 |
| syn_scan   |            0 |        0 |            0 |         26 |          0 |
| udp_scan   |            0 |        0 |            0 |          0 |         26 |


Figure: `reports/figures/rf_optimized_confusion_matrix.png`

## Optimized model feature importance

| feature                   |   importance |
|:--------------------------|-------------:|
| src2dst_bytes             |       0.1676 |
| bytes_per_packet          |       0.1396 |
| iat_mean_ms               |       0.1336 |
| bidirectional_bytes       |       0.1157 |
| bidirectional_mean_ps     |       0.1021 |
| bidirectional_rst_packets |       0.0545 |
| bidirectional_packets     |       0.0273 |
| iat_mean_ms_missing       |       0.0259 |
| iat_cv_missing            |       0.0256 |
| iat_std_ms_missing        |       0.0251 |


Figure: `reports/figures/rf_optimized_feature_importance_top10.png`

## Optimized model cross-validation

- F1 weighted scores: `[0.9458, 0.9792, 0.9799, 0.9896, 0.9313]`

- Mean F1 weighted: `0.9652`

- Std F1 weighted: `0.0225`

- Accuracy scores: `[0.9495, 0.9796, 0.9796, 0.9898, 0.9388]`

- Mean accuracy: `0.9675`

- Std accuracy: `0.0197`

## Final model decision

- Decision: `optimized_model_selected`

- Reason: The optimized model is selected because it improves the held-out test weighted F1-score and keeps the train-test gap below 5%. Although its cross-validation mean F1 is slightly lower than the baseline, the difference is small and within the defined tolerance. Therefore, the optimized model offers a better test performance while maintaining acceptable cross-validation stability.

The optimized model improves the held-out test weighted F1-score from `0.9689` to `0.9797` and increases test accuracy from `0.9697` to `0.9798`. The train-test gap remains below the 5% overfitting threshold, so there is no evidence of overfitting in the optimized model.

However, the cross-validation results show a more nuanced picture: the baseline model has a mean weighted F1-score of `0.9676` with standard deviation `0.0198`, while the optimized model obtains `0.9652` with standard deviation `0.0225`. This means that the optimized model performs better on the held-out split, while the baseline is slightly more stable across folds. Since the difference in cross-validation mean F1 is small, the optimized model is still selected, but the baseline remains a strong reference model.

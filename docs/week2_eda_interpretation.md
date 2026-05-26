
## Correction after visual EDA review

The initial scatter plot `iat_cv` vs `syn_ack_ratio_manual` did not provide useful class separation. Both variables became nearly constant after flow extraction, cleaning and imputation:

- `iat_cv` collapsed to zero because most sampled flows contain very few packets or highly regular timestamps.
- `syn_ack_ratio_manual` collapsed around 1 because bidirectional TCP flows count SYN-ACK packets as both SYN and ACK, and non-TCP flows require imputation.

For this reason, constant or zero-variance features were removed from the final ML feature list before training. The final EDA interpretation relies more on PCA 2D, byte volume, packet size, duration, protocol and missing-value indicators.

This correction avoids claiming discriminative power for features that are not empirically discriminative in the final dataset.

## Correction after visual EDA review

The initial scatter plot `iat_cv` vs `syn_ack_ratio_manual` did not provide useful class separation. Both variables became nearly constant after flow extraction, cleaning and imputation:

- `iat_cv` collapsed to zero because most sampled flows contain very few packets or highly regular timestamps.
- `syn_ack_ratio_manual` collapsed around 1 because bidirectional TCP flows count SYN-ACK packets as both SYN and ACK, and non-TCP flows require imputation.

For this reason, constant or zero-variance features were removed from the final ML feature list before training. The final EDA interpretation relies more on PCA 2D, byte volume, packet size, duration, protocol and missing-value indicators.

This correction avoids claiming discriminative power for features that are not empirically discriminative in the final dataset.

# K-Means Clustering Interpretation

Selected number of clusters: **K = 6**.

## K selection

K-Means was evaluated for K values from 2 to 10 using both the Elbow Method and the Silhouette Score. The Elbow curve shows a clear reduction in inertia from K=2 to K=4, after which the improvement becomes progressively smaller. However, the maximum Silhouette Score is obtained for K=6, indicating that the most compact and well-separated structure in the feature space contains six clusters.

Although the dataset contains five manually assigned traffic labels, this discrepancy is expected in unsupervised learning. K-Means does not use the labels during training and only groups flows according to geometric similarity in the scaled feature space. Therefore, a single semantic traffic class can be split into multiple behavioral subgroups. For example, normal traffic can be separated into TCP-like and non-TCP/request-response patterns, while scanning traffic can be grouped according to protocol, duration, TCP flags and directionality. For this reason, K=6 was selected as the final clustering configuration.

## Elbow and Silhouette results

|   k |   inertia |   silhouette |
|----:|----------:|-------------:|
|   2 |  4673.21  |     0.653593 |
|   3 |  2441.83  |     0.714743 |
|   4 |  1194.02  |     0.782829 |
|   5 |   734.541 |     0.81905  |
|   6 |   590.846 |     0.827015 |
|   7 |   512.042 |     0.791001 |
|   8 |   438.518 |     0.769961 |
|   9 |   369.033 |     0.781589 |
|  10 |   307.802 |     0.799134 |


## Cluster composition by real label

|   cluster |   icmp_flood |   normal |   port_sweep |   syn_scan |   udp_scan |
|----------:|-------------:|---------:|-------------:|-----------:|-----------:|
|         0 |       0      |   0      |       0.2182 |     0.7818 |     0      |
|         1 |       0      |   0      |       0      |     0      |     1      |
|         2 |       0      |   1      |       0      |     0      |     0      |
|         3 |       0      |   1      |       0      |     0      |     0      |
|         4 |       0.9524 |   0.0159 |       0      |     0      |     0.0317 |
|         5 |       0.0667 |   0.4667 |       0.4667 |     0      |     0      |


## Dominant label per cluster

|   cluster | dominant_label   |   proportion |
|----------:|:-----------------|-------------:|
|         0 | syn_scan         |     0.781818 |
|         1 | udp_scan         |     1        |
|         2 | normal           |     1        |
|         3 | normal           |     1        |
|         4 | icmp_flood       |     0.952381 |
|         5 | normal           |     0.466667 |


## Cluster profiles in original feature units

|   cluster |   bidirectional_duration_ms |   bidirectional_packets |   bidirectional_bytes |   bidirectional_mean_ps |   bidirectional_packets_per_ms |   iat_mean_ms |   bidirectional_syn_packets |   bidirectional_ack_packets |   bidirectional_rst_packets |   src2dst_bytes |   dst2src_bytes |   dst2src_packets |
|----------:|----------------------------:|------------------------:|----------------------:|------------------------:|-------------------------------:|--------------:|----------------------------:|----------------------------:|----------------------------:|----------------:|----------------:|------------------:|
|         0 |                           0 |                       2 |                   112 |                    56   |                              2 |        0.0131 |                           1 |                           1 |                           1 |              58 |              54 |                 1 |
|         1 |                           0 |                       1 |                    42 |                    42   |                              1 |        0.0129 |                           0 |                           0 |                           0 |              42 |               0 |                 0 |
|         2 |                           1 |                       2 |                   154 |                    81.5 |                              2 |        0.0877 |                           1 |                           1 |                           0 |             112 |              54 |                 1 |
|         3 |                           0 |                       2 |                   154 |                    81.5 |                              2 |        0.0877 |                           0 |                           0 |                           0 |              96 |              54 |                 1 |
|         4 |                           0 |                       1 |                    82 |                    81.5 |                              1 |        0.0129 |                           0 |                           0 |                           0 |              82 |               0 |                 0 |
|         5 |                           1 |                       2 |                   154 |                    81.5 |                              2 |        0.0877 |                           0 |                           0 |                           0 |             112 |              54 |                 1 |


## Technical interpretation


### Cluster 0 — TCP reconnaissance / SYN scan with reset

This cluster is mainly composed of `syn_scan` traffic, with a smaller proportion of `port_sweep`. It is characterized by extremely short flows, small packets, and the presence of SYN, ACK and RST flags. This behavior is coherent with TCP reconnaissance, especially half-open SYN scans, where the scanner sends SYN packets and aborts the connection using RST before completing a normal data exchange.

The presence of port sweep traffic in the same cluster is also reasonable, because port sweeps generate short low-volume probing flows with similar asymmetry and no meaningful payload transfer.

### Cluster 1 — UDP scan without response

This cluster is a pure `udp_scan` cluster. Its flows usually contain a single packet, no destination-to-source response and no TCP flags. This matches UDP scanning behavior: UDP has no handshake, and probes to closed or filtered ports may not generate a useful bidirectional flow.

### Cluster 2 — Normal short TCP traffic

This cluster contains only `normal` traffic. It is characterized by short bidirectional flows with SYN and ACK flags but no RST. Compared with the SYN scan cluster, the absence of reset behavior indicates that these flows are not aborted in the same way as half-open scans.

### Cluster 3 — Normal non-TCP / short request-response traffic

This cluster also contains only `normal` traffic, but unlike Cluster 2, it has no TCP flags. This suggests normal non-TCP or request-response traffic. K-Means separates it from normal TCP traffic because the feature geometry is different, even though both groups share the same semantic label.

### Cluster 4 — ICMP flood / one-way control traffic

This cluster is mainly composed of `icmp_flood` traffic. It is characterized by one-packet flows, zero duration, no destination-to-source bytes and no TCP flags. This is coherent with ICMP flood behavior, where packets are generated rapidly without TCP state or handshake.

### Cluster 5 — Ambiguous short bidirectional flows

This is the least pure cluster. It contains both `normal` and `port_sweep` flows. The common pattern is short bidirectional traffic without TCP flags. This indicates that some port sweep flows can resemble normal request-response traffic when only isolated per-flow L3/L4 features are used.

A possible improvement would be to add temporal aggregation features such as the number of unique destination ports contacted per source IP, number of destination hosts per time window, or scan rate. These features would represent scanning behavior more directly than per-flow statistics alone.

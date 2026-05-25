# Week 2 Day 1 - NFStream Exploration Notes

## Objective

Explore NFStream flow extraction from normalized PCAP files and identify relevant L3/L4 columns for the feature engineering stage.

## Technical compatibility issue

The original Docker/WSL PCAPs were captured using Linux cooked capture v2 (`LINUX_SLL2`). NFStream failed to extract flows directly from that format. To solve this, the PCAPs were normalized into Ethernet/IP PCAPs under:

`data/interim/nfstream_compatible`

The normalization preserves timestamps and L3/L4 headers while replacing only the link-layer header. This is acceptable because the project does not use Ethernet MAC addresses or L2 fields as Machine Learning features.

## Processed PCAPs

| label      | pcap_file                   |   n_flows |
|:-----------|:----------------------------|----------:|
| icmp_flood | icmp_flood_week1_final.pcap |        61 |
| normal     | normal_week1_final.pcap     |       546 |
| port_sweep | port_sweep_week1_final.pcap |        43 |
| syn_scan   | syn_scan_week1_final.pcap   |     60120 |
| udp_scan   | udp_scan_week1_final.pcap   |     19801 |

## Combined DataFrame

- Total flows: 80571
- Total columns: 98

## Labels found

| label      |   n_flows |
|:-----------|----------:|
| syn_scan   |     60120 |
| udp_scan   |     19801 |
| normal     |       546 |
| icmp_flood |        61 |
| port_sweep |        43 |

## Summary by label

| label      |   n_flows |   n_pcaps |   bidirectional_duration_ms_mean |   bidirectional_duration_ms_median |   bidirectional_duration_ms_std |   bidirectional_packets_mean |   bidirectional_packets_median |   bidirectional_packets_std |   bidirectional_bytes_mean |   bidirectional_bytes_median |   bidirectional_bytes_std |   src2dst_packets_mean |   src2dst_packets_median |   src2dst_packets_std |   src2dst_bytes_mean |   src2dst_bytes_median |   src2dst_bytes_std |   dst2src_packets_mean |   dst2src_packets_median |   dst2src_packets_std |   dst2src_bytes_mean |   dst2src_bytes_median |   dst2src_bytes_std |   bidirectional_mean_ps_mean |   bidirectional_mean_ps_median |   bidirectional_mean_ps_std |   bytes_asymmetry_ratio_mean |   bytes_asymmetry_ratio_median |   bytes_asymmetry_ratio_std |   packets_asymmetry_ratio_mean |   packets_asymmetry_ratio_median |   packets_asymmetry_ratio_std |   packets_per_ms_mean |   packets_per_ms_median |   packets_per_ms_std |   bytes_per_packet_mean |   bytes_per_packet_median |   bytes_per_packet_std |
|:-----------|----------:|----------:|---------------------------------:|-----------------------------------:|--------------------------------:|-----------------------------:|-------------------------------:|----------------------------:|---------------------------:|-----------------------------:|--------------------------:|-----------------------:|-------------------------:|----------------------:|---------------------:|-----------------------:|--------------------:|-----------------------:|-------------------------:|----------------------:|---------------------:|-----------------------:|--------------------:|-----------------------------:|-------------------------------:|----------------------------:|-----------------------------:|-------------------------------:|----------------------------:|-------------------------------:|---------------------------------:|------------------------------:|----------------------:|------------------------:|---------------------:|------------------------:|--------------------------:|-----------------------:|
| icmp_flood |        61 |         1 |                         9428.89  |                                  0 |                       73641.9   |                    94982.2   |                              1 |                  741827     |                3.98929e+06 |                           88 |               3.11567e+07 |              47491.6   |                        1 |            370913     |          1.99468e+06 |                     88 |         1.55784e+07 |              47490.6   |                        0 |            370913     |          1.99461e+06 |                      0 |         1.55784e+07 |                       76.426 |                           66   |                      11.878 |                       76.738 |                         67     |                      14.771 |                          1.984 |                            2     |                         0.128 |                10.073 |                  10.073 |              nan     |                  76.426 |                      66   |                 11.878 |
| normal     |       546 |         1 |                           11.824 |                                  1 |                          35.937 |                       53.762 |                             10 |                     194.644 |                1.00539e+06 |                         1241 |               5.30716e+06 |                 31.663 |                        6 |               131.534 |     834098           |                    594 |         5.3012e+06  |                 22.099 |                        4 |                64     |     171289           |                    767 |    551695           |                     3952.45  |                          112.5 |                    7599.53  |                       75.714 |                          0.944 |                     246.467 |                          1.173 |                            1.107 |                         0.338 |                13.082 |                  10     |               13.275 |                3952.45  |                     112.5 |               7599.53  |
| port_sweep |        43 |         1 |                          129.442 |                                  0 |                         844.125 |                       24.628 |                              2 |                      58.621 |             2040           |                          112 |            5022.28        |                 23.791 |                        1 |                58.951 |       1994.51        |                     58 |      5040.12        |                  0.837 |                        1 |                 0.374 |         45.488       |                     54 |        20.322       |                       60.702 |                           56   |                      10.668 |                     1943.31  |                          1.073 |                    5060.6   |                         23.919 |                            1     |                        59.294 |                18.028 |                  18.833 |               14.367 |                  60.702 |                      56   |                 10.668 |
| syn_scan   |     60120 |         1 |                            0.015 |                                  0 |                           0.121 |                        2.003 |                              2 |                       0.055 |              112.236       |                          112 |               3.489       |                  1.005 |                        1 |                 0.07  |         58.331       |                     58 |         4.825       |                  0.998 |                        1 |                 0.045 |         53.904       |                     54 |         2.421       |                       56.033 |                           56   |                       0.735 |                        1.361 |                          1.073 |                       6.398 |                          1.005 |                            1     |                         0.093 |                 2.011 |                   2     |                0.105 |                  56.033 |                      56   |                  0.735 |
| udp_scan   |     19801 |         1 |                           28.958 |                                  0 |                        4074.56  |                        1.016 |                              1 |                       1.841 |               44.361       |                           42 |             131.638       |                  1.014 |                        1 |                 1.699 |         44.224       |                     42 |       120.017       |                  0.002 |                        0 |                 0.146 |          0.137       |                      0 |        11.78        |                       43.232 |                           42   |                      10.659 |                       44.319 |                         43     |                      11.579 |                          2.001 |                            2     |                         0.087 |                 1.59  |                   2     |                0.791 |                  43.232 |                      42   |                 10.659 |

## Key NFStream column families

### Flow identity

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`

### Timing

- `bidirectional_first_seen_ms`
- `bidirectional_last_seen_ms`
- `bidirectional_duration_ms`

### Volume

- `bidirectional_packets`
- `bidirectional_bytes`
- `src2dst_packets`
- `src2dst_bytes`
- `dst2src_packets`
- `dst2src_bytes`

### Packet size

- `bidirectional_mean_ps`
- `bidirectional_min_ps`
- `bidirectional_max_ps`
- `bidirectional_stddev_ps`

### Directional asymmetry

Derived exploratory features:

- `bytes_asymmetry_ratio`
- `packets_asymmetry_ratio`

### Packet rate

Derived exploratory feature:

- `packets_per_ms`

## Bidirectional vs directional flows

NFStream represents each flow as a bidirectional communication. The `bidirectional_*` columns summarize both directions together. The `src2dst_*` columns describe packets from the initial source to the destination. The `dst2src_*` columns describe packets in the reverse direction.

This distinction is important because normal client-server traffic usually contains both requests and responses, while scans and floods often produce asymmetric flows.

## TCP flags

bidirectional_syn_packets, bidirectional_cwr_packets, bidirectional_ece_packets, bidirectional_urg_packets, bidirectional_ack_packets, bidirectional_psh_packets, bidirectional_rst_packets, bidirectional_fin_packets, src2dst_syn_packets, src2dst_cwr_packets, src2dst_ece_packets, src2dst_urg_packets, src2dst_ack_packets, src2dst_psh_packets, src2dst_rst_packets, src2dst_fin_packets, dst2src_syn_packets, dst2src_cwr_packets, dst2src_ece_packets, dst2src_urg_packets, dst2src_ack_packets, dst2src_psh_packets, dst2src_rst_packets, dst2src_fin_packets

## L7 columns excluded from final ML features

Potential L7/application metadata columns detected:

application_name, application_category_name, application_is_guessed, application_confidence, requested_server_name, client_fingerprint, server_fingerprint, user_agent, content_type

These columns will not be used in the final ML feature set because the project focuses on L3/L4 features without payload inspection.

## Initial findings

The first NFStream exploration confirms that the dataset can be converted into a flow-level table. Duration, bytes, packets, packet size and directional asymmetry are available or derivable and are suitable candidates for the next feature selection stage.

The next step is to formalize the selected features and compute advanced manual features with Scapy, including IAT, RTT estimate, TCP window statistics and SYN/ACK ratio.

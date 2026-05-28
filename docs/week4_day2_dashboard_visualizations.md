# Week 4 Day 2 — Interactive Dashboard Visualizations

## Goal

Extend the Streamlit dashboard with interactive visualizations and anomaly alerts.

## Implemented features

- Plotly bar chart showing the predicted class distribution.
- Plotly scatter plot showing `bytes` vs `duration_ms`, colored by predicted class.
- Plotly timeline showing flows ordered by relative capture time.
- Class-filterable flow table.
- Confidence-based cell coloring in the table:
  - Green: confidence >= 80%.
  - Yellow: 60% <= confidence < 80%.
  - Red: confidence < 60%.
- Anomaly alert banner using `st.error()`.
- About section explaining the system, features, model artifacts and anomaly threshold.
- Mean prediction confidence metric.

## Technical decisions

### Why a class distribution bar chart?

The bar chart provides a fast summary of the traffic composition in the uploaded PCAP.
It allows the analyst to immediately identify whether the capture is mostly normal
or dominated by a specific attack class.

### Why bytes vs duration?

The scatter plot of `bytes` vs `duration_ms` visualizes the feature space learned by
the model. Normal application traffic usually generates larger and more diverse flows,
while scans tend to produce short flows with low payload volume. This makes the plot
useful both for analysis and for the technical report.

### Why a timeline?

The timeline shows when each class appears during the capture. This is useful for
identifying whether an attack occurs throughout the full capture or starts at a
specific point in time.

### Why class filtering?

Class filtering allows the analyst to inspect only relevant flows, for example only
`syn_scan` flows. This makes the table usable even when the PCAP contains thousands
of flows.

## Validation evidence

### Test PCAP

`data/test/mixed_day5.pcap`

### Observed metrics

| Metric | Value |
|---|---:|
| Total flows | 2027 |
| Normal flows | 39 |
| Anomalous flows | 1988 |
| Most frequent attack | syn_scan |
| Mean confidence | 75.77% |

### Predicted class distribution

| Predicted class | Flows |
|---|---:|
| syn_scan | 986 |
| udp_scan | 973 |
| normal | 39 |
| port_sweep | 15 |
| icmp_flood | 14 |

### Table filter validation

| Filter | Expected visible rows |
|---|---:|
| syn_scan | 986 |
| udp_scan | 973 |
| normal | 39 |
| port_sweep | 15 |
| icmp_flood | 14 |

## Dashboard checklist

- [ ] `streamlit run app.py` starts successfully.
- [ ] `mixed_day5.pcap` can be uploaded.
- [ ] The dashboard shows the five metrics.
- [ ] The anomaly banner appears with `st.error()`.
- [ ] The class distribution bar chart is visible.
- [ ] The bytes vs duration scatter plot is visible.
- [ ] The timeline is visible.
- [ ] The table can be filtered by predicted class.
- [ ] The About section is visible.
- [ ] A screenshot of the scatter plot has been saved for the report.

## Known limitations

- The current dashboard analyzes uploaded PCAPs in batch mode, not live streaming.
- Large PCAP files may take several seconds to process.
- The timeline depends on flow start timestamps extracted by the pipeline.
- Mean confidence should be interpreted together with class-level metrics, not as a standalone accuracy score.

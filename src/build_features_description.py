"""
Build the L3/L4 feature description document for the NetFlow Analyzer project.

This script reads the exploratory NFStream outputs from Week 2 Day 1,
defines the selected feature set, computes derived feature statistics,
and writes a Markdown document with formulas, protocol-level justification
and expected behavior by traffic class.

Outputs:
    - docs/features_description.md
    - data/processed/selected_features_inventory.csv
    - data/processed/selected_features_stats_by_label.csv
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
DOCS_DIR = PROJECT_ROOT / "docs"

FLOW_PATH = PROCESSED_DIR / "nfstream_all_flows_exploration.csv"
SUMMARY_PATH = PROCESSED_DIR / "nfstream_summary_by_label.csv"
PROTOCOL_PATH = PROCESSED_DIR / "nfstream_protocol_distribution.csv"

OUT_DOC = DOCS_DIR / "features_description.md"
OUT_INVENTORY = PROCESSED_DIR / "selected_features_inventory.csv"
OUT_STATS = PROCESSED_DIR / "selected_features_stats_by_label.csv"


SELECTED_FEATURES: list[dict[str, Any]] = [
    {
        "feature": "protocol",
        "type": "NFStream base",
        "formula": "IP protocol number: 1=ICMP, 6=TCP, 17=UDP",
        "justification": (
            "The transport/network protocol is an L3/L4 field and separates "
            "connection-oriented TCP traffic from connectionless UDP and ICMP. "
            "It is useful because the attacks in the dataset exercise different "
            "protocol behavior without inspecting payload."
        ),
        "expected_normal": "TCP and UDP mixture due to HTTP/FTP/DNS.",
        "expected_icmp_flood": "Mostly ICMP, although Docker DNS noise may appear as UDP.",
        "expected_syn_scan": "Mostly TCP.",
        "expected_udp_scan": "Mostly UDP.",
        "expected_port_sweep": "Mixed TCP/ICMP depending on probe type.",
        "model_use": "Use, encoded as categorical/numeric protocol identifier.",
    },
    {
        "feature": "bidirectional_duration_ms",
        "type": "NFStream base",
        "formula": "last_packet_timestamp_ms - first_packet_timestamp_ms",
        "justification": (
            "A legitimate TCP flow normally includes connection setup, data transfer "
            "and teardown, while scans often create very short probe flows. "
            "Duration is therefore a direct behavioral indicator of whether a flow "
            "contains real communication or only reconnaissance/control packets."
        ),
        "expected_normal": "Higher and more variable; HTTP/FTP may last milliseconds to seconds.",
        "expected_icmp_flood": "Can be very short or aggregated into a long high-rate flow.",
        "expected_syn_scan": "Very short flows, often near 0 ms in Docker.",
        "expected_udp_scan": "Short flows, usually one request and little/no response.",
        "expected_port_sweep": "Short probe flows with little data exchange.",
        "model_use": "Use.",
    },
    {
        "feature": "bidirectional_packets",
        "type": "NFStream base",
        "formula": "count(all packets in both directions)",
        "justification": (
            "Packet count measures the volume of interaction inside a flow. "
            "Real client-server communication usually involves several packets, "
            "whereas scan flows are often composed of one or two packets."
        ),
        "expected_normal": "Moderate to high, especially for HTTP/FTP transfers.",
        "expected_icmp_flood": "Potentially very high if NFStream aggregates flood packets.",
        "expected_syn_scan": "Very low, commonly 1-3 packets per flow.",
        "expected_udp_scan": "Very low, frequently 1 packet per destination/port.",
        "expected_port_sweep": "Low per host/port probe.",
        "model_use": "Use.",
    },
    {
        "feature": "bidirectional_bytes",
        "type": "NFStream base",
        "formula": "sum(packet sizes in both directions)",
        "justification": (
            "Byte count captures the amount of data exchanged. "
            "Legitimate traffic tends to carry more application data, while scans "
            "and probes are dominated by headers and small control packets."
        ),
        "expected_normal": "Higher and more variable due to HTTP/FTP payloads.",
        "expected_icmp_flood": "Can be high if many ICMP packets are grouped into one flow.",
        "expected_syn_scan": "Low; TCP control packets without payload.",
        "expected_udp_scan": "Low; small UDP probes and sparse replies.",
        "expected_port_sweep": "Low; mainly probe packets.",
        "model_use": "Use.",
    },
    {
        "feature": "src2dst_packets",
        "type": "NFStream base",
        "formula": "count(packets from initial source to destination)",
        "justification": (
            "Directional packet count distinguishes active probing from normal "
            "request-response traffic. Attack tools often generate many outgoing "
            "probes with limited reverse traffic."
        ),
        "expected_normal": "Client requests plus data/control packets.",
        "expected_icmp_flood": "High in attack direction if attacker is source.",
        "expected_syn_scan": "Usually one SYN probe per flow direction.",
        "expected_udp_scan": "Usually one UDP probe per flow.",
        "expected_port_sweep": "Outgoing probes towards multiple hosts/ports.",
        "model_use": "Use.",
    },
    {
        "feature": "dst2src_packets",
        "type": "NFStream base",
        "formula": "count(packets from destination back to initial source)",
        "justification": (
            "Reverse-direction packet count measures response behavior. "
            "Normal flows usually receive replies, while scans may receive few, "
            "none, or reset/error responses."
        ),
        "expected_normal": "Usually present due to server responses.",
        "expected_icmp_flood": "Low or absent depending on echo replies and aggregation.",
        "expected_syn_scan": "SYN-ACK/RST responses may appear, but data exchange is absent.",
        "expected_udp_scan": "Often zero or ICMP unreachable responses.",
        "expected_port_sweep": "Sparse responses from alive hosts only.",
        "model_use": "Use.",
    },
    {
        "feature": "src2dst_bytes",
        "type": "NFStream base",
        "formula": "sum(bytes from initial source to destination)",
        "justification": (
            "Directional bytes quantify how much traffic is sent by the initiator. "
            "This is useful to capture scan/flood behavior where most bytes come "
            "from the probing side."
        ),
        "expected_normal": "Variable; requests may be smaller than responses.",
        "expected_icmp_flood": "High in attack direction if flood is grouped.",
        "expected_syn_scan": "Low; SYN/control packets only.",
        "expected_udp_scan": "Low; small UDP probes.",
        "expected_port_sweep": "Low per probe, repeated over many targets.",
        "model_use": "Use.",
    },
    {
        "feature": "dst2src_bytes",
        "type": "NFStream base",
        "formula": "sum(bytes from destination back to initial source)",
        "justification": (
            "Reverse bytes capture whether the destination actually responds. "
            "This is important because reconnaissance traffic often has little "
            "or no reverse data compared with normal services."
        ),
        "expected_normal": "Often significant due to HTTP/FTP responses.",
        "expected_icmp_flood": "Low or response-dependent.",
        "expected_syn_scan": "Low; SYN-ACK/RST only.",
        "expected_udp_scan": "Often zero or small ICMP errors.",
        "expected_port_sweep": "Sparse and low-volume responses.",
        "model_use": "Use.",
    },
    {
        "feature": "bytes_asymmetry_ratio",
        "type": "Derived",
        "formula": "(src2dst_bytes + 1) / (dst2src_bytes + 1)",
        "justification": (
            "The +1 smoothing avoids division by zero. "
            "The ratio measures whether the flow is balanced or dominated by one "
            "direction. Scans and floods often produce extreme asymmetry."
        ),
        "expected_normal": "Closer to balanced or response-heavy depending on service.",
        "expected_icmp_flood": "High if many packets go from attacker to victim.",
        "expected_syn_scan": "Often moderately/highly asymmetric.",
        "expected_udp_scan": "High when destinations do not respond.",
        "expected_port_sweep": "High for unanswered probes.",
        "model_use": "Use.",
    },
    {
        "feature": "packets_asymmetry_ratio",
        "type": "Derived",
        "formula": "(src2dst_packets + 1) / (dst2src_packets + 1)",
        "justification": (
            "This captures request-response imbalance independently of packet size. "
            "It is useful when bytes are small but the number of probes is meaningful."
        ),
        "expected_normal": "Usually near balanced in established flows.",
        "expected_icmp_flood": "High in attack direction if replies are limited.",
        "expected_syn_scan": "Often near 1-2 depending on SYN-ACK/RST response.",
        "expected_udp_scan": "High when UDP probes receive no response.",
        "expected_port_sweep": "High for one-way host/port probes.",
        "model_use": "Use.",
    },
    {
        "feature": "bidirectional_mean_ps",
        "type": "NFStream base",
        "formula": "mean(packet_size_bytes over all packets in the flow)",
        "justification": (
            "Packet size separates data-transfer traffic from control/probe traffic. "
            "Scans usually contain only headers and small packets, while normal "
            "HTTP/FTP traffic can contain larger data packets."
        ),
        "expected_normal": "Higher and more variable; can approach MTU in data transfers.",
        "expected_icmp_flood": "Small and stable ICMP packet sizes.",
        "expected_syn_scan": "Small TCP control packets.",
        "expected_udp_scan": "Small UDP probe packets.",
        "expected_port_sweep": "Small probe packets.",
        "model_use": "Use.",
    },
    {
        "feature": "bidirectional_syn_packets",
        "type": "NFStream TCP flags",
        "formula": "count(TCP packets with SYN flag)",
        "justification": (
            "SYN packets initiate TCP connections. A high number of SYN packets "
            "without corresponding data exchange is characteristic of scanning."
        ),
        "expected_normal": "Low; usually one per TCP connection.",
        "expected_icmp_flood": "N/A or zero because ICMP has no TCP flags.",
        "expected_syn_scan": "High relative to useful data exchange.",
        "expected_udp_scan": "N/A or zero because UDP has no TCP flags.",
        "expected_port_sweep": "Present when TCP probes are used.",
        "model_use": "Use for TCP flows; zero/NaN handling during cleaning.",
    },
    {
        "feature": "bidirectional_ack_packets",
        "type": "NFStream TCP flags",
        "formula": "count(TCP packets with ACK flag)",
        "justification": (
            "ACK packets indicate TCP handshake completion and data acknowledgment. "
            "Normal connections produce multiple ACKs, while incomplete scans do not "
            "produce the same ACK pattern."
        ),
        "expected_normal": "Common in established TCP connections.",
        "expected_icmp_flood": "N/A or zero.",
        "expected_syn_scan": "Lower than normal established traffic.",
        "expected_udp_scan": "N/A or zero.",
        "expected_port_sweep": "Sparse, depending on probe response.",
        "model_use": "Use.",
    },
    {
        "feature": "bidirectional_rst_packets",
        "type": "NFStream TCP flags",
        "formula": "count(TCP packets with RST flag)",
        "justification": (
            "RST indicates abrupt connection reset. SYN scans commonly trigger or send "
            "RST packets because the scanner does not complete a normal session."
        ),
        "expected_normal": "Occasional but not dominant.",
        "expected_icmp_flood": "N/A or zero.",
        "expected_syn_scan": "Relevant; often present in half-open scan behavior.",
        "expected_udp_scan": "N/A or zero.",
        "expected_port_sweep": "Can appear when probing closed TCP ports.",
        "model_use": "Use.",
    },
    {
        "feature": "bidirectional_fin_packets",
        "type": "NFStream TCP flags",
        "formula": "count(TCP packets with FIN flag)",
        "justification": (
            "FIN is used for graceful TCP connection termination. Its presence is more "
            "consistent with legitimate sessions than one-shot scans."
        ),
        "expected_normal": "May appear when TCP sessions close normally.",
        "expected_icmp_flood": "N/A or zero.",
        "expected_syn_scan": "Usually low or zero.",
        "expected_udp_scan": "N/A or zero.",
        "expected_port_sweep": "Usually low or zero.",
        "model_use": "Use.",
    },
    {
        "feature": "bidirectional_psh_packets",
        "type": "NFStream TCP flags",
        "formula": "count(TCP packets with PSH flag)",
        "justification": (
            "PSH is commonly associated with TCP segments carrying application data. "
            "It can help separate real data exchange from pure control/probe traffic."
        ),
        "expected_normal": "More likely in HTTP/FTP data exchange.",
        "expected_icmp_flood": "N/A or zero.",
        "expected_syn_scan": "Usually zero.",
        "expected_udp_scan": "N/A or zero.",
        "expected_port_sweep": "Usually zero.",
        "model_use": "Use.",
    },
    {
        "feature": "syn_ack_ratio",
        "type": "Derived from TCP flags",
        "formula": "bidirectional_syn_packets / bidirectional_ack_packets; NaN if ACK count is zero",
        "justification": (
            "TCP handshakes require a relationship between SYN and ACK packets. "
            "A large deviation indicates connection attempts that do not become "
            "normal established sessions, which is typical of reconnaissance scans."
        ),
        "expected_normal": "Close to balanced or below 1 when many data ACKs exist.",
        "expected_icmp_flood": "NaN or zero; not TCP.",
        "expected_syn_scan": "High when SYNs dominate over ACKs.",
        "expected_udp_scan": "NaN or zero; not TCP.",
        "expected_port_sweep": "High for unanswered TCP probes.",
        "model_use": "Use after cleaning/imputation.",
    },
    {
        "feature": "bidirectional_packets_per_ms",
        "type": "Derived",
        "formula": "bidirectional_packets / max(bidirectional_duration_ms, 1)",
        "justification": (
            "Packet rate captures intensity. Floods and aggressive scans can generate "
            "many packets in short windows, while normal traffic is usually more "
            "variable and less uniformly concentrated."
        ),
        "expected_normal": "Variable but usually lower than aggressive attacks.",
        "expected_icmp_flood": "High if flood packets are grouped by NFStream.",
        "expected_syn_scan": "Can be high because duration is near zero.",
        "expected_udp_scan": "Moderate/high for rapid probes.",
        "expected_port_sweep": "Moderate/high for rapid host probing.",
        "model_use": "Use with capping/outlier handling later.",
    },
]


EXCLUDED_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "application_name",
    "application_category_name",
    "application_is_guessed",
    "application_confidence",
    "requested_server_name",
    "client_fingerprint",
    "server_fingerprint",
    "user_agent",
    "content_type",
]


def require_file(path: Path) -> None:
    """
    Ensure that a required input file exists.

    Args:
        path: File path to validate.

    Raises:
        FileNotFoundError: If the path does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Required file not found: {path}. "
            "Run notebooks/01_nfstream_exploration.ipynb first."
        )


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add derived L3/L4 features used for feature selection documentation.

    Args:
        df: Flow-level NFStream DataFrame.

    Returns:
        Copy of df with derived features added.
    """
    out = df.copy()

    if {"src2dst_bytes", "dst2src_bytes"}.issubset(out.columns):
        out["bytes_asymmetry_ratio"] = (out["src2dst_bytes"] + 1) / (out["dst2src_bytes"] + 1)

    if {"src2dst_packets", "dst2src_packets"}.issubset(out.columns):
        out["packets_asymmetry_ratio"] = (out["src2dst_packets"] + 1) / (out["dst2src_packets"] + 1)

    if {"bidirectional_packets", "bidirectional_duration_ms"}.issubset(out.columns):
        duration_safe = out["bidirectional_duration_ms"].clip(lower=1)
        out["bidirectional_packets_per_ms"] = out["bidirectional_packets"] / duration_safe

    if {"bidirectional_syn_packets", "bidirectional_ack_packets"}.issubset(out.columns):
        ack = out["bidirectional_ack_packets"].replace(0, np.nan)
        out["syn_ack_ratio"] = out["bidirectional_syn_packets"] / ack

    return out


def compute_feature_stats(df: pd.DataFrame, selected_features: list[str]) -> pd.DataFrame:
    """
    Compute per-label statistics for selected numeric features.

    Args:
        df: Flow-level DataFrame.
        selected_features: List of selected feature names.

    Returns:
        Long-form DataFrame with mean, median, std, min, max and null percentage.
    """
    rows: list[dict[str, Any]] = []

    for feature in selected_features:
        if feature not in df.columns:
            rows.append(
                {
                    "feature": feature,
                    "label": "ALL",
                    "available": False,
                    "mean": np.nan,
                    "median": np.nan,
                    "std": np.nan,
                    "min": np.nan,
                    "max": np.nan,
                    "null_pct": 100.0,
                }
            )
            continue

        if not pd.api.types.is_numeric_dtype(df[feature]):
            continue

        for label, group in df.groupby("label"):
            values = group[feature]
            rows.append(
                {
                    "feature": feature,
                    "label": label,
                    "available": True,
                    "mean": round(values.mean(skipna=True), 6),
                    "median": round(values.median(skipna=True), 6),
                    "std": round(values.std(skipna=True), 6),
                    "min": round(values.min(skipna=True), 6),
                    "max": round(values.max(skipna=True), 6),
                    "null_pct": round(values.isna().mean() * 100, 3),
                }
            )

    return pd.DataFrame(rows)


def sanitize_for_markdown(value: Any) -> str:
    """
    Convert a value into a Markdown table-safe string.

    Args:
        value: Any object.

    Returns:
        Markdown-safe string without pipe characters.
    """
    return str(value).replace("|", "/")


def build_markdown(
    inventory: pd.DataFrame,
    stats: pd.DataFrame,
    summary: pd.DataFrame,
    protocols: pd.DataFrame,
) -> str:
    """
    Build the complete Markdown document.

    Args:
        inventory: Selected feature inventory.
        stats: Per-label selected feature statistics.
        summary: Summary by label from Day 1.
        protocols: Protocol distribution from Day 1.

    Returns:
        Markdown document as string.
    """
    inventory_md = inventory.applymap(sanitize_for_markdown).to_markdown(index=False)

    stats_excerpt = stats[
        stats["feature"].isin(
            [
                "bidirectional_duration_ms",
                "bidirectional_packets",
                "bidirectional_bytes",
                "bytes_asymmetry_ratio",
                "bidirectional_mean_ps",
                "syn_ack_ratio",
                "bidirectional_packets_per_ms",
            ]
        )
    ]

    return f"""# L3/L4 Feature Description

## Objective

This document defines the selected L3/L4 features for the NetFlow Analyzer project. The goal is to classify network traffic using flow-level behavior without inspecting packet payloads.

The selected features are based on:

1. NFStream flow reconstruction.
2. Directional traffic statistics.
3. TCP flag counters.
4. Derived ratios that summarize asymmetry and packet rate.

## Scope

The project intentionally avoids payload inspection and application-layer signatures. Therefore, fields such as application names, TLS fingerprints, requested server names, user agents and content types are excluded from the final Machine Learning feature set.

## Selected feature inventory

{inventory_md}

## Empirical dataset summary

The following table comes from the NFStream exploration stage.

{summary.to_markdown(index=False)}

## Protocol distribution by label

{protocols.to_markdown(index=False)}

## Selected feature statistics by label

The full version is stored in:

`data/processed/selected_features_stats_by_label.csv`

Excerpt:

{stats_excerpt.to_markdown(index=False)}

## Excluded columns

The following columns are not selected for the initial ML feature set:

{", ".join(f"`{col}`" for col in EXCLUDED_COLUMNS)}

### Reason for exclusion

- IP addresses can cause the model to memorize the Docker lab topology.
- Ports can cause overfitting to the specific services used in the experiment.
- Application-layer fields violate the L3/L4-only design goal.
- Fingerprints and content-related fields depend on DPI or application metadata.

## Notes for the next step

The next feature engineering step will add manual Scapy-based features:

- Inter-arrival time mean, standard deviation and coefficient of variation.
- Estimated TCP RTT from SYN to SYN-ACK.
- TCP window size statistics.
- Manual SYN/ACK ratio validation.

These manual features are expected to strengthen the protocol-level interpretation of the model.
"""


def main() -> None:
    """Generate feature description documentation and supporting CSV files."""
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    require_file(FLOW_PATH)
    require_file(SUMMARY_PATH)
    require_file(PROTOCOL_PATH)

    flows = pd.read_csv(FLOW_PATH)
    summary = pd.read_csv(SUMMARY_PATH)
    protocols = pd.read_csv(PROTOCOL_PATH)

    flows = add_derived_features(flows)

    inventory = pd.DataFrame(SELECTED_FEATURES)
    selected_feature_names = inventory["feature"].tolist()

    forbidden_tokens = [
        "application",
        "fingerprint",
        "user_agent",
        "content_type",
        "requested_server",
    ]

    invalid_selected = [
        feature
        for feature in selected_feature_names
        if any(token in feature.lower() for token in forbidden_tokens)
    ]

    if invalid_selected:
        raise ValueError(f"L7/application features selected by mistake: {invalid_selected}")

    stats = compute_feature_stats(flows, selected_feature_names)

    inventory.to_csv(OUT_INVENTORY, index=False)
    stats.to_csv(OUT_STATS, index=False)

    markdown = build_markdown(
        inventory=inventory,
        stats=stats,
        summary=summary,
        protocols=protocols,
    )

    OUT_DOC.write_text(markdown, encoding="utf-8")

    print(f"Saved: {OUT_DOC}")
    print(f"Saved: {OUT_INVENTORY}")
    print(f"Saved: {OUT_STATS}")
    print(f"Selected features: {len(selected_feature_names)}")


if __name__ == "__main__":
    main()

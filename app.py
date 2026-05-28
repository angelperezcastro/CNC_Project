"""
Streamlit dashboard for NetFlow Analyzer.

Week 4 Day 3 scope:
- Upload a PCAP/PCAPNG file.
- Run the existing prediction pipeline from src.predict.
- Show summary metrics including mean confidence and analysis time.
- Show an anomaly alert banner.
- Show interactive Plotly visualizations:
  1. Class distribution bar chart.
  2. Bytes vs duration scatter plot.
  3. Flow timeline.
- Show a class-filterable flow table.
- Show an About section explaining the system.
- Improve UX for long analyses and invalid PCAP files.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

from src.dashboard_adapter import (
    analyze_pcap_for_dashboard,
    build_flow_table,
    first_existing_column,
)
from src.predict import DEFAULT_NORMAL_THRESHOLD


st.set_page_config(
    page_title="NetFlow Analyzer",
    page_icon="🛡️",
    layout="wide",
)


DURATION_ALIASES = ("duration_ms", "bidirectional_duration_ms", "flow_duration_ms")
BYTES_ALIASES = ("bytes", "bidirectional_bytes", "total_bytes")
PACKETS_ALIASES = ("packets", "bidirectional_packets", "total_packets")
START_TIME_ALIASES = (
    "bidirectional_first_seen_ms",
    "first_seen_ms",
    "timestamp",
    "start_time",
    "flow_start_ms",
)
SRC_IP_ALIASES = ("src_ip", "source_ip", "src_addr", "src")
DST_IP_ALIASES = ("dst_ip", "destination_ip", "dst_addr", "dst")
SRC_PORT_ALIASES = ("src_port", "source_port", "sport")
DST_PORT_ALIASES = ("dst_port", "destination_port", "dport")


def main() -> None:
    """
    Render the NetFlow Analyzer dashboard.
    """
    st.title("🛡️ NetFlow Analyzer")
    st.caption(
        "Upload a PCAP file, execute the trained ML pipeline, and inspect classified network flows."
    )

    render_sidebar()

    if "predictions_df" not in st.session_state:
        render_empty_state()
        render_about()
        return

    predictions_df = st.session_state["predictions_df"]
    uploaded_filename = st.session_state.get("uploaded_filename", "uploaded capture")

    st.markdown(f"### Analysis result: `{uploaded_filename}`")

    render_metrics(predictions_df)
    render_anomaly_alert(predictions_df)
    render_visualizations(predictions_df)
    render_filtered_table(predictions_df)
    render_about()


def render_sidebar() -> None:
    """
    Render sidebar controls and trigger PCAP analysis.
    """
    st.sidebar.header("PCAP analysis")

    uploaded_file = st.sidebar.file_uploader(
        "Upload PCAP / PCAPNG",
        type=["pcap", "pcapng"],
        help="Upload a packet capture generated during the project or a new test capture.",
    )

    st.sidebar.markdown("### Visualization options")
    use_log_bytes = st.sidebar.checkbox(
        "Use logarithmic byte scale",
        value=True,
        help="Useful when normal transfers and scan traffic have very different byte volumes.",
    )
    st.session_state["use_log_bytes"] = use_log_bytes

    analyze_clicked = st.sidebar.button(
        "Analizar",
        type="primary",
        use_container_width=True,
        disabled=uploaded_file is None,
    )

    st.sidebar.divider()
    st.sidebar.markdown("### Day 3 scope")
    st.sidebar.markdown(
        """
        - End-to-end PCAP demo
        - Progress bar
        - Long-analysis UX
        - Invalid PCAP handling
        - Demo-ready dashboard
        """
    )

    if analyze_clicked and uploaded_file is not None:
        run_analysis(uploaded_file)


def run_analysis(uploaded_file) -> None:
    """
    Save the uploaded capture temporarily and run the prediction pipeline.

    Streamlit receives uploaded files as bytes, while the existing prediction
    pipeline expects a filesystem path. Therefore, the uploaded PCAP is first
    stored in a temporary file.

    Day 3 UX improvements:
    - Basic invalid PCAP/PCAPNG detection.
    - Spinner during analysis.
    - Progress bar for long-running analysis.
    - Runtime measurement.
    - Cleaner error messages for invalid captures.
    """
    suffix = Path(uploaded_file.name).suffix.lower()

    if suffix not in {".pcap", ".pcapng"}:
        st.error("Invalid file type. Upload a .pcap or .pcapng file.")
        return

    uploaded_bytes = bytes(uploaded_file.getbuffer())

    if not looks_like_packet_capture(uploaded_bytes):
        st.error(
            "Invalid PCAP/PCAPNG file. The uploaded file does not contain a valid packet capture header."
        )
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
        tmp_file.write(uploaded_bytes)
        tmp_path = Path(tmp_file.name)

    progress_bar = st.progress(0, text="Preparing PCAP analysis...")
    start_time = time.perf_counter()

    try:
        with st.spinner("Analyzing PCAP with the trained Random Forest model..."):
            progress_bar.progress(15, text="PCAP uploaded and stored temporarily.")
            progress_bar.progress(35, text="Running flow extraction and feature engineering...")

            predictions_df = analyze_pcap_for_dashboard(tmp_path)

            progress_bar.progress(85, text="Preparing dashboard visualizations...")

        elapsed_seconds = time.perf_counter() - start_time

        st.session_state["predictions_df"] = predictions_df
        st.session_state["uploaded_filename"] = uploaded_file.name
        st.session_state["analysis_time_seconds"] = elapsed_seconds

        progress_bar.progress(100, text="Analysis completed.")

        if elapsed_seconds > 10:
            st.info(
                f"Analysis took {elapsed_seconds:.2f} seconds. "
                "Large PCAP files require more time because flow extraction and manual features "
                "must be computed before prediction."
            )

        st.success(f"Analysis completed: {uploaded_file.name} in {elapsed_seconds:.2f} seconds.")

    except Exception as exc:
        progress_bar.empty()
        st.error(
            "The uploaded file could not be analyzed. "
            "Please verify that it is a valid PCAP/PCAPNG capture and not a corrupted file."
        )

        with st.expander("Technical error details"):
            st.exception(exc)


def looks_like_packet_capture(file_bytes: bytes) -> bool:
    """
    Perform a lightweight PCAP/PCAPNG header validation.

    Args:
        file_bytes: Uploaded file content.

    Returns:
        True if the file starts with a known PCAP or PCAPNG magic number.
    """
    if len(file_bytes) < 4:
        return False

    magic = file_bytes[:4]

    pcap_magic_numbers = {
        b"\xa1\xb2\xc3\xd4",
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x4d\x3c\xb2\xa1",
    }

    pcapng_magic_number = b"\x0a\x0d\x0d\x0a"

    return magic in pcap_magic_numbers or magic == pcapng_magic_number


def render_empty_state() -> None:
    """
    Render initial dashboard instructions.
    """
    st.info("Upload a PCAP file from the sidebar and click **Analizar**.")

    st.markdown(
        """
        ### Expected result

        Once a PCAP is analyzed, this dashboard will display:

        - Total reconstructed flows.
        - Number of normal and anomalous flows.
        - Mean prediction confidence.
        - Analysis time.
        - Class distribution bar chart.
        - Bytes vs duration scatter plot.
        - Flow timeline.
        - Class-filterable flow table.
        """
    )


def compute_dashboard_metrics(df: pd.DataFrame) -> dict[str, object]:
    """
    Compute the main dashboard metrics.

    Args:
        df: Prediction DataFrame normalized by src.dashboard_adapter.

    Returns:
        Dictionary with dashboard-level metrics.
    """
    total_flows = len(df)
    anomalous_flows = int(df["dashboard_is_anomaly"].sum())
    normal_flows = total_flows - anomalous_flows

    attack_series = df.loc[df["dashboard_is_anomaly"], "dashboard_prediction"]

    if attack_series.empty:
        most_frequent_attack = "None"
    else:
        most_frequent_attack = str(attack_series.value_counts().idxmax())

    confidence = pd.to_numeric(df["dashboard_confidence_pct"], errors="coerce")
    mean_confidence = float(confidence.mean()) if not confidence.dropna().empty else np.nan

    return {
        "total_flows": total_flows,
        "normal_flows": normal_flows,
        "anomalous_flows": anomalous_flows,
        "most_frequent_attack": most_frequent_attack,
        "mean_confidence": mean_confidence,
    }


def render_metrics(df: pd.DataFrame) -> None:
    """
    Render summary metrics.

    Day 2 added mean confidence to distinguish hard predictions from probabilistic
    model confidence.

    Day 3 adds analysis time to support the final end-to-end demo.
    """
    metrics = compute_dashboard_metrics(df)
    analysis_time = st.session_state.get("analysis_time_seconds")

    col1, col2, col3, col4, col5, col6 = st.columns(6)

    col1.metric("Total flows", f"{metrics['total_flows']:,}")
    col2.metric("Normal flows", f"{metrics['normal_flows']:,}")
    col3.metric("Anomalous flows", f"{metrics['anomalous_flows']:,}")
    col4.metric("Most frequent attack", str(metrics["most_frequent_attack"]))

    mean_confidence = metrics["mean_confidence"]
    if pd.isna(mean_confidence):
        col5.metric("Mean confidence", "N/A")
    else:
        col5.metric("Mean confidence", f"{mean_confidence:.2f}%")

    if analysis_time is None:
        col6.metric("Analysis time", "N/A")
    else:
        col6.metric("Analysis time", f"{analysis_time:.2f}s")


def render_anomaly_alert(df: pd.DataFrame) -> None:
    """
    Render an alert banner when anomalous flows are detected.
    """
    anomalous_df = df[df["dashboard_is_anomaly"]]

    if anomalous_df.empty:
        st.success("No anomalous flows detected in this PCAP.")
        return

    attack_counts = anomalous_df["dashboard_prediction"].value_counts()
    top_attacks = ", ".join(
        f"{label}: {count}" for label, count in attack_counts.head(5).items()
    )

    st.error(
        f"🚨 Anomalous traffic detected: {len(anomalous_df):,} anomalous flows. "
        f"Breakdown: {top_attacks}."
    )


def build_chart_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build a stable plotting DataFrame from the prediction output.

    Args:
        df: Prediction DataFrame normalized by src.dashboard_adapter.

    Returns:
        DataFrame with normalized columns for visualizations.
    """
    chart_df = df.copy()

    duration_col = first_existing_column(chart_df, DURATION_ALIASES)
    bytes_col = first_existing_column(chart_df, BYTES_ALIASES)
    packets_col = first_existing_column(chart_df, PACKETS_ALIASES)
    start_time_col = first_existing_column(chart_df, START_TIME_ALIASES)
    src_ip_col = first_existing_column(chart_df, SRC_IP_ALIASES)
    dst_ip_col = first_existing_column(chart_df, DST_IP_ALIASES)
    src_port_col = first_existing_column(chart_df, SRC_PORT_ALIASES)
    dst_port_col = first_existing_column(chart_df, DST_PORT_ALIASES)

    chart_df["predicted_class"] = chart_df["dashboard_prediction"].astype(str)
    chart_df["confidence_pct"] = pd.to_numeric(
        chart_df["dashboard_confidence_pct"],
        errors="coerce",
    )

    chart_df["duration_ms"] = (
        pd.to_numeric(chart_df[duration_col], errors="coerce")
        if duration_col is not None
        else np.nan
    )
    chart_df["bytes"] = (
        pd.to_numeric(chart_df[bytes_col], errors="coerce")
        if bytes_col is not None
        else np.nan
    )
    chart_df["packets"] = (
        pd.to_numeric(chart_df[packets_col], errors="coerce")
        if packets_col is not None
        else np.nan
    )

    if start_time_col is not None:
        start_raw = pd.to_numeric(chart_df[start_time_col], errors="coerce")
        min_start = start_raw.min()
        chart_df["start_time_s"] = (start_raw - min_start) / 1000.0
    else:
        chart_df["start_time_s"] = np.arange(len(chart_df), dtype=float)

    chart_df["flow_index"] = np.arange(len(chart_df), dtype=int)

    chart_df["src_ip_display"] = (
        chart_df[src_ip_col].astype(str) if src_ip_col is not None else "N/A"
    )
    chart_df["dst_ip_display"] = (
        chart_df[dst_ip_col].astype(str) if dst_ip_col is not None else "N/A"
    )
    chart_df["src_port_display"] = (
        chart_df[src_port_col].astype(str) if src_port_col is not None else "N/A"
    )
    chart_df["dst_port_display"] = (
        chart_df[dst_port_col].astype(str) if dst_port_col is not None else "N/A"
    )

    return chart_df


def render_visualizations(df: pd.DataFrame) -> None:
    """
    Render the interactive visualizations.
    """
    st.subheader("Interactive visualizations")

    chart_df = build_chart_dataframe(df)

    render_class_distribution_chart(chart_df)

    left_col, right_col = st.columns(2)
    with left_col:
        render_bytes_duration_scatter(chart_df)
    with right_col:
        render_flow_timeline(chart_df)


def render_class_distribution_chart(chart_df: pd.DataFrame) -> None:
    """
    Render a Plotly bar chart with predicted class distribution.
    """
    class_counts = (
        chart_df["predicted_class"]
        .value_counts()
        .rename_axis("predicted_class")
        .reset_index(name="flows")
    )

    fig = px.bar(
        class_counts,
        x="predicted_class",
        y="flows",
        text="flows",
        title="Detected class distribution",
        labels={
            "predicted_class": "Predicted class",
            "flows": "Number of flows",
        },
    )

    fig.update_traces(textposition="outside")
    fig.update_layout(
        xaxis_title="Predicted class",
        yaxis_title="Number of flows",
        showlegend=False,
    )

    st.plotly_chart(fig, use_container_width=True)


def render_bytes_duration_scatter(chart_df: pd.DataFrame) -> None:
    """
    Render a bytes vs duration scatter plot colored by predicted class.

    This is the most important visual explanation for the technical report,
    because it shows whether the model separates traffic behaviors in the
    feature space.
    """
    scatter_df = chart_df.dropna(subset=["duration_ms", "bytes"]).copy()

    if scatter_df.empty:
        st.warning("Scatter plot cannot be rendered because duration or bytes are missing.")
        return

    fig = px.scatter(
        scatter_df,
        x="duration_ms",
        y="bytes",
        color="predicted_class",
        title="Bytes vs duration by predicted class",
        labels={
            "duration_ms": "Flow duration (ms)",
            "bytes": "Flow bytes",
            "predicted_class": "Predicted class",
            "confidence_pct": "Confidence (%)",
        },
        hover_data={
            "src_ip_display": True,
            "dst_ip_display": True,
            "src_port_display": True,
            "dst_port_display": True,
            "packets": True,
            "confidence_pct": ":.2f",
            "flow_index": True,
        },
    )

    if st.session_state.get("use_log_bytes", True):
        fig.update_yaxes(type="log")

    fig.update_layout(
        xaxis_title="Duration (ms)",
        yaxis_title="Bytes",
        legend_title="Predicted class",
    )

    st.plotly_chart(fig, use_container_width=True)


def render_flow_timeline(chart_df: pd.DataFrame) -> None:
    """
    Render a flow timeline ordered by relative start time.
    """
    timeline_df = chart_df.dropna(subset=["start_time_s"]).copy()
    timeline_df = timeline_df.sort_values("start_time_s")

    if timeline_df.empty:
        st.warning("Timeline cannot be rendered because timestamp data is missing.")
        return

    fig = px.scatter(
        timeline_df,
        x="start_time_s",
        y="flow_index",
        color="predicted_class",
        title="Flow timeline by predicted class",
        labels={
            "start_time_s": "Relative capture time (s)",
            "flow_index": "Flow index",
            "predicted_class": "Predicted class",
            "confidence_pct": "Confidence (%)",
        },
        hover_data={
            "src_ip_display": True,
            "dst_ip_display": True,
            "src_port_display": True,
            "dst_port_display": True,
            "duration_ms": True,
            "bytes": True,
            "confidence_pct": ":.2f",
        },
    )

    fig.update_layout(
        xaxis_title="Relative capture time (s)",
        yaxis_title="Flow index",
        legend_title="Predicted class",
    )

    st.plotly_chart(fig, use_container_width=True)


def render_filtered_table(df: pd.DataFrame) -> None:
    """
    Render a class-filterable flow table.
    """
    st.subheader("Classified flows")

    available_classes = sorted(df["dashboard_prediction"].dropna().unique().tolist())

    selected_classes = st.multiselect(
        "Filter by predicted class",
        options=available_classes,
        default=available_classes,
        help="Example: select only syn_scan to inspect scan flows.",
    )

    if not selected_classes:
        st.warning("Select at least one class to display flows.")
        return

    filtered_df = df[df["dashboard_prediction"].isin(selected_classes)].copy()
    flow_table = build_flow_table(filtered_df)

    st.caption(f"Showing {len(filtered_df):,} of {len(df):,} flows.")

    if "confidence (%)" in flow_table.columns:
        try:
            styled_table = flow_table.style.map(
                style_confidence_cell,
                subset=["confidence (%)"],
            )
            st.dataframe(
                styled_table,
                use_container_width=True,
                hide_index=True,
            )
        except Exception:
            st.dataframe(
                flow_table,
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.dataframe(
            flow_table,
            use_container_width=True,
            hide_index=True,
        )

    with st.expander("Raw prediction output"):
        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
        )


def style_confidence_cell(value: object) -> str:
    """
    Color confidence cells using intuitive thresholds.

    Green: confidence >= 80%.
    Yellow: 60% <= confidence < 80%.
    Red: confidence < 60%.
    """
    try:
        numeric_value = float(value)
    except (TypeError, ValueError):
        return ""

    if numeric_value >= 80:
        return "background-color: #d1fae5; color: #065f46"
    if numeric_value >= 60:
        return "background-color: #fef3c7; color: #92400e"
    return "background-color: #fee2e2; color: #991b1b"


def render_about() -> None:
    """
    Render the About section required for the dashboard.
    """
    with st.expander("About NetFlow Analyzer"):
        st.markdown(
            f"""
            ### What this dashboard does

            NetFlow Analyzer classifies network flows from uploaded PCAP files using
            Layer 3 and Layer 4 features only. It does **not** inspect packet payloads.

            ### Processing pipeline

            1. The user uploads a PCAP or PCAPNG file.
            2. The existing prediction pipeline normalizes the capture for NFStream.
            3. Flow-level features are extracted.
            4. The same feature schema used during training is applied.
            5. Features are scaled with the saved scaler.
            6. The optimized Random Forest model predicts the traffic class.
            7. The dashboard visualizes predictions and anomalies.

            ### Main features used

            - Flow duration.
            - Bidirectional bytes and packets.
            - Bytes per packet.
            - Packets per millisecond.
            - TCP flag counts.
            - SYN/ACK ratio.
            - Inter-arrival time statistics.
            - Estimated RTT.
            - TCP window size statistics.

            ### Model

            - Classifier: optimized Random Forest.
            - Model artifact: `models/rf_optimized.pkl`.
            - Scaler artifact: `models/scaler.pkl`.
            - Label encoder: `models/label_encoder.pkl`.
            - Feature schema: `models/feature_columns.json`.

            ### Anomaly rule

            A flow is flagged as anomalous when:

            `P(normal) < {DEFAULT_NORMAL_THRESHOLD}`

            This means the dashboard uses not only the predicted class, but also
            the model probability assigned to the normal class.
            """
        )


if __name__ == "__main__":
    main()

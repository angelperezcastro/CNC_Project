"""
Streamlit dashboard for NetFlow Analyzer.

Week 4 Day 1 scope:
- Upload a PCAP/PCAPNG file.
- Run the existing prediction pipeline from src.predict.
- Show four summary metrics.
- Show a table of classified flows.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from src.dashboard_adapter import analyze_pcap_for_dashboard, build_flow_table


st.set_page_config(
    page_title="NetFlow Analyzer",
    page_icon="🛡️",
    layout="wide",
)


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
        return

    predictions_df = st.session_state["predictions_df"]
    render_metrics(predictions_df)
    render_table(predictions_df)


def render_sidebar() -> None:
    """
    Render sidebar controls and trigger PCAP analysis.
    """
    st.sidebar.header("PCAP analysis")

    uploaded_file = st.sidebar.file_uploader(
        "Upload PCAP / PCAPNG",
        type=["pcap", "pcapng"],
    )

    analyze_clicked = st.sidebar.button(
        "Analizar",
        type="primary",
        use_container_width=True,
        disabled=uploaded_file is None,
    )

    st.sidebar.divider()
    st.sidebar.markdown("### Day 1 scope")
    st.sidebar.markdown(
        """
        - Upload PCAP
        - Run trained prediction pipeline
        - Show summary metrics
        - Show classified flow table
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
    """
    suffix = Path(uploaded_file.name).suffix.lower()

    if suffix not in {".pcap", ".pcapng"}:
        st.error("Invalid file type. Upload a .pcap or .pcapng file.")
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
        tmp_file.write(uploaded_file.getbuffer())
        tmp_path = Path(tmp_file.name)

    try:
        with st.spinner("Analyzing PCAP with the trained Random Forest model..."):
            predictions_df = analyze_pcap_for_dashboard(tmp_path)

        st.session_state["predictions_df"] = predictions_df
        st.session_state["uploaded_filename"] = uploaded_file.name

        st.success(f"Analysis completed: {uploaded_file.name}")

    except Exception as exc:
        st.error("The PCAP could not be analyzed.")
        st.exception(exc)


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
        - Number of normal flows.
        - Number of anomalous flows.
        - Most frequent attack class.
        - Flow-level classification table.
        """
    )


def render_metrics(df: pd.DataFrame) -> None:
    """
    Render the four required metrics for Week 4 Day 1.
    """
    total_flows = len(df)
    anomalous_flows = int(df["dashboard_is_anomaly"].sum())
    normal_flows = total_flows - anomalous_flows

    attack_series = df.loc[df["dashboard_is_anomaly"], "dashboard_prediction"]

    if attack_series.empty:
        most_frequent_attack = "None"
    else:
        most_frequent_attack = str(attack_series.value_counts().idxmax())

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total flows", f"{total_flows:,}")
    col2.metric("Normal flows", f"{normal_flows:,}")
    col3.metric("Anomalous flows", f"{anomalous_flows:,}")
    col4.metric("Most frequent attack", most_frequent_attack)

    if anomalous_flows > 0:
        st.warning(
            f"{anomalous_flows} anomalous flows detected. "
            f"Most frequent attack class: {most_frequent_attack}."
        )
    else:
        st.success("No anomalous flows detected.")


def render_table(df: pd.DataFrame) -> None:
    """
    Render the classified flow table.
    """
    st.subheader("Classified flows")

    flow_table = build_flow_table(df)

    st.dataframe(
        flow_table,
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("Raw prediction output"):
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )


if __name__ == "__main__":
    main()

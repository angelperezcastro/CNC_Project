"""
Dashboard adapter for NetFlow Analyzer.

This module connects the Streamlit UI with the existing Week 3 prediction
pipeline implemented in src.predict.predict_pcap().

The dashboard does not duplicate feature extraction, scaling, model loading or
prediction logic. It only passes the correct parameters to the existing pipeline
and adapts the output for visualization.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.predict import (
    predict_pcap,
    DEFAULT_MODEL_PATH,
    DEFAULT_SCALER_PATH,
    DEFAULT_LABEL_ENCODER_PATH,
    DEFAULT_FEATURE_COLUMNS_PATH,
    DEFAULT_CLEANING_REPORT_PATH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_NORMAL_THRESHOLD,
)


PREDICTION_ALIASES = (
    "predicted_class",
    "predicted_label",
    "prediction",
    "class_prediction",
    "label_pred",
    "class",
)

CONFIDENCE_ALIASES = (
    "confidence",
    "confidence_pct",
    "prediction_confidence",
    "predicted_probability",
    "max_probability",
    "probability",
)

NORMAL_PROBABILITY_ALIASES = (
    "normal_probability",
    "prob_normal",
    "p_normal",
    "normal_proba",
)

ANOMALY_ALIASES = (
    "is_anomaly",
    "anomaly",
    "anomalous",
)

SRC_IP_ALIASES = ("src_ip", "source_ip", "src_addr", "src")
DST_IP_ALIASES = ("dst_ip", "destination_ip", "dst_addr", "dst")
SRC_PORT_ALIASES = ("src_port", "source_port", "sport")
DST_PORT_ALIASES = ("dst_port", "destination_port", "dport")
DURATION_ALIASES = ("duration_ms", "bidirectional_duration_ms", "flow_duration_ms")
BYTES_ALIASES = ("bytes", "bidirectional_bytes", "total_bytes")
PACKETS_ALIASES = ("packets", "bidirectional_packets", "total_packets")


def analyze_pcap_for_dashboard(
    pcap_path: str | Path,
    normalize_pcap: bool = True,
    max_packets: int | None = None,
    max_packets_per_flow: int | None = None,
) -> pd.DataFrame:
    """
    Run the existing prediction pipeline and normalize its output for Streamlit.

    Args:
        pcap_path: Path to the uploaded PCAP/PCAPNG file.
        normalize_pcap: Whether to normalize the PCAP before NFStream processing.
        max_packets: Optional global packet limit for faster testing.
        max_packets_per_flow: Optional packet limit per flow.

    Returns:
        DataFrame with dashboard helper columns:
        - dashboard_prediction
        - dashboard_confidence_pct
        - dashboard_is_anomaly
    """
    raw_df = run_existing_prediction_pipeline(
        pcap_path=Path(pcap_path),
        normalize_pcap=normalize_pcap,
        max_packets=max_packets,
        max_packets_per_flow=max_packets_per_flow,
    )
    return normalize_prediction_output(raw_df)


def run_existing_prediction_pipeline(
    pcap_path: Path,
    normalize_pcap: bool,
    max_packets: int | None,
    max_packets_per_flow: int | None,
) -> pd.DataFrame:
    """
    Execute src.predict.predict_pcap() with the project's default model artifacts.

    Args:
        pcap_path: PCAP file path.
        normalize_pcap: Whether to normalize the PCAP for NFStream compatibility.
        max_packets: Optional packet limit.
        max_packets_per_flow: Optional packet limit per flow.

    Returns:
        Prediction DataFrame.
    """
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_stem = pcap_path.stem.replace(" ", "_")
    output_path = DEFAULT_OUTPUT_DIR / f"{safe_stem}_dashboard_{timestamp}.csv"

    result = predict_pcap(
        pcap_path=pcap_path,
        model_path=DEFAULT_MODEL_PATH,
        scaler_path=DEFAULT_SCALER_PATH,
        label_encoder_path=DEFAULT_LABEL_ENCODER_PATH,
        feature_columns_path=DEFAULT_FEATURE_COLUMNS_PATH,
        cleaning_report_path=DEFAULT_CLEANING_REPORT_PATH,
        output_path=output_path,
        normal_threshold=DEFAULT_NORMAL_THRESHOLD,
        max_packets=max_packets,
        max_packets_per_flow=max_packets_per_flow,
        normalize_pcap=normalize_pcap,
    )

    try:
        return coerce_prediction_result_to_dataframe(result)
    except Exception:
        if output_path.exists():
            return pd.read_csv(output_path)
        raise


def coerce_prediction_result_to_dataframe(result: Any) -> pd.DataFrame:
    """
    Convert the return value from predict_pcap() into a DataFrame.

    Args:
        result: Object returned by predict_pcap().

    Returns:
        Prediction DataFrame.
    """
    if isinstance(result, pd.DataFrame):
        return result

    if isinstance(result, (str, Path)):
        path = Path(result)
        if path.exists() and path.suffix.lower() == ".csv":
            return pd.read_csv(path)

    if isinstance(result, tuple):
        for item in result:
            try:
                return coerce_prediction_result_to_dataframe(item)
            except Exception:
                continue

    if isinstance(result, list):
        return pd.DataFrame(result)

    if isinstance(result, dict):
        return pd.DataFrame(result)

    raise TypeError(f"Unsupported predict_pcap() return type: {type(result)}")


def normalize_prediction_output(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add stable dashboard columns independently of the exact prediction CSV names.

    Args:
        df: Raw prediction DataFrame.

    Returns:
        Normalized DataFrame ready for Streamlit.
    """
    if df.empty:
        raise ValueError("The prediction output is empty.")

    output = df.copy()

    prediction_col = first_existing_column(output, PREDICTION_ALIASES)
    if prediction_col is None:
        raise ValueError(
            "No prediction column found. "
            f"Available columns: {list(output.columns)}"
        )

    output["dashboard_prediction"] = output[prediction_col].astype(str)

    confidence_col = first_existing_column(output, CONFIDENCE_ALIASES)
    if confidence_col is None:
        output["dashboard_confidence_pct"] = np.nan
    else:
        confidence = pd.to_numeric(output[confidence_col], errors="coerce")
        if not confidence.dropna().empty and confidence.dropna().between(0, 1).all():
            confidence = confidence * 100
        output["dashboard_confidence_pct"] = confidence

    anomaly_col = first_existing_column(output, ANOMALY_ALIASES)
    normal_probability_col = first_existing_column(output, NORMAL_PROBABILITY_ALIASES)

    if anomaly_col is not None:
        output["dashboard_is_anomaly"] = output[anomaly_col].astype(bool)
    elif normal_probability_col is not None:
        normal_probability = pd.to_numeric(
            output[normal_probability_col],
            errors="coerce",
        )
        output["dashboard_is_anomaly"] = normal_probability < DEFAULT_NORMAL_THRESHOLD
    else:
        output["dashboard_is_anomaly"] = (
            output["dashboard_prediction"].str.lower() != "normal"
        )

    return output


def build_flow_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build the compact flow table required for Week 4 Day 1.

    Args:
        df: Normalized prediction DataFrame.

    Returns:
        Display DataFrame with flow identifiers, prediction and confidence.
    """
    table = pd.DataFrame()

    add_column_if_exists(table, df, "src_ip", SRC_IP_ALIASES)
    add_column_if_exists(table, df, "dst_ip", DST_IP_ALIASES)
    add_column_if_exists(table, df, "src_port", SRC_PORT_ALIASES)
    add_column_if_exists(table, df, "dst_port", DST_PORT_ALIASES)
    add_column_if_exists(table, df, "duration_ms", DURATION_ALIASES)
    add_column_if_exists(table, df, "bytes", BYTES_ALIASES)
    add_column_if_exists(table, df, "packets", PACKETS_ALIASES)

    table["prediction"] = df["dashboard_prediction"]
    table["confidence (%)"] = df["dashboard_confidence_pct"].round(2)
    table["is_anomaly"] = df["dashboard_is_anomaly"]

    return table


def add_column_if_exists(
    target: pd.DataFrame,
    source: pd.DataFrame,
    output_name: str,
    aliases: tuple[str, ...],
) -> None:
    """
    Add a column to the display table if any alias exists in the source DataFrame.
    """
    source_col = first_existing_column(source, aliases)

    if source_col is not None:
        target[output_name] = source[source_col]


def first_existing_column(df: pd.DataFrame, aliases: tuple[str, ...]) -> str | None:
    """
    Return the first existing column using case-insensitive matching.
    """
    lower_to_original = {str(col).lower(): col for col in df.columns}

    for alias in aliases:
        if alias.lower() in lower_to_original:
            return lower_to_original[alias.lower()]

    return None

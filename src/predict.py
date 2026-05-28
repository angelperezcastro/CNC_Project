"""
Prediction CLI for the NetFlow Analyzer project.

This script receives a new PCAP file, normalizes it when needed for NFStream,
extracts flow-level L3/L4 features using src.pipeline.process_pcap(), applies
the same feature schema and scaler used during training, loads the optimized
Random Forest model, and outputs a CSV with flow-level predictions.

Example:
    python src/predict.py data/test/mixed_day5.pcap

Anomaly rule:
    A flow is flagged as anomalous when P(normal) < 0.4.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import process_pcap  # noqa: E402
from src.normalize_pcaps_for_nfstream import normalize_pcap_for_nfstream  # noqa: E402


DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "rf_optimized.pkl"
DEFAULT_SCALER_PATH = PROJECT_ROOT / "models" / "scaler.pkl"
DEFAULT_LABEL_ENCODER_PATH = PROJECT_ROOT / "models" / "label_encoder.pkl"
DEFAULT_FEATURE_COLUMNS_PATH = PROJECT_ROOT / "models" / "feature_columns.json"
DEFAULT_CLEANING_REPORT_PATH = PROJECT_ROOT / "data" / "processed" / "cleaning_report.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "reports" / "predictions"
DEFAULT_NORMALIZED_PCAP_DIR = PROJECT_ROOT / "data" / "test" / "normalized"

NORMAL_LABEL = "normal"
DEFAULT_NORMAL_THRESHOLD = 0.4


def load_feature_columns(path: Path) -> list[str]:
    """
    Load the ordered list of feature columns used during model training.

    Args:
        path: JSON file containing the feature names.

    Returns:
        Ordered list of feature names.

    Raises:
        FileNotFoundError: If the feature file does not exist.
        ValueError: If the JSON content is not a list.
    """
    if not path.exists():
        raise FileNotFoundError(f"Feature columns file not found: {path}")

    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, list):
        raise ValueError(f"Expected list in {path}, got {type(data)}")

    return [str(col) for col in data]


def load_cleaning_report(path: Path) -> dict[str, Any]:
    """
    Load the cleaning report generated during dataset preparation.

    Args:
        path: Path to cleaning_report.json.

    Returns:
        Cleaning report dictionary. Empty dict if the file does not exist.
    """
    if not path.exists():
        print(f"[WARN] Cleaning report not found: {path}")
        return {}

    return json.loads(path.read_text(encoding="utf-8"))


def load_scaler_object(path: Path):
    """
    Load the fitted scaler from disk.

    The project stores models/scaler.pkl as a dictionary with this structure:

        {
            "scaler": StandardScaler(...),
            "feature_columns": [...]
        }

    This function extracts the actual scaler object so prediction can call
    scaler.transform(X).

    Args:
        path: Path to models/scaler.pkl.

    Returns:
        Fitted scaler object with a .transform() method.

    Raises:
        FileNotFoundError: If the scaler file does not exist.
        TypeError: If no valid scaler object can be found.
    """
    if not path.exists():
        raise FileNotFoundError(f"Scaler file not found: {path}")

    obj = joblib.load(path)

    if hasattr(obj, "transform"):
        return obj

    if isinstance(obj, dict):
        print(f"[INFO] scaler.pkl is a dict with keys: {list(obj.keys())}")

        if "scaler" in obj and hasattr(obj["scaler"], "transform"):
            print("[INFO] Using scaler stored under key: 'scaler'")
            return obj["scaler"]

        for key, value in obj.items():
            if hasattr(value, "transform"):
                print(f"[INFO] Using scaler stored under key: '{key}'")
                return value

        raise TypeError(
            "models/scaler.pkl is a dict, but it does not contain a valid scaler "
            f"object with .transform(). Available keys: {list(obj.keys())}"
        )

    raise TypeError(
        f"Unsupported scaler object type: {type(obj)}. "
        "Expected StandardScaler or dict containing a scaler."
    )


def collect_imputation_rules(cleaning_report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Collect imputation rules recursively from the cleaning report.

    During Week 2, missing-value metadata was stored with fields such as
    `imputation_value` and `indicator_column`. This function searches the full
    cleaning report recursively so it remains robust even if the exact section
    name changes.

    Args:
        cleaning_report: Parsed cleaning report.

    Returns:
        Dict mapping original feature name to imputation metadata.
    """
    rules: dict[str, dict[str, Any]] = {}

    def walk(obj: Any, parent_key: str | None = None) -> None:
        if isinstance(obj, dict):
            if "imputation_value" in obj or "indicator_column" in obj:
                if parent_key is not None:
                    rules[parent_key] = obj
                return

            for key, value in obj.items():
                walk(value, str(key))

        elif isinstance(obj, list):
            for item in obj:
                walk(item, parent_key)

    walk(cleaning_report)
    return rules


def normalize_protocol_column(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensure the protocol column is numeric.

    NFStream/pipeline outputs may represent protocol either as a number or as a
    string label. The training dataset uses a numeric protocol feature, so this
    function maps common protocol names to their IP protocol numbers.

    Args:
        df: Flow DataFrame.

    Returns:
        DataFrame with numeric protocol column when present.
    """
    df = df.copy()

    if "protocol" not in df.columns:
        return df

    protocol_map = {
        "icmp": 1,
        "tcp": 6,
        "udp": 17,
        "1": 1,
        "6": 6,
        "17": 17,
    }

    protocol_series = df["protocol"]

    if protocol_series.dtype == object:
        mapped = protocol_series.astype(str).str.lower().map(protocol_map)
        numeric = pd.to_numeric(protocol_series, errors="coerce")
        df["protocol"] = mapped.fillna(numeric)
    else:
        df["protocol"] = pd.to_numeric(protocol_series, errors="coerce")

    return df


def add_prediction_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add derived features required by the trained model at prediction time.

    Some features used during training were created during dataset preparation,
    not directly by NFStream. When predicting on a new PCAP, they must be
    reconstructed before aligning the feature schema.

    Args:
        df: Raw flow DataFrame returned by src.pipeline.process_pcap().

    Returns:
        DataFrame with additional derived features when possible.
    """
    df = df.copy()
    df = normalize_protocol_column(df)

    eps = 1e-9

    if (
        "duration_zero_flag" not in df.columns
        and "bidirectional_duration_ms" in df.columns
    ):
        duration = pd.to_numeric(df["bidirectional_duration_ms"], errors="coerce")
        df["duration_zero_flag"] = (duration <= 0).astype(int)

    if (
        "bytes_per_packet" not in df.columns
        and "bidirectional_bytes" in df.columns
        and "bidirectional_packets" in df.columns
    ):
        bytes_total = pd.to_numeric(df["bidirectional_bytes"], errors="coerce")
        packets_total = pd.to_numeric(df["bidirectional_packets"], errors="coerce")
        df["bytes_per_packet"] = bytes_total / (packets_total + eps)

    if (
        "bidirectional_packets_per_ms" not in df.columns
        and "bidirectional_packets" in df.columns
        and "bidirectional_duration_ms" in df.columns
    ):
        packets_total = pd.to_numeric(df["bidirectional_packets"], errors="coerce")
        duration_ms = pd.to_numeric(df["bidirectional_duration_ms"], errors="coerce")
        df["bidirectional_packets_per_ms"] = packets_total / (duration_ms + eps)

    if (
        "bytes_asymmetry_ratio" not in df.columns
        and "src2dst_bytes" in df.columns
        and "dst2src_bytes" in df.columns
    ):
        src_bytes = pd.to_numeric(df["src2dst_bytes"], errors="coerce")
        dst_bytes = pd.to_numeric(df["dst2src_bytes"], errors="coerce")
        df["bytes_asymmetry_ratio"] = (src_bytes - dst_bytes).abs() / (
            src_bytes + dst_bytes + eps
        )

    if (
        "packets_asymmetry_ratio" not in df.columns
        and "src2dst_packets" in df.columns
        and "dst2src_packets" in df.columns
    ):
        src_packets = pd.to_numeric(df["src2dst_packets"], errors="coerce")
        dst_packets = pd.to_numeric(df["dst2src_packets"], errors="coerce")
        df["packets_asymmetry_ratio"] = (src_packets - dst_packets).abs() / (
            src_packets + dst_packets + eps
        )

    return df


def add_missing_indicators_and_impute(
    df: pd.DataFrame,
    feature_columns: list[str],
    cleaning_report: dict[str, Any],
) -> pd.DataFrame:
    """
    Apply prediction-time missing indicators and imputation.

    This mirrors the idea used during dataset preparation: if a feature had
    missing values during training, an additional *_missing indicator can be
    used as an informative L3/L4 signal.

    Args:
        df: Raw flow DataFrame from process_pcap().
        feature_columns: Final feature schema expected by the model.
        cleaning_report: Cleaning metadata from training.

    Returns:
        DataFrame with missing indicators and imputed values where possible.
    """
    df = df.copy()
    imputation_rules = collect_imputation_rules(cleaning_report)

    for raw_feature, metadata in imputation_rules.items():
        indicator_col = metadata.get("indicator_column")
        imputation_value = metadata.get("imputation_value")

        if indicator_col and indicator_col in feature_columns:
            if raw_feature in df.columns:
                df[indicator_col] = df[raw_feature].isna().astype(int)
            elif indicator_col not in df.columns:
                df[indicator_col] = 1

        if raw_feature in df.columns and imputation_value is not None:
            df[raw_feature] = pd.to_numeric(df[raw_feature], errors="coerce")
            df[raw_feature] = df[raw_feature].fillna(imputation_value)

    for col in feature_columns:
        if col.endswith("_missing") and col not in df.columns:
            base_col = col.removesuffix("_missing")

            if base_col in df.columns:
                df[col] = df[base_col].isna().astype(int)
            else:
                df[col] = 1

    return df


def align_and_validate_features(
    flow_df: pd.DataFrame,
    feature_columns: list[str],
    cleaning_report: dict[str, Any],
) -> pd.DataFrame:
    """
    Align extracted features with the model training schema.

    Args:
        flow_df: Raw flow DataFrame extracted from the PCAP.
        feature_columns: Ordered feature list used by the trained model.
        cleaning_report: Cleaning report used for imputation metadata.

    Returns:
        DataFrame with exactly the expected feature columns.

    Raises:
        ValueError: If required columns are missing or invalid values remain.
    """
    prepared_df = add_prediction_derived_features(flow_df)

    prepared_df = add_missing_indicators_and_impute(
        df=prepared_df,
        feature_columns=feature_columns,
        cleaning_report=cleaning_report,
    )

    missing_columns = [col for col in feature_columns if col not in prepared_df.columns]

    if missing_columns:
        raise ValueError(
            "Prediction features do not match training features. "
            f"Missing columns: {missing_columns}"
        )

    X = prepared_df[feature_columns].copy()
    X = X.apply(pd.to_numeric, errors="coerce")

    if np.isinf(X.to_numpy()).any():
        bad_cols = X.columns[np.isinf(X.to_numpy()).any(axis=0)].tolist()
        raise ValueError(f"Infinite values found in columns: {bad_cols}")

    if X.isna().any().any():
        bad_cols = X.columns[X.isna().any()].tolist()
        raise ValueError(
            "NaN values remain after prediction-time preprocessing. "
            f"Columns with NaN: {bad_cols}. "
            "This means the prediction preprocessing does not fully match training."
        )

    return X


def prepare_pcap_for_nfstream(pcap_path: Path, normalize: bool = True) -> Path:
    """
    Prepare a PCAP file for NFStream.

    Some captures generated inside Docker/WSL are stored as Linux cooked capture
    frames (SLL). Wireshark can read them, but NFStream may fail to extract
    flows from that link-layer format. To avoid prediction failures, this
    function creates a normalized copy before calling the feature pipeline.

    Args:
        pcap_path: Original PCAP path.
        normalize: Whether to normalize the PCAP before processing.

    Returns:
        Path to the PCAP that should be passed to NFStream.
    """
    if not normalize:
        return pcap_path

    DEFAULT_NORMALIZED_PCAP_DIR.mkdir(parents=True, exist_ok=True)

    normalized_path = DEFAULT_NORMALIZED_PCAP_DIR / f"{pcap_path.stem}_nfstream.pcap"

    print(f"[INFO] Normalizing PCAP for NFStream: {pcap_path} -> {normalized_path}")

    try:
        normalize_pcap_for_nfstream(pcap_path, normalized_path)
    except Exception as exc:
        raise RuntimeError(
            "Failed to normalize PCAP for NFStream. "
            "Check that tshark/editcap are installed and that the PCAP is readable."
        ) from exc

    if not normalized_path.exists() or normalized_path.stat().st_size == 0:
        raise RuntimeError(f"Normalized PCAP was not created correctly: {normalized_path}")

    return normalized_path


def build_prediction_table(
    flow_df: pd.DataFrame,
    y_pred: np.ndarray,
    probabilities: np.ndarray,
    class_names: np.ndarray,
    label_encoder,
    normal_threshold: float,
) -> pd.DataFrame:
    """
    Build a readable prediction table.

    Args:
        flow_df: Original extracted flow DataFrame.
        y_pred: Encoded predicted labels.
        probabilities: Class probability matrix.
        class_names: Class names in probability-column order.
        label_encoder: Fitted LabelEncoder.
        normal_threshold: Threshold for anomaly detection.

    Returns:
        DataFrame with predictions, probabilities and anomaly flag.
    """
    result_df = flow_df.copy()

    predicted_labels = label_encoder.inverse_transform(y_pred)
    confidence = probabilities.max(axis=1)

    if NORMAL_LABEL not in class_names:
        raise ValueError(f"Normal label '{NORMAL_LABEL}' not found in classes: {class_names}")

    normal_idx = list(class_names).index(NORMAL_LABEL)
    normal_probability = probabilities[:, normal_idx]

    result_df["predicted_class"] = predicted_labels
    result_df["confidence"] = confidence
    result_df["normal_probability"] = normal_probability
    result_df["is_anomaly"] = result_df["normal_probability"] < normal_threshold

    probability_df = pd.DataFrame(
        probabilities,
        columns=[f"proba_{class_name}" for class_name in class_names],
        index=result_df.index,
    )

    result_df = pd.concat([result_df, probability_df], axis=1)

    preferred_columns = [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "bidirectional_duration_ms",
        "bidirectional_packets",
        "bidirectional_bytes",
        "src2dst_bytes",
        "dst2src_bytes",
        "bidirectional_mean_ps",
        "iat_mean_ms",
        "duration_zero_flag",
        "bidirectional_syn_packets",
        "bidirectional_ack_packets",
        "bidirectional_rst_packets",
        "predicted_class",
        "confidence",
        "normal_probability",
        "is_anomaly",
    ]

    probability_columns = [f"proba_{class_name}" for class_name in class_names]

    first_columns = [
        col for col in preferred_columns + probability_columns
        if col in result_df.columns
    ]

    remaining_columns = [
        col for col in result_df.columns
        if col not in first_columns
    ]

    return result_df[first_columns + remaining_columns]


def predict_pcap(
    pcap_path: Path,
    model_path: Path,
    scaler_path: Path,
    label_encoder_path: Path,
    feature_columns_path: Path,
    cleaning_report_path: Path,
    output_path: Path,
    normal_threshold: float,
    max_packets: int | None,
    max_packets_per_flow: int | None,
    normalize_pcap: bool,
) -> pd.DataFrame:
    """
    Run the full PCAP prediction pipeline.

    Args:
        pcap_path: Input PCAP file.
        model_path: Trained Random Forest model.
        scaler_path: Fitted scaler.
        label_encoder_path: Fitted LabelEncoder.
        feature_columns_path: JSON with training feature columns.
        cleaning_report_path: JSON cleaning report from training.
        output_path: Output CSV file.
        normal_threshold: P(normal) threshold for anomaly flag.
        max_packets: Optional cap for packets read by Scapy.
        max_packets_per_flow: Optional cap for packets per flow.
        normalize_pcap: Whether to normalize the input PCAP before NFStream.

    Returns:
        Prediction DataFrame.
    """
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    print(f"[INFO] Loading model: {model_path}")
    model = joblib.load(model_path)

    print(f"[INFO] Loading scaler: {scaler_path}")
    scaler = load_scaler_object(scaler_path)

    print(f"[INFO] Loading label encoder: {label_encoder_path}")
    label_encoder = joblib.load(label_encoder_path)

    print(f"[INFO] Loading feature columns: {feature_columns_path}")
    feature_columns = load_feature_columns(feature_columns_path)

    print(f"[INFO] Loading cleaning report: {cleaning_report_path}")
    cleaning_report = load_cleaning_report(cleaning_report_path)

    pcap_for_pipeline = prepare_pcap_for_nfstream(
        pcap_path=pcap_path,
        normalize=normalize_pcap,
    )

    print(f"[INFO] Extracting flows with src.pipeline.process_pcap(): {pcap_for_pipeline}")

    try:
        flow_df = process_pcap(
            pcap_path=pcap_for_pipeline,
            label="unknown",
            n_meters=1,
            max_packets=max_packets,
            max_packets_per_flow=max_packets_per_flow,
        )
    except ValueError as exc:
        if "NFStream extracted no flows" in str(exc):
            raise RuntimeError(
                "No NFStream-compatible flows were extracted from this PCAP even "
                "after normalization. The capture may contain only unsupported "
                "traffic, or the normalization step did not produce an "
                "Ethernet/IP-compatible PCAP."
            ) from exc
        raise

    if flow_df.empty:
        raise ValueError(f"No flows extracted from PCAP: {pcap_for_pipeline}")

    print(f"[INFO] Extracted flows: {len(flow_df)}")

    X_raw = align_and_validate_features(
        flow_df=flow_df,
        feature_columns=feature_columns,
        cleaning_report=cleaning_report,
    )

    print("[INFO] Scaling features.")
    X_scaled_array = scaler.transform(X_raw)

    X_scaled = pd.DataFrame(
        X_scaled_array,
        columns=feature_columns,
        index=X_raw.index,
    )

    print("[INFO] Predicting classes.")
    y_pred = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)

    prediction_df = build_prediction_table(
        flow_df=flow_df,
        y_pred=y_pred,
        probabilities=probabilities,
        class_names=label_encoder.classes_,
        label_encoder=label_encoder,
        normal_threshold=normal_threshold,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    prediction_df.to_csv(output_path, index=False)

    total_flows = len(prediction_df)
    anomalous_flows = int(prediction_df["is_anomaly"].sum())

    print(f"[INFO] Predictions saved to: {output_path}")

    print("\n=== Prediction summary ===")
    print(f"Total flows: {total_flows}")
    print(f"Anomalous flows, P(normal) < {normal_threshold}: {anomalous_flows}")

    print("\nPredicted classes:")
    print(prediction_df["predicted_class"].value_counts().to_string())

    print("\nAnomaly counts:")
    print(prediction_df["is_anomaly"].value_counts().to_string())

    print(f"\nMean confidence: {prediction_df['confidence'].mean():.4f}")
    print(f"Mean P(normal):  {prediction_df['normal_probability'].mean():.4f}")

    return prediction_df


def parse_optional_int(value: str | None) -> int | None:
    """
    Parse optional positive integer CLI arguments.

    Args:
        value: String value or None.

    Returns:
        Parsed integer or None.

    Raises:
        argparse.ArgumentTypeError: If the value is not positive.
    """
    if value is None:
        return None

    parsed = int(value)

    if parsed <= 0:
        raise argparse.ArgumentTypeError("Value must be a positive integer or omitted.")

    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Predict network traffic classes from a new PCAP file."
    )

    parser.add_argument("pcap_path", type=Path, help="Path to input PCAP file.")

    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--scaler", type=Path, default=DEFAULT_SCALER_PATH)
    parser.add_argument("--label-encoder", type=Path, default=DEFAULT_LABEL_ENCODER_PATH)
    parser.add_argument("--feature-columns", type=Path, default=DEFAULT_FEATURE_COLUMNS_PATH)
    parser.add_argument("--cleaning-report", type=Path, default=DEFAULT_CLEANING_REPORT_PATH)

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path. Default: reports/predictions/<pcap_stem>_predictions.csv",
    )

    parser.add_argument(
        "--normal-threshold",
        type=float,
        default=DEFAULT_NORMAL_THRESHOLD,
        help="Anomaly threshold based on P(normal). Default: 0.4",
    )

    parser.add_argument(
        "--max-packets",
        type=parse_optional_int,
        default=None,
        help="Optional maximum number of packets read by Scapy.",
    )

    parser.add_argument(
        "--max-packets-per-flow",
        type=parse_optional_int,
        default=10000,
        help="Optional maximum number of packets stored per flow.",
    )

    parser.add_argument(
        "--no-normalize",
        action="store_true",
        help="Disable PCAP normalization before NFStream processing.",
    )

    return parser


def main() -> None:
    """CLI entrypoint."""
    parser = build_arg_parser()
    args = parser.parse_args()

    output_path = args.output
    if output_path is None:
        output_path = DEFAULT_OUTPUT_DIR / f"{args.pcap_path.stem}_predictions.csv"

    predict_pcap(
        pcap_path=args.pcap_path,
        model_path=args.model,
        scaler_path=args.scaler,
        label_encoder_path=args.label_encoder,
        feature_columns_path=args.feature_columns,
        cleaning_report_path=args.cleaning_report,
        output_path=output_path,
        normal_threshold=args.normal_threshold,
        max_packets=args.max_packets,
        max_packets_per_flow=args.max_packets_per_flow,
        normalize_pcap=not args.no_normalize,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)
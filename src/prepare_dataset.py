from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[1]

INPUT_DATASET = PROJECT_ROOT / "data" / "processed" / "dataset_features_day4.csv"

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
DOCS_DIR = PROJECT_ROOT / "docs"
MODELS_DIR = PROJECT_ROOT / "models"

OUT_CLEAN_UNBALANCED = PROCESSED_DIR / "dataset_clean_unbalanced.csv"
OUT_DATASET = PROCESSED_DIR / "dataset.csv"
OUT_SCALED = PROCESSED_DIR / "dataset_scaled.csv"
OUT_FEATURE_COLUMNS = PROCESSED_DIR / "feature_columns.json"
OUT_CLEANING_REPORT = PROCESSED_DIR / "cleaning_report.json"
OUT_OUTLIER_REPORT = PROCESSED_DIR / "outlier_clipping_report.csv"
OUT_BALANCE_REPORT = PROCESSED_DIR / "class_balance_report.csv"
OUT_STATS_BY_LABEL = PROCESSED_DIR / "feature_stats_by_label.csv"
OUT_SCALER = MODELS_DIR / "scaler.pkl"
OUT_NOTES = DOCS_DIR / "week2_day5_cleaning_eda_notes.md"

EXPECTED_LABELS = [
    "normal",
    "icmp_flood",
    "syn_scan",
    "udp_scan",
    "port_sweep",
]

BASE_FEATURE_COLUMNS = [
    "protocol",
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "dst2src_packets",
    "src2dst_bytes",
    "dst2src_bytes",
    "bidirectional_mean_ps",
    "bidirectional_syn_packets",
    "bidirectional_ack_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
    "bidirectional_psh_packets",
    "bytes_asymmetry_ratio",
    "packets_asymmetry_ratio",
    "bidirectional_packets_per_ms",
    "bytes_per_packet",
    "syn_ack_ratio_nfstream",
    "manual_packet_count",
    "iat_mean_ms",
    "iat_std_ms",
    "iat_cv",
    "rtt_estimate_ms",
    "tcp_window_min",
    "tcp_window_max",
    "tcp_window_mean",
    "tcp_window_var",
    "syn_ack_ratio_manual",
]

CRITICAL_COLUMNS = [
    "label",
    "protocol",
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
]


def require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")


def coerce_numeric_features(df: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    out = df.copy()

    for col in features:
        if col in out.columns:
            out[col] = pd.to_numeric(out[col], errors="coerce")

    return out


def add_missing_indicators_and_impute(
    df: pd.DataFrame,
    feature_columns: list[str],
) -> tuple[pd.DataFrame, list[str], dict[str, Any]]:
    out = df.copy()
    final_features = list(feature_columns)
    report: dict[str, Any] = {}

    for col in feature_columns:
        if col not in out.columns:
            continue

        missing_count = int(out[col].isna().sum())
        missing_pct = float(out[col].isna().mean() * 100)

        if missing_count > 0:
            indicator_col = f"{col}_missing"
            out[indicator_col] = out[col].isna().astype(int)
            final_features.append(indicator_col)

            median_value = out[col].median(skipna=True)

            if pd.isna(median_value):
                median_value = 0.0

            out[col] = out[col].fillna(median_value)

            report[col] = {
                "missing_count": missing_count,
                "missing_pct": round(missing_pct, 4),
                "imputation_value": float(median_value),
                "indicator_column": indicator_col,
            }

    return out, final_features, report


def clip_outliers_by_quantile(
    df: pd.DataFrame,
    feature_columns: list[str],
    lower_q: float = 0.01,
    upper_q: float = 0.99,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    out = df.copy()
    rows: list[dict[str, Any]] = []

    skip_exact = {"protocol"}
    skip_suffixes = ("_missing", "_flag")

    for col in feature_columns:
        if col not in out.columns:
            continue

        if col in skip_exact or col.endswith(skip_suffixes):
            continue

        if not pd.api.types.is_numeric_dtype(out[col]):
            continue

        lower = out[col].quantile(lower_q)
        upper = out[col].quantile(upper_q)

        if pd.isna(lower) or pd.isna(upper):
            continue

        before = out[col].copy()
        out[col] = out[col].clip(lower=lower, upper=upper)

        n_low = int((before < lower).sum())
        n_high = int((before > upper).sum())

        rows.append(
            {
                "feature": col,
                "lower_q": lower_q,
                "upper_q": upper_q,
                "lower_value": float(lower),
                "upper_value": float(upper),
                "n_clipped_low": n_low,
                "n_clipped_high": n_high,
                "n_clipped_total": n_low + n_high,
                "pct_clipped_total": round((n_low + n_high) / len(out) * 100, 4),
            }
        )

    return out, pd.DataFrame(rows)


def balance_by_undersampling(
    df: pd.DataFrame,
    label_col: str = "label",
    max_ratio: int = 3,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    counts_before = df[label_col].value_counts().sort_index()
    min_count = int(counts_before.min())
    target_max = int(min_count * max_ratio)

    frames = []

    for label, group in df.groupby(label_col):
        if len(group) > target_max:
            sampled = group.sample(n=target_max, random_state=random_state)
        else:
            sampled = group

        frames.append(sampled)

    balanced = (
        pd.concat(frames, ignore_index=True)
        .sample(frac=1.0, random_state=random_state)
        .reset_index(drop=True)
    )

    counts_after = balanced[label_col].value_counts().sort_index()
    labels = sorted(set(counts_before.index).union(set(counts_after.index)))

    report = pd.DataFrame(
        {
            "label": labels,
            "count_before": [int(counts_before.get(label, 0)) for label in labels],
            "count_after": [int(counts_after.get(label, 0)) for label in labels],
        }
    )

    report["removed_by_balancing"] = report["count_before"] - report["count_after"]

    return balanced, report


def compute_feature_stats_by_label(
    df: pd.DataFrame,
    feature_columns: list[str],
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []

    for feature in feature_columns:
        if feature not in df.columns:
            continue

        if not pd.api.types.is_numeric_dtype(df[feature]):
            continue

        for label, group in df.groupby("label"):
            values = group[feature]

            rows.append(
                {
                    "label": label,
                    "feature": feature,
                    "mean": round(values.mean(), 6),
                    "median": round(values.median(), 6),
                    "std": round(values.std(), 6),
                    "min": round(values.min(), 6),
                    "max": round(values.max(), 6),
                    "null_pct": round(values.isna().mean() * 100, 4),
                }
            )

    return pd.DataFrame(rows)


def build_markdown_report(
    cleaning_report: dict[str, Any],
    balance_report: pd.DataFrame,
    outlier_report: pd.DataFrame,
    stats_by_label: pd.DataFrame,
    final_feature_columns: list[str],
) -> str:
    key_features = [
        "bidirectional_duration_ms",
        "iat_mean_ms",
        "iat_cv",
        "syn_ack_ratio_manual",
        "bidirectional_packets_per_ms",
        "bidirectional_bytes",
    ]

    stats_excerpt = stats_by_label[stats_by_label["feature"].isin(key_features)]
    top_outliers = outlier_report.sort_values("n_clipped_total", ascending=False).head(15)

    lines = []
    lines.append("# Week 2 Day 5 - Dataset Cleaning, Balancing, Scaling and EDA")
    lines.append("")
    lines.append("## Objective")
    lines.append("")
    lines.append("Prepare the final dataset for Machine Learning from data/processed/dataset_features_day4.csv.")
    lines.append("")
    lines.append("## Important cleaning decision")
    lines.append("")
    lines.append("A global dropna() was intentionally avoided. Some NaN values are semantically valid:")
    lines.append("")
    lines.append("- rtt_estimate_ms is NaN for UDP, ICMP and incomplete TCP handshakes.")
    lines.append("- TCP window statistics are NaN for non-TCP flows.")
    lines.append("- SYN/ACK ratio is NaN for non-TCP flows or flows without ACK packets.")
    lines.append("")
    lines.append("Instead, the pipeline adds missing-value indicator columns and imputes numeric NaNs with global medians. This preserves protocol information without deleting entire traffic classes.")
    lines.append("")
    lines.append("## Cleaning summary")
    lines.append("")
    lines.append(json.dumps(cleaning_report, indent=2))
    lines.append("")
    lines.append("## Class balance report")
    lines.append("")
    lines.append(balance_report.to_markdown(index=False))
    lines.append("")
    lines.append("## Outlier clipping report")
    lines.append("")
    lines.append("Stored in data/processed/outlier_clipping_report.csv")
    lines.append("")
    lines.append("Top clipped features:")
    lines.append("")
    lines.append(top_outliers.to_markdown(index=False))
    lines.append("")
    lines.append("## Feature statistics by label")
    lines.append("")
    lines.append("Stored in data/processed/feature_stats_by_label.csv")
    lines.append("")
    lines.append("Excerpt:")
    lines.append("")
    lines.append(stats_excerpt.to_markdown(index=False))
    lines.append("")
    lines.append("## Final feature columns")
    lines.append("")
    lines.append(f"Total final ML features: {len(final_feature_columns)}")
    lines.append("")
    for feature in final_feature_columns:
        lines.append(f"- {feature}")
    lines.append("")
    lines.append("## Generated files")
    lines.append("")
    lines.append("- data/processed/dataset_clean_unbalanced.csv")
    lines.append("- data/processed/dataset.csv")
    lines.append("- data/processed/dataset_scaled.csv")
    lines.append("- data/processed/feature_columns.json")
    lines.append("- data/processed/cleaning_report.json")
    lines.append("- data/processed/outlier_clipping_report.csv")
    lines.append("- data/processed/class_balance_report.csv")
    lines.append("- data/processed/feature_stats_by_label.csv")
    lines.append("- models/scaler.pkl")
    lines.append("")
    lines.append("## Next step")
    lines.append("")
    lines.append("Use dataset_scaled.csv for K-Means clustering and dataset.csv or dataset_scaled.csv for supervised classification experiments.")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    require_file(INPUT_DATASET)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    raw = pd.read_csv(INPUT_DATASET)

    report: dict[str, Any] = {
        "input_path": str(INPUT_DATASET.relative_to(PROJECT_ROOT)),
        "initial_rows": int(len(raw)),
        "initial_columns": int(raw.shape[1]),
    }

    df = raw.copy()
    df = df.replace([np.inf, -np.inf], np.nan)

    before_label_filter = len(df)
    df = df[df["label"].isin(EXPECTED_LABELS)].copy()
    report["rows_removed_unknown_label"] = int(before_label_filter - len(df))

    available_features = [col for col in BASE_FEATURE_COLUMNS if col in df.columns]
    missing_features = [col for col in BASE_FEATURE_COLUMNS if col not in df.columns]

    report["available_base_features"] = available_features
    report["missing_base_features"] = missing_features

    df = coerce_numeric_features(df, available_features)

    before_critical_drop = len(df)
    critical_available = [col for col in CRITICAL_COLUMNS if col in df.columns]
    df = df.dropna(subset=critical_available).copy()
    report["rows_removed_critical_nan"] = int(before_critical_drop - len(df))

    before_invalid_numeric = len(df)
    df = df[df["bidirectional_packets"] > 0].copy()
    df = df[df["bidirectional_bytes"] > 0].copy()
    df = df[df["bidirectional_duration_ms"] >= 0].copy()
    report["rows_removed_invalid_packets_bytes_duration"] = int(before_invalid_numeric - len(df))

    df["duration_zero_flag"] = (df["bidirectional_duration_ms"] == 0).astype(int)
    report["duration_zero_rows_kept"] = int(df["duration_zero_flag"].sum())

    feature_columns = list(available_features) + ["duration_zero_flag"]

    df, feature_columns, imputation_report = add_missing_indicators_and_impute(
        df=df,
        feature_columns=feature_columns,
    )

    report["imputation_report"] = imputation_report

    clipped_df, outlier_report = clip_outliers_by_quantile(
        df=df,
        feature_columns=feature_columns,
        lower_q=0.01,
        upper_q=0.99,
    )

    balanced_df, balance_report = balance_by_undersampling(
        clipped_df,
        label_col="label",
        max_ratio=3,
        random_state=42,
    )

    feature_columns = [col for col in feature_columns if col in balanced_df.columns]

    clean_unbalanced = clipped_df[feature_columns + ["label"]].copy()
    final_dataset = balanced_df[feature_columns + ["label"]].copy()

    clean_unbalanced.to_csv(OUT_CLEAN_UNBALANCED, index=False)
    final_dataset.to_csv(OUT_DATASET, index=False)

    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(final_dataset[feature_columns])

    scaled_df = pd.DataFrame(scaled_features, columns=feature_columns)
    scaled_df["label"] = final_dataset["label"].values

    scaled_df.to_csv(OUT_SCALED, index=False)

    joblib.dump(
        {
            "scaler": scaler,
            "feature_columns": feature_columns,
        },
        OUT_SCALER,
    )

    with OUT_FEATURE_COLUMNS.open("w", encoding="utf-8") as file:
        json.dump(
            {
                "feature_columns": feature_columns,
                "label_column": "label",
            },
            file,
            indent=2,
        )

    report["rows_after_cleaning_before_balancing"] = int(len(clean_unbalanced))
    report["rows_after_balancing"] = int(len(final_dataset))
    report["final_feature_count"] = int(len(feature_columns))
    report["output_dataset"] = str(OUT_DATASET.relative_to(PROJECT_ROOT))
    report["output_scaled_dataset"] = str(OUT_SCALED.relative_to(PROJECT_ROOT))
    report["scaler_path"] = str(OUT_SCALER.relative_to(PROJECT_ROOT))

    with OUT_CLEANING_REPORT.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    outlier_report.to_csv(OUT_OUTLIER_REPORT, index=False)
    balance_report.to_csv(OUT_BALANCE_REPORT, index=False)

    stats_by_label = compute_feature_stats_by_label(final_dataset, feature_columns)
    stats_by_label.to_csv(OUT_STATS_BY_LABEL, index=False)

    notes = build_markdown_report(
        cleaning_report=report,
        balance_report=balance_report,
        outlier_report=outlier_report,
        stats_by_label=stats_by_label,
        final_feature_columns=feature_columns,
    )

    OUT_NOTES.write_text(notes, encoding="utf-8")

    print(f"Saved: {OUT_CLEAN_UNBALANCED}")
    print(f"Saved: {OUT_DATASET}")
    print(f"Saved: {OUT_SCALED}")
    print(f"Saved: {OUT_SCALER}")
    print(f"Saved: {OUT_FEATURE_COLUMNS}")
    print(f"Saved: {OUT_CLEANING_REPORT}")
    print(f"Saved: {OUT_OUTLIER_REPORT}")
    print(f"Saved: {OUT_BALANCE_REPORT}")
    print(f"Saved: {OUT_STATS_BY_LABEL}")
    print(f"Saved: {OUT_NOTES}")
    print()
    print("Final dataset shape:", final_dataset.shape)
    print("Scaled dataset shape:", scaled_df.shape)
    print()
    print("Class balance after cleaning:")
    print(final_dataset["label"].value_counts())
    print()
    print("Feature count:", len(feature_columns))


if __name__ == "__main__":
    main()

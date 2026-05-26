from __future__ import annotations

import json
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import LabelEncoder


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
DOCS_DIR = PROJECT_ROOT / "docs"
FIGURES_DIR = DOCS_DIR / "figures"
MODELS_DIR = PROJECT_ROOT / "models"

DATASET_PATH = PROCESSED_DIR / "dataset.csv"
SCALED_PATH = PROCESSED_DIR / "dataset_scaled.csv"
FEATURE_COLUMNS_PATH = PROCESSED_DIR / "feature_columns.json"
CLEANING_REPORT_PATH = PROCESSED_DIR / "cleaning_report.json"
BALANCE_REPORT_PATH = PROCESSED_DIR / "class_balance_report.csv"
OUTLIER_REPORT_PATH = PROCESSED_DIR / "outlier_clipping_report.csv"
FEATURE_STATS_PATH = PROCESSED_DIR / "feature_stats_by_label.csv"
SCALER_PATH = MODELS_DIR / "scaler.pkl"

OUT_EDA_REVIEW = DOCS_DIR / "week2_eda_review.md"
OUT_FEATURE_ENGINEERING_SECTION = DOCS_DIR / "report_feature_engineering_section.md"
OUT_WEEK2_SUMMARY = DOCS_DIR / "week2_closing_summary.md"

OUT_PCA_REVIEW = FIGURES_DIR / "week2_review_pca_2d_with_centroids.png"
OUT_IAT_SYNACK_REVIEW = FIGURES_DIR / "week2_review_iat_cv_vs_syn_ack.png"


def require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Missing required file: {path}")


def load_inputs() -> tuple[pd.DataFrame, pd.DataFrame, list[str], dict]:
    require_file(DATASET_PATH)
    require_file(SCALED_PATH)
    require_file(FEATURE_COLUMNS_PATH)
    require_file(CLEANING_REPORT_PATH)
    require_file(SCALER_PATH)

    df = pd.read_csv(DATASET_PATH)
    scaled = pd.read_csv(SCALED_PATH)

    with FEATURE_COLUMNS_PATH.open("r", encoding="utf-8") as file:
        feature_columns = json.load(file)["feature_columns"]

    with CLEANING_REPORT_PATH.open("r", encoding="utf-8") as file:
        cleaning_report = json.load(file)

    return df, scaled, feature_columns, cleaning_report


def compute_class_overview(df: pd.DataFrame) -> pd.DataFrame:
    rows = []

    for label, group in df.groupby("label"):
        row = {
            "label": label,
            "n_flows": len(group),
        }

        for col in [
            "bidirectional_duration_ms",
            "bidirectional_packets",
            "bidirectional_bytes",
            "iat_mean_ms",
            "iat_cv",
            "syn_ack_ratio_manual",
            "bidirectional_packets_per_ms",
        ]:
            if col in group.columns:
                row[f"{col}_mean"] = round(group[col].mean(), 6)
                row[f"{col}_median"] = round(group[col].median(), 6)

        rows.append(row)

    return pd.DataFrame(rows).sort_values("label")


def compute_pca_review(
    scaled: pd.DataFrame,
    feature_columns: list[str],
) -> tuple[pd.DataFrame, np.ndarray, float]:
    X = scaled[feature_columns].values

    pca = PCA(n_components=2, random_state=42)
    components = pca.fit_transform(X)

    pca_df = pd.DataFrame(
        {
            "PC1": components[:, 0],
            "PC2": components[:, 1],
            "label": scaled["label"].values,
        }
    )

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(scaled["label"])

    if len(set(y_encoded)) > 1 and len(scaled) > len(set(y_encoded)):
        score = float(silhouette_score(X, y_encoded))
    else:
        score = float("nan")

    return pca_df, pca.explained_variance_ratio_, score


def save_pca_plot(pca_df: pd.DataFrame) -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    centroids = (
        pca_df.groupby("label")[["PC1", "PC2"]]
        .mean()
        .reset_index()
    )

    plt.figure(figsize=(10, 7))
    sns.scatterplot(
        data=pca_df,
        x="PC1",
        y="PC2",
        hue="label",
        alpha=0.7,
        s=35,
    )

    for _, row in centroids.iterrows():
        plt.scatter(row["PC1"], row["PC2"], s=220, marker="X", edgecolor="black")
        plt.text(row["PC1"], row["PC2"], str(row["label"]), fontsize=10, weight="bold")

    plt.title("Week 2 PCA 2D review with class centroids")
    plt.tight_layout()
    plt.savefig(OUT_PCA_REVIEW, dpi=160)
    plt.close()


def save_iat_synack_plot(df: pd.DataFrame) -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    x_col = "iat_cv"
    y_col = "syn_ack_ratio_manual"

    if x_col not in df.columns or y_col not in df.columns:
        return

    plt.figure(figsize=(10, 7))
    sns.scatterplot(
        data=df,
        x=x_col,
        y=y_col,
        hue="label",
        alpha=0.75,
        s=40,
    )

    plt.title("Week 2 review: IAT CV vs manual SYN/ACK ratio")
    plt.tight_layout()
    plt.savefig(OUT_IAT_SYNACK_REVIEW, dpi=160)
    plt.close()


def build_eda_review_markdown(
    df: pd.DataFrame,
    scaled: pd.DataFrame,
    feature_columns: list[str],
    cleaning_report: dict,
    class_overview: pd.DataFrame,
    pca_variance: np.ndarray,
    silhouette: float,
) -> str:
    label_counts = df["label"].value_counts().to_frame("n_flows").reset_index()
    label_counts.columns = ["label", "n_flows"]

    nan_dataset = int(df.isna().sum().sum())
    nan_scaled = int(scaled.isna().sum().sum())
    ratio = df["label"].value_counts().max() / df["label"].value_counts().min()

    lines = []
    lines.append("# Week 2 EDA Review")
    lines.append("")
    lines.append("## Objective")
    lines.append("")
    lines.append("This document reviews the final Week 2 dataset before starting the Machine Learning phase.")
    lines.append("")
    lines.append("The review checks data integrity, class balance, feature separability, PCA visualization and the relationship between protocol-aware features.")
    lines.append("")
    lines.append("## Dataset integrity")
    lines.append("")
    lines.append(f"- dataset.csv shape: {df.shape}")
    lines.append(f"- dataset_scaled.csv shape: {scaled.shape}")
    lines.append(f"- number of ML features: {len(feature_columns)}")
    lines.append(f"- NaN values in dataset.csv: {nan_dataset}")
    lines.append(f"- NaN values in dataset_scaled.csv: {nan_scaled}")
    lines.append(f"- max/min class ratio: {ratio:.3f}")
    lines.append("")
    lines.append("## Class distribution")
    lines.append("")
    lines.append(label_counts.to_markdown(index=False))
    lines.append("")
    lines.append("## Cleaning summary")
    lines.append("")
    lines.append(f"- Initial rows: {cleaning_report.get('initial_rows')}")
    lines.append(f"- Rows after cleaning before balancing: {cleaning_report.get('rows_after_cleaning_before_balancing')}")
    lines.append(f"- Rows after balancing: {cleaning_report.get('rows_after_balancing')}")
    lines.append(f"- Duration-zero rows kept: {cleaning_report.get('duration_zero_rows_kept')}")
    lines.append(f"- Rows removed due to critical NaNs: {cleaning_report.get('rows_removed_critical_nan')}")
    lines.append(f"- Rows removed due to invalid packets/bytes/duration: {cleaning_report.get('rows_removed_invalid_packets_bytes_duration')}")
    lines.append("")
    lines.append("## Feature statistics by class")
    lines.append("")
    lines.append(class_overview.to_markdown(index=False))
    lines.append("")
    lines.append("## PCA 2D review")
    lines.append("")
    lines.append(f"- PCA explained variance PC1: {pca_variance[0]:.4f}")
    lines.append(f"- PCA explained variance PC2: {pca_variance[1]:.4f}")
    lines.append(f"- PCA total explained variance: {pca_variance.sum():.4f}")
    lines.append(f"- True-label silhouette score on scaled features: {silhouette:.4f}")
    lines.append("")
    lines.append("Generated figure:")
    lines.append("")
    lines.append("- docs/figures/week2_review_pca_2d_with_centroids.png")
    lines.append("")
    lines.append("## IAT CV vs SYN/ACK ratio review")
    lines.append("")
    lines.append("Generated figure:")
    lines.append("")
    lines.append("- docs/figures/week2_review_iat_cv_vs_syn_ack.png")
    lines.append("")
    lines.append("Interpretation notes:")
    lines.append("")
    lines.append("- Non-TCP traffic may have imputed SYN/ACK-related values plus missing indicators.")
    lines.append("- SYN scan and port sweep can overlap in SYN/ACK ratio because both are probing behaviors.")
    lines.append("- Full separability is not required before ML, but complete overlap would indicate a feature extraction issue.")
    lines.append("- The PCA plot should be used as a qualitative check before K-Means.")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    if nan_dataset == 0 and nan_scaled == 0 and ratio <= 3:
        lines.append("The final Week 2 dataset is clean, balanced, scaled and ready for the Machine Learning phase.")
    else:
        lines.append("The dataset still requires attention before ML because one or more validation checks failed.")
    lines.append("")

    return "\n".join(lines)


def build_feature_engineering_section(
    df: pd.DataFrame,
    class_overview: pd.DataFrame,
    cleaning_report: dict,
) -> str:
    lines = []
    lines.append("# Section 4 - Feature Engineering")
    lines.append("")
    lines.append("## 4.1 Goal and scope")
    lines.append("")
    lines.append("The objective of the feature engineering stage is to transform raw packet captures into flow-level numerical features suitable for Machine Learning.")
    lines.append("")
    lines.append("The project is intentionally limited to Layer 3 and Layer 4 information. Payload inspection and application-layer signatures are excluded to preserve privacy, avoid dependence on decrypted traffic and focus on protocol behavior.")
    lines.append("")
    lines.append("## 4.2 Flow reconstruction")
    lines.append("")
    lines.append("The PCAP files are first normalized into Ethernet/IP captures because the original Docker/WSL captures used Linux cooked capture v2. This normalization preserves IP, TCP, UDP and ICMP headers and timestamps, while replacing only the link-layer header.")
    lines.append("")
    lines.append("NFStream is used to reconstruct bidirectional flows and compute aggregate statistics such as duration, packet counts, byte counts, packet size and TCP flag counters.")
    lines.append("")
    lines.append("## 4.3 Selected features")
    lines.append("")
    feature_rows = [
        ["protocol", "IP protocol number", "Separates TCP, UDP and ICMP behavior."],
        ["bidirectional_duration_ms", "last_seen - first_seen", "Scans and probes usually produce short flows; normal sessions last longer."],
        ["bidirectional_packets", "count of packets in both directions", "Measures flow interaction volume."],
        ["bidirectional_bytes", "sum of packet bytes in both directions", "Distinguishes data transfer from control/probe traffic."],
        ["src2dst_bytes / dst2src_bytes", "directional byte counters", "Captures asymmetry between initiator and responder."],
        ["bytes_asymmetry_ratio", "(src2dst_bytes + 1) / (dst2src_bytes + 1)", "Highlights one-way scans and floods."],
        ["bidirectional_mean_ps", "mean packet size", "Small control packets differ from application data flows."],
        ["TCP flag counts", "SYN, ACK, RST, FIN, PSH counters", "Represent TCP handshake, reset and data-transfer behavior."],
        ["iat_cv", "std(IAT) / mean(IAT)", "Measures timing regularity; automated traffic is often more regular."],
        ["rtt_estimate_ms", "timestamp(SYN-ACK) - timestamp(SYN)", "Only exists for complete TCP handshakes."],
        ["tcp_window statistics", "min, max, mean, variance of TCP window", "Represents TCP session dynamics."],
        ["syn_ack_ratio_manual", "count(SYN) / count(ACK)", "Detects abnormal connection attempt behavior."],
        ["bidirectional_packets_per_ms", "packets / max(duration_ms, 1)", "Measures traffic intensity, useful for floods and fast scans."],
    ]
    feature_table = pd.DataFrame(feature_rows, columns=["feature", "formula", "technical justification"])
    lines.append(feature_table.to_markdown(index=False))
    lines.append("")
    lines.append("## 4.4 Manual Scapy features")
    lines.append("")
    lines.append("NFStream provides strong flow-level aggregation, but some protocol-aware features are calculated manually with Scapy. These include inter-arrival time, estimated RTT, TCP window statistics and a manually validated SYN/ACK ratio.")
    lines.append("")
    lines.append("A key design decision is to return NaN when a feature is not semantically defined. For example, UDP and ICMP do not have TCP RTT or TCP window size. Incomplete TCP handshakes also do not receive an artificial RTT of 0; they receive NaN because no valid RTT exists.")
    lines.append("")
    lines.append("## 4.5 Cleaning and imputation")
    lines.append("")
    lines.append("A global dropna operation was avoided because it would remove protocol-specific rows where missing values are meaningful. Instead, missing indicator columns are added and NaN values are imputed with the global median.")
    lines.append("")
    lines.append(f"The initial Day 4 dataset contained {cleaning_report.get('initial_rows')} rows. After cleaning and before balancing, {cleaning_report.get('rows_after_cleaning_before_balancing')} rows remained. The final balanced dataset contains {cleaning_report.get('rows_after_balancing')} rows.")
    lines.append("")
    lines.append(f"Duration-zero flows kept: {cleaning_report.get('duration_zero_rows_kept')}. These are preserved because scans in a local Docker network can legitimately produce near-instantaneous flows.")
    lines.append("")
    lines.append("## 4.6 Outlier handling and scaling")
    lines.append("")
    lines.append("Extreme values are clipped using the 1st and 99th percentiles per feature. This reduces the effect of unusually large flows while preserving class-level patterns.")
    lines.append("")
    lines.append("The final numeric feature matrix is standardized using StandardScaler. The fitted scaler is saved in models/scaler.pkl to guarantee consistent preprocessing during prediction.")
    lines.append("")
    lines.append("## 4.7 Empirical validation")
    lines.append("")
    lines.append("The following table summarizes the empirical behavior of key features by class.")
    lines.append("")
    lines.append(class_overview.to_markdown(index=False))
    lines.append("")
    lines.append("These statistics validate that the selected features are not arbitrary: they reflect measurable differences in timing, duration, packet volume, TCP behavior and protocol type.")
    lines.append("")
    lines.append("## 4.8 Limitations")
    lines.append("")
    lines.append("- The dataset is generated in a controlled Docker environment, so absolute timing values may differ from a real network.")
    lines.append("- Some features are protocol-specific and require missing-value indicators.")
    lines.append("- UDP scan and port sweep may partially overlap because both generate short low-volume probing flows.")
    lines.append("- The current feature set does not inspect payload and therefore cannot distinguish application semantics inside encrypted traffic.")
    lines.append("")

    return "\n".join(lines)


def build_week2_summary(
    df: pd.DataFrame,
    scaled: pd.DataFrame,
    feature_columns: list[str],
) -> str:
    lines = []
    lines.append("# Week 2 Closing Summary")
    lines.append("")
    lines.append("## Status")
    lines.append("")
    lines.append("Week 2 is complete. The project now has a cleaned, balanced and scaled flow-level dataset ready for Machine Learning.")
    lines.append("")
    lines.append("## Main deliverables")
    lines.append("")
    deliverables = [
        "notebooks/01_nfstream_exploration.ipynb",
        "docs/features_description.md",
        "src/manual_features.py",
        "src/pipeline.py",
        "src/prepare_dataset.py",
        "notebooks/02_eda.ipynb",
        "data/processed/dataset.csv",
        "data/processed/dataset_scaled.csv",
        "models/scaler.pkl",
        "docs/week2_eda_review.md",
        "docs/report_feature_engineering_section.md",
    ]
    for item in deliverables:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Final dataset")
    lines.append("")
    lines.append(f"- dataset.csv shape: {df.shape}")
    lines.append(f"- dataset_scaled.csv shape: {scaled.shape}")
    lines.append(f"- feature count: {len(feature_columns)}")
    lines.append("")
    lines.append("## Class distribution")
    lines.append("")
    counts = df["label"].value_counts().to_frame("n_flows").reset_index()
    counts.columns = ["label", "n_flows"]
    lines.append(counts.to_markdown(index=False))
    lines.append("")
    lines.append("## Next step")
    lines.append("")
    lines.append("Start Week 3 with unsupervised clustering using K-Means on data/processed/dataset_scaled.csv.")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    df, scaled, feature_columns, cleaning_report = load_inputs()

    bundle = joblib.load(SCALER_PATH)
    if len(bundle["feature_columns"]) != len(feature_columns):
        raise ValueError("Scaler feature count does not match feature_columns.json")

    if int(df.isna().sum().sum()) != 0:
        raise ValueError("dataset.csv contains NaN values")

    if int(scaled.isna().sum().sum()) != 0:
        raise ValueError("dataset_scaled.csv contains NaN values")

    class_ratio = df["label"].value_counts().max() / df["label"].value_counts().min()
    if class_ratio > 3:
        raise ValueError(f"Class balance ratio is above 3:1: {class_ratio}")

    class_overview = compute_class_overview(df)
    pca_df, pca_variance, silhouette = compute_pca_review(scaled, feature_columns)

    save_pca_plot(pca_df)
    save_iat_synack_plot(df)

    eda_review = build_eda_review_markdown(
        df=df,
        scaled=scaled,
        feature_columns=feature_columns,
        cleaning_report=cleaning_report,
        class_overview=class_overview,
        pca_variance=pca_variance,
        silhouette=silhouette,
    )

    feature_engineering_section = build_feature_engineering_section(
        df=df,
        class_overview=class_overview,
        cleaning_report=cleaning_report,
    )

    week2_summary = build_week2_summary(
        df=df,
        scaled=scaled,
        feature_columns=feature_columns,
    )

    OUT_EDA_REVIEW.write_text(eda_review, encoding="utf-8")
    OUT_FEATURE_ENGINEERING_SECTION.write_text(feature_engineering_section, encoding="utf-8")
    OUT_WEEK2_SUMMARY.write_text(week2_summary, encoding="utf-8")

    print(f"Saved: {OUT_EDA_REVIEW}")
    print(f"Saved: {OUT_FEATURE_ENGINEERING_SECTION}")
    print(f"Saved: {OUT_WEEK2_SUMMARY}")
    print(f"Saved: {OUT_PCA_REVIEW}")
    print(f"Saved: {OUT_IAT_SYNACK_REVIEW}")
    print()
    print("Dataset shape:", df.shape)
    print("Scaled shape:", scaled.shape)
    print("Class ratio:", round(class_ratio, 3))
    print("PCA explained variance:", pca_variance)
    print("Silhouette score:", round(silhouette, 4))
    print()
    print("Labels:")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()

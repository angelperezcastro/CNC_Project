"""
End-to-end feature extraction pipeline.

This module combines:
1. NFStream flow-level features.
2. Derived L3/L4 flow features.
3. Manual Scapy packet-level features.
4. Traffic labels.

The main entry point is process_pcap(), which receives a PCAP path and label
and returns a complete feature DataFrame ready for cleaning and ML stages.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional, Any

import numpy as np
import pandas as pd
from nfstream import NFStreamer
from scapy.all import PcapReader
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Allows both:
#   python src/pipeline.py
#   python -m src.pipeline
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.manual_features import calc_manual_features  # noqa: E402


DEFAULT_INPUT_DIR = PROJECT_ROOT / "data" / "interim" / "nfstream_compatible"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "processed" / "dataset_features_day4.csv"
DEFAULT_ERRORS_OUTPUT = PROJECT_ROOT / "data" / "processed" / "pipeline_errors_day4.csv"
DEFAULT_SUMMARY_OUTPUT = PROJECT_ROOT / "data" / "processed" / "pipeline_day4_summary_by_label.csv"


LABELS = ["normal", "icmp_flood", "syn_scan", "udp_scan", "port_sweep"]

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


NFSTREAM_BASE_COLUMNS = [
    # Identity
    "id",
    "expiration_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",

    # Timing
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
    "bidirectional_duration_ms",

    # Volume
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",

    # Packet size
    "bidirectional_min_ps",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",

    # TCP flags - bidirectional
    "bidirectional_syn_packets",
    "bidirectional_cwr_packets",
    "bidirectional_ece_packets",
    "bidirectional_urg_packets",
    "bidirectional_ack_packets",
    "bidirectional_psh_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",

    # TCP flags - src to dst
    "src2dst_syn_packets",
    "src2dst_ack_packets",
    "src2dst_rst_packets",
    "src2dst_fin_packets",
    "src2dst_psh_packets",

    # TCP flags - dst to src
    "dst2src_syn_packets",
    "dst2src_ack_packets",
    "dst2src_rst_packets",
    "dst2src_fin_packets",
    "dst2src_psh_packets",
]


def infer_label_from_path(path: Path) -> str:
    """
    Infer traffic label from a PCAP path.

    Args:
        path: PCAP file path.

    Returns:
        Inferred label or 'unknown'.
    """
    text = str(path).lower()

    for label in LABELS:
        if label in text:
            return label

    return "unknown"


def ensure_valid_pcap_path(pcap_path: Path) -> Path:
    """
    Validate PCAP path before processing.

    Args:
        pcap_path: Input path.

    Returns:
        Resolved PCAP path.

    Raises:
        FileNotFoundError: If PCAP does not exist.
        ValueError: If PCAP is empty.
    """
    resolved = Path(pcap_path).resolve()

    if not resolved.exists():
        raise FileNotFoundError(f"PCAP file does not exist: {resolved}")

    if resolved.stat().st_size == 0:
        raise ValueError(f"PCAP file is empty: {resolved}")

    return resolved


def protocol_number_to_name(protocol: Any) -> str:
    """
    Convert IP protocol number to a readable protocol name.

    Args:
        protocol: Protocol number from NFStream.

    Returns:
        Protocol name: TCP, UDP, ICMP or OTHER.
    """
    try:
        protocol_int = int(protocol)
    except (TypeError, ValueError):
        return "OTHER"

    return PROTOCOL_MAP.get(protocol_int, "OTHER")


def safe_int(value: Any, default: int = 0) -> int:
    """
    Convert value to int defensively.

    Args:
        value: Input value.
        default: Fallback value.

    Returns:
        Integer value or default.
    """
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_nfstream_flows(
    pcap_path: Path,
    n_meters: int = 1,
) -> pd.DataFrame:
    """
    Extract NFStream flows from a normalized PCAP.

    Args:
        pcap_path: Input PCAP path.
        n_meters: Number of NFStream metering processes.
            n_meters=1 is safer inside WSL/Jupyter/reproducible scripts.

    Returns:
        NFStream flow DataFrame with selected base columns.

    Raises:
        ValueError: If NFStream returns no flows.
    """
    pcap_path = ensure_valid_pcap_path(pcap_path)

    streamer = NFStreamer(
        source=str(pcap_path),
        statistical_analysis=True,
        splt_analysis=10,
        n_dissections=0,
        n_meters=n_meters,
    )

    df = streamer.to_pandas(columns_to_anonymize=[])

    if df is None or df.empty:
        raise ValueError(f"NFStream extracted no flows from {pcap_path}")

    available_columns = [col for col in NFSTREAM_BASE_COLUMNS if col in df.columns]
    selected = df[available_columns].copy()

    selected["nfstream_row_id"] = np.arange(len(selected))
    selected["pcap_file"] = pcap_path.name

    return selected


def add_derived_nfstream_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add derived L3/L4 features from NFStream base features.

    Args:
        df: NFStream DataFrame.

    Returns:
        DataFrame with derived features added.
    """
    out = df.copy()

    if {"src2dst_bytes", "dst2src_bytes"}.issubset(out.columns):
        out["bytes_asymmetry_ratio"] = (out["src2dst_bytes"] + 1) / (out["dst2src_bytes"] + 1)

    if {"src2dst_packets", "dst2src_packets"}.issubset(out.columns):
        out["packets_asymmetry_ratio"] = (out["src2dst_packets"] + 1) / (out["dst2src_packets"] + 1)

    if {"bidirectional_packets", "bidirectional_duration_ms"}.issubset(out.columns):
        duration_safe = out["bidirectional_duration_ms"].clip(lower=1)
        out["bidirectional_packets_per_ms"] = out["bidirectional_packets"] / duration_safe

    if {"bidirectional_bytes", "bidirectional_packets"}.issubset(out.columns):
        packets_safe = out["bidirectional_packets"].replace(0, np.nan)
        out["bytes_per_packet"] = out["bidirectional_bytes"] / packets_safe

    if {"bidirectional_syn_packets", "bidirectional_ack_packets"}.issubset(out.columns):
        ack_safe = out["bidirectional_ack_packets"].replace(0, np.nan)
        out["syn_ack_ratio_nfstream"] = out["bidirectional_syn_packets"] / ack_safe

    if "protocol" in out.columns:
        out["protocol_name"] = out["protocol"].apply(protocol_number_to_name)

    return out


def get_ip_pair(packet: Packet) -> Optional[tuple[str, str]]:
    """
    Extract IPv4/IPv6 source and destination addresses.

    Args:
        packet: Scapy packet.

    Returns:
        Tuple (src_ip, dst_ip), or None if no IP layer exists.
    """
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None


def get_protocol_and_ports(packet: Packet) -> Optional[tuple[str, int, int]]:
    """
    Extract protocol and ports from a packet.

    Args:
        packet: Scapy packet.

    Returns:
        Tuple (protocol_name, src_port, dst_port).
        ICMP uses ports 0/0.
    """
    if TCP in packet:
        return "TCP", int(packet[TCP].sport), int(packet[TCP].dport)

    if UDP in packet:
        return "UDP", int(packet[UDP].sport), int(packet[UDP].dport)

    if ICMP in packet:
        return "ICMP", 0, 0

    return None


def canonical_key_from_endpoints(
    protocol_name: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> tuple:
    """
    Build a bidirectional canonical flow key.

    Args:
        protocol_name: TCP, UDP, ICMP or OTHER.
        src_ip: Source IP.
        src_port: Source transport port.
        dst_ip: Destination IP.
        dst_port: Destination transport port.

    Returns:
        Canonical tuple that is direction-independent.
    """
    endpoint_a = (str(src_ip), int(src_port))
    endpoint_b = (str(dst_ip), int(dst_port))

    low, high = sorted([endpoint_a, endpoint_b])

    return protocol_name, low, high


def canonical_key_from_packet(packet: Packet) -> Optional[tuple]:
    """
    Build canonical bidirectional key from a Scapy packet.

    Args:
        packet: Scapy packet.

    Returns:
        Canonical flow key, or None for unsupported packets.
    """
    ip_pair = get_ip_pair(packet)
    proto_ports = get_protocol_and_ports(packet)

    if ip_pair is None or proto_ports is None:
        return None

    src_ip, dst_ip = ip_pair
    protocol_name, src_port, dst_port = proto_ports

    return canonical_key_from_endpoints(
        protocol_name=protocol_name,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


def canonical_key_from_nfstream_row(row: pd.Series) -> tuple:
    """
    Build canonical bidirectional key from an NFStream row.

    Args:
        row: NFStream DataFrame row.

    Returns:
        Canonical flow key.
    """
    protocol_name = protocol_number_to_name(row.get("protocol"))

    src_ip = str(row.get("src_ip"))
    dst_ip = str(row.get("dst_ip"))
    src_port = safe_int(row.get("src_port"), default=0)
    dst_port = safe_int(row.get("dst_port"), default=0)

    # For ICMP, NFStream ports may be missing or not semantically useful.
    if protocol_name == "ICMP":
        src_port = 0
        dst_port = 0

    return canonical_key_from_endpoints(
        protocol_name=protocol_name,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


def collect_packets_by_flow(
    pcap_path: Path,
    max_packets: Optional[int] = None,
    max_packets_per_flow: Optional[int] = 10_000,
) -> dict[tuple, list[Packet]]:
    """
    Read PCAP packets and group them by bidirectional flow key.

    Args:
        pcap_path: Input PCAP path.
        max_packets: Optional maximum number of packets to read from the PCAP.
        max_packets_per_flow: Optional cap per flow to avoid storing too many
            packets for flood traffic. Use None or <=0 for no cap.

    Returns:
        Dictionary mapping canonical flow key to list of Scapy packets.
    """
    pcap_path = ensure_valid_pcap_path(pcap_path)
    packet_index: dict[tuple, list[Packet]] = defaultdict(list)

    cap_enabled = max_packets_per_flow is not None and max_packets_per_flow > 0

    with PcapReader(str(pcap_path)) as reader:
        for packet_idx, packet in enumerate(reader):
            if max_packets is not None and packet_idx >= max_packets:
                break

            key = canonical_key_from_packet(packet)

            if key is None:
                continue

            if cap_enabled and len(packet_index[key]) >= int(max_packets_per_flow):
                continue

            packet_index[key].append(packet)

    return packet_index


def packet_time_ms(packet: Packet) -> float:
    """
    Return Scapy packet timestamp in milliseconds.

    Args:
        packet: Scapy packet.

    Returns:
        Timestamp in milliseconds.
    """
    return float(packet.time) * 1000.0


def filter_packets_for_nfstream_row(
    row: pd.Series,
    packet_index: dict[tuple, list[Packet]],
    time_margin_ms: float = 2.0,
) -> list[Packet]:
    """
    Select packets corresponding to one NFStream flow row.

    Args:
        row: NFStream row.
        packet_index: Dict from canonical flow key to packets.
        time_margin_ms: Time tolerance around NFStream first/last timestamps.

    Returns:
        List of packets assigned to the flow.

    Note:
        If timestamp filtering fails because of capture/NFStream timestamp
        inconsistencies, the function falls back to all packets with the same
        canonical key.
    """
    key = canonical_key_from_nfstream_row(row)
    candidates = packet_index.get(key, [])

    if not candidates:
        return []

    first_seen = row.get("bidirectional_first_seen_ms")
    last_seen = row.get("bidirectional_last_seen_ms")

    if pd.isna(first_seen) or pd.isna(last_seen):
        return candidates

    try:
        start_ms = float(first_seen) - time_margin_ms
        end_ms = float(last_seen) + time_margin_ms
    except (TypeError, ValueError):
        return candidates

    filtered = [
        packet
        for packet in candidates
        if start_ms <= packet_time_ms(packet) <= end_ms
    ]

    # Important fallback:
    # Some zero-duration scan flows can have tiny timestamp mismatches.
    # Returning all candidates is preferable to losing manual features entirely.
    return filtered if filtered else candidates


def extract_manual_features_for_nfstream_flows(
    pcap_path: Path,
    flows_df: pd.DataFrame,
    max_packets: Optional[int] = None,
    max_packets_per_flow: Optional[int] = 10_000,
) -> pd.DataFrame:
    """
    Compute manual Scapy features for each NFStream flow row.

    Args:
        pcap_path: Input PCAP path.
        flows_df: NFStream flow DataFrame.
        max_packets: Optional maximum packets to read.
        max_packets_per_flow: Optional cap per flow in packet index.

    Returns:
        DataFrame with one row per NFStream row and manual features.
    """
    packet_index = collect_packets_by_flow(
        pcap_path=pcap_path,
        max_packets=max_packets,
        max_packets_per_flow=max_packets_per_flow,
    )

    manual_rows: list[dict[str, Any]] = []

    feature_cache: dict[tuple, dict[str, float]] = {}
    packet_count_cache: dict[tuple, int] = {}

    for _, row in flows_df.iterrows():
        nfstream_row_id = int(row["nfstream_row_id"])
        key = canonical_key_from_nfstream_row(row)

        cache_key = (
            key,
            safe_int(row.get("bidirectional_first_seen_ms"), default=-1),
            safe_int(row.get("bidirectional_last_seen_ms"), default=-1),
        )

        if cache_key in feature_cache:
            features = feature_cache[cache_key]
            manual_packet_count = packet_count_cache[cache_key]
        else:
            packets = filter_packets_for_nfstream_row(row, packet_index)
            features = calc_manual_features(packets)
            manual_packet_count = len(packets)

            feature_cache[cache_key] = features
            packet_count_cache[cache_key] = manual_packet_count

        manual_rows.append(
            {
                "nfstream_row_id": nfstream_row_id,
                "manual_packet_count": manual_packet_count,
                **features,
            }
        )

    return pd.DataFrame(manual_rows)


def process_pcap(
    pcap_path: Path,
    label: str,
    n_meters: int = 1,
    max_packets: Optional[int] = None,
    max_packets_per_flow: Optional[int] = 10_000,
) -> pd.DataFrame:
    """
    Process one PCAP and return complete features.

    Steps:
        1. Receive PCAP path and label.
        2. Extract NFStream base flow features.
        3. Compute manual Scapy features per flow.
        4. Merge both feature tables by internal row id.
        5. Add label and return complete DataFrame.

    Args:
        pcap_path: Input normalized PCAP.
        label: Traffic label.
        n_meters: NFStream metering processes.
        max_packets: Optional maximum packets to read with Scapy.
        max_packets_per_flow: Optional cap per flow to avoid memory blow-up.

    Returns:
        Complete feature DataFrame.
    """
    pcap_path = ensure_valid_pcap_path(pcap_path)

    nfstream_df = extract_nfstream_flows(
        pcap_path=pcap_path,
        n_meters=n_meters,
    )
    nfstream_df = add_derived_nfstream_features(nfstream_df)

    manual_df = extract_manual_features_for_nfstream_flows(
        pcap_path=pcap_path,
        flows_df=nfstream_df,
        max_packets=max_packets,
        max_packets_per_flow=max_packets_per_flow,
    )

    merged = nfstream_df.merge(
        manual_df,
        on="nfstream_row_id",
        how="left",
        validate="one_to_one",
    )

    merged["label"] = label
    merged["pcap_path"] = str(pcap_path.relative_to(PROJECT_ROOT))

    return merged


def discover_pcaps(input_dir: Path) -> list[Path]:
    """
    Discover PCAP files to process.

    Args:
        input_dir: Directory containing normalized PCAPs.

    Returns:
        Sorted list of PCAP paths, excluding smoke/arp-only files.
    """
    input_dir = Path(input_dir)

    return sorted(
        path
        for path in input_dir.rglob("*.pcap")
        if "smoke" not in path.name.lower()
        and "arp_only" not in path.name.lower()
    )


def build_summary_by_label(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build compact summary of pipeline output.

    Args:
        df: Complete feature DataFrame.

    Returns:
        Summary DataFrame grouped by label.
    """
    agg_spec = {
        "n_flows": ("label", "size"),
        "n_pcaps": ("pcap_file", "nunique"),
    }

    for col in [
        "bidirectional_duration_ms",
        "bidirectional_packets",
        "bidirectional_bytes",
        "manual_packet_count",
        "iat_cv",
        "rtt_estimate_ms",
        "tcp_window_mean",
        "syn_ack_ratio_manual",
        "bidirectional_packets_per_ms",
    ]:
        if col in df.columns:
            agg_spec[f"{col}_mean"] = (col, "mean")
            agg_spec[f"{col}_median"] = (col, "median")
            agg_spec[f"{col}_null_pct"] = (col, lambda s: round(s.isna().mean() * 100, 3))

    return (
        df.groupby("label")
        .agg(**agg_spec)
        .round(4)
        .reset_index()
    )


def process_directory(
    input_dir: Path,
    output_path: Path,
    errors_output_path: Path,
    summary_output_path: Path,
    n_meters: int = 1,
    max_packets: Optional[int] = None,
    max_packets_per_flow: Optional[int] = 10_000,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Process all PCAPs under a directory.

    Args:
        input_dir: Directory with normalized PCAPs.
        output_path: Output CSV path for full dataset.
        errors_output_path: Output CSV path for processing errors.
        summary_output_path: Output CSV path for label summary.
        n_meters: NFStream metering processes.
        max_packets: Optional maximum packets to read per PCAP.
        max_packets_per_flow: Optional cap per flow.

    Returns:
        Tuple (combined_df, errors_df).
    """
    pcap_files = discover_pcaps(input_dir)

    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found under {input_dir}")

    all_frames: list[pd.DataFrame] = []
    errors: list[dict[str, Any]] = []

    start_all = time.time()

    for idx, pcap_path in enumerate(pcap_files, start=1):
        label = infer_label_from_path(pcap_path)

        print("=" * 100)
        print(f"[{idx}/{len(pcap_files)}] Processing {pcap_path.relative_to(PROJECT_ROOT)} label={label}")

        start = time.time()

        try:
            df = process_pcap(
                pcap_path=pcap_path,
                label=label,
                n_meters=n_meters,
                max_packets=max_packets,
                max_packets_per_flow=max_packets_per_flow,
            )

            elapsed = time.time() - start
            print(f"OK -> shape={df.shape}, elapsed={elapsed:.2f}s")

            all_frames.append(df)

        except Exception as exc:
            elapsed = time.time() - start
            print(f"ERROR -> {repr(exc)}")

            errors.append(
                {
                    "pcap_path": str(pcap_path.relative_to(PROJECT_ROOT)),
                    "label": label,
                    "error": repr(exc),
                    "elapsed_seconds": round(elapsed, 3),
                }
            )

    if not all_frames:
        raise RuntimeError("No PCAP could be processed successfully.")

    combined = pd.concat(all_frames, ignore_index=True, sort=False)
    errors_df = pd.DataFrame(errors)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    errors_output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_output_path.parent.mkdir(parents=True, exist_ok=True)

    combined.to_csv(output_path, index=False)
    errors_df.to_csv(errors_output_path, index=False)

    summary = build_summary_by_label(combined)
    summary.to_csv(summary_output_path, index=False)

    elapsed_all = time.time() - start_all

    print("=" * 100)
    print(f"Saved dataset: {output_path}")
    print(f"Saved errors: {errors_output_path}")
    print(f"Saved summary: {summary_output_path}")
    print(f"Combined shape: {combined.shape}")
    print(f"Errors: {len(errors_df)}")
    print(f"Total elapsed: {elapsed_all:.2f}s")

    return combined, errors_df


def parse_optional_int(value: Optional[str]) -> Optional[int]:
    """
    Parse optional integer CLI values.

    Args:
        value: CLI string.

    Returns:
        Integer or None.
    """
    if value is None:
        return None

    parsed = int(value)

    if parsed <= 0:
        return None

    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build command-line argument parser.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        description="Extract NFStream + manual Scapy features from PCAP files."
    )

    parser.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help="Single PCAP to process. If omitted, --input-dir is processed.",
    )

    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help="Label for single PCAP mode. If omitted, inferred from path.",
    )

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directory containing normalized PCAPs.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output CSV path.",
    )

    parser.add_argument(
        "--errors-output",
        type=Path,
        default=DEFAULT_ERRORS_OUTPUT,
        help="Output CSV path for errors.",
    )

    parser.add_argument(
        "--summary-output",
        type=Path,
        default=DEFAULT_SUMMARY_OUTPUT,
        help="Output CSV path for summary by label.",
    )

    parser.add_argument(
        "--n-meters",
        type=int,
        default=1,
        help="NFStream n_meters value.",
    )

    parser.add_argument(
        "--max-packets",
        type=str,
        default=None,
        help="Optional max packets to read per PCAP with Scapy. <=0 means no limit.",
    )

    parser.add_argument(
        "--max-packets-per-flow",
        type=str,
        default="10000",
        help="Optional max packets stored per flow. <=0 means no limit.",
    )

    return parser


def main() -> None:
    """CLI entry point."""
    parser = build_arg_parser()
    args = parser.parse_args()

    max_packets = parse_optional_int(args.max_packets)
    max_packets_per_flow = parse_optional_int(args.max_packets_per_flow)

    if args.pcap is not None:
        label = args.label or infer_label_from_path(args.pcap)

        df = process_pcap(
            pcap_path=args.pcap,
            label=label,
            n_meters=args.n_meters,
            max_packets=max_packets,
            max_packets_per_flow=max_packets_per_flow,
        )

        args.output.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.output, index=False)

        print(f"Saved single-PCAP dataset: {args.output}")
        print("Shape:", df.shape)
        return

    process_directory(
        input_dir=args.input_dir,
        output_path=args.output,
        errors_output_path=args.errors_output,
        summary_output_path=args.summary_output,
        n_meters=args.n_meters,
        max_packets=max_packets,
        max_packets_per_flow=max_packets_per_flow,
    )


if __name__ == "__main__":
    main()

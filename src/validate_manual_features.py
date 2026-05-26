"""
Validate manual Scapy features on real normalized PCAP files.

This script samples packets from the normalized PCAP dataset, groups them into
simple bidirectional 5-tuple flows, applies src.manual_features, and writes a
small validation CSV.

This is not the final extraction pipeline. Its goal is only to verify that
manual feature functions work on real packets before they are integrated with
NFStream outputs.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

import pandas as pd
from scapy.all import PcapReader
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Allow running this file both ways:
#   python src/validate_manual_features.py
#   python -m src.validate_manual_features
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.manual_features import calc_manual_features  # noqa: E402


PCAP_DIR = PROJECT_ROOT / "data" / "interim" / "nfstream_compatible"
OUT_PATH = PROJECT_ROOT / "data" / "processed" / "manual_features_validation_sample.csv"


def infer_label_from_path(path: Path) -> str:
    """
    Infer a traffic label from a PCAP path.

    Args:
        path: PCAP file path.

    Returns:
        Traffic label inferred from directory or filename.
    """
    text = str(path).lower()

    for label in ["normal", "icmp_flood", "syn_scan", "udp_scan", "port_sweep"]:
        if label in text:
            return label

    return "unknown"


def get_ip_pair(packet: Packet) -> Optional[tuple[str, str]]:
    """
    Extract source and destination IPs from IPv4 or IPv6 packets.

    Args:
        packet: Scapy packet.

    Returns:
        Tuple (src_ip, dst_ip), or None if the packet has no IP layer.
    """
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None


def get_protocol_and_ports(packet: Packet) -> Optional[tuple[str, int, int]]:
    """
    Extract transport protocol and ports where available.

    Args:
        packet: Scapy packet.

    Returns:
        Tuple (protocol, src_port, dst_port). For ICMP, ports are set to 0.
        Returns None for unsupported non-IP packets.
    """
    if TCP in packet:
        return "TCP", int(packet[TCP].sport), int(packet[TCP].dport)

    if UDP in packet:
        return "UDP", int(packet[UDP].sport), int(packet[UDP].dport)

    if ICMP in packet:
        return "ICMP", 0, 0

    return None


def canonical_flow_key(packet: Packet) -> Optional[tuple]:
    """
    Build a simple bidirectional flow key.

    Args:
        packet: Scapy packet.

    Returns:
        Canonical bidirectional key based on protocol, IPs and ports.
        Returns None for unsupported packets.
    """
    ip_pair = get_ip_pair(packet)
    proto_ports = get_protocol_and_ports(packet)

    if ip_pair is None or proto_ports is None:
        return None

    src_ip, dst_ip = ip_pair
    protocol, src_port, dst_port = proto_ports

    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)

    low, high = sorted([endpoint_a, endpoint_b])

    return protocol, low, high


def collect_sample_flows(
    pcap_path: Path,
    max_packets: int = 100_000,
    max_packets_per_flow: int = 5_000,
) -> dict[tuple, list[Packet]]:
    """
    Collect a bounded set of packets grouped by bidirectional flow key.

    Args:
        pcap_path: Input PCAP path.
        max_packets: Maximum number of packets to read from the PCAP.
        max_packets_per_flow: Maximum packets stored per flow.

    Returns:
        Dictionary mapping flow keys to packet lists.
    """
    flows: dict[tuple, list[Packet]] = defaultdict(list)

    with PcapReader(str(pcap_path)) as reader:
        for idx, packet in enumerate(reader):
            if idx >= max_packets:
                break

            key = canonical_flow_key(packet)

            if key is None:
                continue

            if len(flows[key]) >= max_packets_per_flow:
                continue

            flows[key].append(packet)

    return flows


def validate_pcaps(max_flows_per_pcap: int = 200) -> pd.DataFrame:
    """
    Validate manual features on all normalized non-smoke PCAPs.

    Args:
        max_flows_per_pcap: Maximum sampled flows per PCAP.

    Returns:
        DataFrame with one row per sampled flow.
    """
    rows: list[dict] = []

    pcap_files = sorted(
        path
        for path in PCAP_DIR.rglob("*.pcap")
        if "smoke" not in path.name.lower()
    )

    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found under {PCAP_DIR}")

    for pcap_path in pcap_files:
        label = infer_label_from_path(pcap_path)

        print(f"Processing {pcap_path.relative_to(PROJECT_ROOT)} label={label}")

        flows = collect_sample_flows(pcap_path)

        print(f"  collected_flows={len(flows)}")

        for flow_idx, (flow_key, packets) in enumerate(flows.items()):
            if flow_idx >= max_flows_per_pcap:
                break

            features = calc_manual_features(packets)

            rows.append(
                {
                    "label": label,
                    "pcap_file": pcap_path.name,
                    "flow_key": str(flow_key),
                    "n_packets_sampled": len(packets),
                    **features,
                }
            )

    return pd.DataFrame(rows)


def main() -> None:
    """
    Run validation and save CSV output.
    """
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    df = validate_pcaps()
    df.to_csv(OUT_PATH, index=False)

    print(f"\nSaved: {OUT_PATH}")
    print("Shape:", df.shape)

    numeric_cols = [
        "iat_mean_ms",
        "iat_std_ms",
        "iat_cv",
        "rtt_estimate_ms",
        "tcp_window_mean",
        "tcp_window_var",
        "syn_ack_ratio_manual",
    ]

    available = [col for col in numeric_cols if col in df.columns]

    if available and not df.empty:
        print("\nSummary by label:")
        print(
            df.groupby("label")[available]
            .agg(["count", "mean", "median"])
            .round(4)
        )


if __name__ == "__main__":
    main()

"""
Manual packet-level feature extraction with Scapy.

This module complements NFStream flow features with low-level TCP/IP features
computed directly from packets:

- Inter-arrival time statistics.
- Estimated TCP RTT from a complete three-way handshake.
- TCP window size statistics.
- SYN/ACK ratio.

Each public function receives a list of Scapy packets belonging to one flow.
The functions are defensive by design: empty flows, non-TCP flows and incomplete
handshakes return NaN instead of raising exceptions.
"""

from __future__ import annotations

from math import isnan
from typing import Iterable

import numpy as np
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6


NAN = float("nan")

# TCP flag masks.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


def _nan_dict(keys: Iterable[str]) -> dict[str, float]:
    """
    Build a dictionary filled with NaN values.

    Args:
        keys: Output feature names.

    Returns:
        Dictionary mapping each key to NaN.
    """
    return {key: NAN for key in keys}


def _safe_time(packet: Packet) -> float:
    """
    Convert a Scapy packet timestamp into a Python float.

    Args:
        packet: Scapy packet.

    Returns:
        Timestamp as float seconds.
    """
    return float(packet.time)


def _sorted_packets(packets: list[Packet]) -> list[Packet]:
    """
    Sort packets by timestamp.

    Args:
        packets: List of Scapy packets.

    Returns:
        Packets sorted by capture timestamp.
    """
    return sorted(packets, key=_safe_time)


def _get_ip_layer(packet: Packet):
    """
    Return the IP or IPv6 layer from a packet.

    Args:
        packet: Scapy packet.

    Returns:
        IP layer, IPv6 layer, or None.
    """
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def _is_tcp(packet: Packet) -> bool:
    """
    Check whether a packet contains a TCP layer.

    Args:
        packet: Scapy packet.

    Returns:
        True if TCP is present, False otherwise.
    """
    return TCP in packet


def _tcp_flag_is_set(packet: Packet, flag_mask: int) -> bool:
    """
    Check whether a TCP flag is set.

    Args:
        packet: Scapy packet.
        flag_mask: Integer TCP flag mask.

    Returns:
        True if the flag is present, False otherwise.
    """
    if TCP not in packet:
        return False

    return bool(int(packet[TCP].flags) & flag_mask)


def _same_tcp_direction(
    packet: Packet,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bool:
    """
    Check whether a TCP packet matches a specific 4-tuple direction.

    Args:
        packet: Scapy packet.
        src_ip: Expected source IP.
        dst_ip: Expected destination IP.
        src_port: Expected source TCP port.
        dst_port: Expected destination TCP port.

    Returns:
        True if packet matches the direction, False otherwise.
    """
    ip_layer = _get_ip_layer(packet)

    if ip_layer is None or TCP not in packet:
        return False

    return (
        ip_layer.src == src_ip
        and ip_layer.dst == dst_ip
        and int(packet[TCP].sport) == src_port
        and int(packet[TCP].dport) == dst_port
    )


def calc_iat_stats(packets: list[Packet]) -> dict[str, float]:
    """
    Calculate packet inter-arrival time statistics for a flow.

    Args:
        packets: List of Scapy packets belonging to the same flow.

    Returns:
        Dictionary with:
            - iat_mean_ms: mean inter-arrival time in milliseconds.
            - iat_std_ms: standard deviation of inter-arrival time in milliseconds.
            - iat_cv: coefficient of variation, std / mean.

    Network rationale:
        IAT variability helps distinguish human/application traffic from floods
        or scans, which often generate packets with more mechanical timing.
    """
    keys = ["iat_mean_ms", "iat_std_ms", "iat_cv"]

    try:
        if packets is None or len(packets) < 2:
            return _nan_dict(keys)

        ordered = _sorted_packets(packets)
        timestamps = np.array([_safe_time(packet) for packet in ordered], dtype=float)

        diffs_ms = np.diff(timestamps) * 1000.0

        if diffs_ms.size == 0:
            return _nan_dict(keys)

        mean_ms = float(np.mean(diffs_ms))
        std_ms = float(np.std(diffs_ms, ddof=0))

        cv = float(std_ms / mean_ms) if mean_ms > 0 else NAN

        return {
            "iat_mean_ms": mean_ms,
            "iat_std_ms": std_ms,
            "iat_cv": cv,
        }

    except Exception:
        return _nan_dict(keys)


def calc_rtt_estimate(packets: list[Packet]) -> float:
    """
    Estimate TCP RTT from a complete three-way handshake.

    Args:
        packets: List of Scapy packets belonging to the same flow.

    Returns:
        Estimated RTT in milliseconds, calculated as:
            timestamp(SYN-ACK) - timestamp(SYN)

        Returns NaN if:
            - the flow is empty,
            - the flow is non-TCP,
            - no SYN -> SYN-ACK -> ACK sequence is found,
            - the candidate handshake is interrupted by RST before completion.

    Network rationale:
        A complete TCP handshake indicates legitimate session establishment,
        while SYN scans often stop with RST and therefore should not receive
        a fake RTT value of 0.
    """
    try:
        if packets is None or len(packets) == 0:
            return NAN

        ordered = [packet for packet in _sorted_packets(packets) if TCP in packet and _get_ip_layer(packet)]

        if not ordered:
            return NAN

        for syn_idx, syn_pkt in enumerate(ordered):
            is_syn = _tcp_flag_is_set(syn_pkt, TCP_SYN)
            is_ack = _tcp_flag_is_set(syn_pkt, TCP_ACK)

            # Initial SYN: SYN=1 and ACK=0.
            if not is_syn or is_ack:
                continue

            syn_ip = _get_ip_layer(syn_pkt)
            syn_tcp = syn_pkt[TCP]

            client_ip = syn_ip.src
            server_ip = syn_ip.dst
            client_port = int(syn_tcp.sport)
            server_port = int(syn_tcp.dport)
            syn_time = _safe_time(syn_pkt)

            synack_time = None
            synack_idx = None

            # Find SYN-ACK in the reverse direction.
            for candidate_idx in range(syn_idx + 1, len(ordered)):
                candidate = ordered[candidate_idx]

                if not _same_tcp_direction(
                    packet=candidate,
                    src_ip=server_ip,
                    dst_ip=client_ip,
                    src_port=server_port,
                    dst_port=client_port,
                ):
                    continue

                if _tcp_flag_is_set(candidate, TCP_SYN) and _tcp_flag_is_set(candidate, TCP_ACK):
                    synack_time = _safe_time(candidate)
                    synack_idx = candidate_idx
                    break

            if synack_time is None or synack_idx is None:
                continue

            # Require final ACK from client to server. If RST appears before that,
            # this is not a complete handshake and should return NaN.
            for ack_idx in range(synack_idx + 1, len(ordered)):
                candidate = ordered[ack_idx]

                if _same_tcp_direction(
                    packet=candidate,
                    src_ip=client_ip,
                    dst_ip=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                ):
                    if _tcp_flag_is_set(candidate, TCP_RST):
                        return NAN

                    if (
                        _tcp_flag_is_set(candidate, TCP_ACK)
                        and not _tcp_flag_is_set(candidate, TCP_SYN)
                    ):
                        rtt_ms = (synack_time - syn_time) * 1000.0
                        return float(rtt_ms) if rtt_ms >= 0 else NAN

            # SYN and SYN-ACK found, but no final ACK.
            return NAN

        return NAN

    except Exception:
        return NAN


def calc_window_stats(packets: list[Packet]) -> dict[str, float]:
    """
    Calculate TCP window size statistics for a flow.

    Args:
        packets: List of Scapy packets belonging to the same flow.

    Returns:
        Dictionary with:
            - tcp_window_min
            - tcp_window_max
            - tcp_window_mean
            - tcp_window_var

        Returns NaN values for non-TCP or empty flows.

    Network rationale:
        TCP window behavior reflects connection dynamics. Legitimate TCP
        sessions can show variable windows, while scanning tools often use
        small or fixed window values.
    """
    keys = [
        "tcp_window_min",
        "tcp_window_max",
        "tcp_window_mean",
        "tcp_window_var",
    ]

    try:
        if packets is None or len(packets) == 0:
            return _nan_dict(keys)

        windows = [
            int(packet[TCP].window)
            for packet in packets
            if TCP in packet
        ]

        if not windows:
            return _nan_dict(keys)

        arr = np.array(windows, dtype=float)

        return {
            "tcp_window_min": float(np.min(arr)),
            "tcp_window_max": float(np.max(arr)),
            "tcp_window_mean": float(np.mean(arr)),
            "tcp_window_var": float(np.var(arr, ddof=0)),
        }

    except Exception:
        return _nan_dict(keys)


def calc_syn_ack_ratio(packets: list[Packet]) -> float:
    """
    Calculate the TCP SYN/ACK packet ratio for a flow.

    Args:
        packets: List of Scapy packets belonging to the same flow.

    Returns:
        count(TCP packets with SYN flag) / count(TCP packets with ACK flag).

        Returns NaN if:
            - the flow is empty,
            - the flow has no TCP packets,
            - there are zero ACK packets.

    Network rationale:
        Abnormal SYN/ACK relationships indicate connection attempts that do not
        behave like normal established TCP sessions, which is useful for
        identifying reconnaissance traffic.
    """
    try:
        if packets is None or len(packets) == 0:
            return NAN

        tcp_packets = [packet for packet in packets if TCP in packet]

        if not tcp_packets:
            return NAN

        syn_count = sum(1 for packet in tcp_packets if _tcp_flag_is_set(packet, TCP_SYN))
        ack_count = sum(1 for packet in tcp_packets if _tcp_flag_is_set(packet, TCP_ACK))

        if ack_count == 0:
            return NAN

        return float(syn_count / ack_count)

    except Exception:
        return NAN


def calc_manual_features(packets: list[Packet]) -> dict[str, float]:
    """
    Calculate all manual packet-level features for a flow.

    Args:
        packets: List of Scapy packets belonging to the same flow.

    Returns:
        Dictionary with IAT, RTT, TCP window and SYN/ACK ratio features.

    Network rationale:
        Combining timing, handshake, TCP window and flag behavior gives a more
        protocol-aware description than aggregate byte/packet counters alone.
    """
    features: dict[str, float] = {}

    features.update(calc_iat_stats(packets))
    features["rtt_estimate_ms"] = calc_rtt_estimate(packets)
    features.update(calc_window_stats(packets))
    features["syn_ack_ratio_manual"] = calc_syn_ack_ratio(packets)

    return features


def is_nan(value: float) -> bool:
    """
    Check whether a float value is NaN.

    Args:
        value: Float value.

    Returns:
        True if value is NaN, False otherwise.
    """
    try:
        return isnan(value)
    except TypeError:
        return False

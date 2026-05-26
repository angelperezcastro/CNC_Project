"""
Unit tests for src.manual_features.

These tests use synthetic Scapy packets so that the expected values are
deterministic and independent from the captured dataset.
"""

import math

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP

from src.manual_features import (
    calc_iat_stats,
    calc_rtt_estimate,
    calc_window_stats,
    calc_syn_ack_ratio,
    calc_manual_features,
)


def with_time(packet, timestamp):
    """Attach a deterministic timestamp to a Scapy packet."""
    packet.time = timestamp
    return packet


def test_calc_iat_stats_three_packets():
    packets = [
        with_time(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), 1.0),
        with_time(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), 1.1),
        with_time(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), 1.3),
    ]

    result = calc_iat_stats(packets)

    assert result["iat_mean_ms"] == pytest.approx(150.0)
    assert result["iat_std_ms"] == pytest.approx(50.0)
    assert result["iat_cv"] == pytest.approx(50.0 / 150.0)


def test_calc_iat_stats_empty_flow_returns_nan():
    result = calc_iat_stats([])

    assert math.isnan(result["iat_mean_ms"])
    assert math.isnan(result["iat_std_ms"])
    assert math.isnan(result["iat_cv"])


def test_calc_rtt_estimate_complete_handshake():
    packets = [
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="S"),
            1.0000,
        ),
        with_time(
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=12345, flags="SA"),
            1.0004,
        ),
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="A"),
            1.0008,
        ),
    ]

    rtt = calc_rtt_estimate(packets)

    assert rtt == pytest.approx(0.4)


def test_calc_rtt_estimate_syn_scan_rst_returns_nan():
    packets = [
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="S"),
            1.0000,
        ),
        with_time(
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=12345, flags="SA"),
            1.0004,
        ),
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="R"),
            1.0008,
        ),
    ]

    rtt = calc_rtt_estimate(packets)

    assert math.isnan(rtt)


def test_calc_rtt_estimate_non_tcp_returns_nan():
    packets = [
        with_time(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), 1.0)
    ]

    rtt = calc_rtt_estimate(packets)

    assert math.isnan(rtt)


def test_calc_window_stats_tcp_packets():
    packets = [
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1111, dport=80, flags="S", window=1024),
            1.0,
        ),
        with_time(
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=1111, flags="SA", window=2048),
            1.1,
        ),
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1111, dport=80, flags="A", window=4096),
            1.2,
        ),
    ]

    result = calc_window_stats(packets)

    assert result["tcp_window_min"] == pytest.approx(1024)
    assert result["tcp_window_max"] == pytest.approx(4096)
    assert result["tcp_window_mean"] == pytest.approx((1024 + 2048 + 4096) / 3)
    assert result["tcp_window_var"] >= 0


def test_calc_window_stats_non_tcp_returns_nan():
    packets = [
        with_time(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), 1.0)
    ]

    result = calc_window_stats(packets)

    assert math.isnan(result["tcp_window_min"])
    assert math.isnan(result["tcp_window_max"])
    assert math.isnan(result["tcp_window_mean"])
    assert math.isnan(result["tcp_window_var"])


def test_calc_syn_ack_ratio():
    packets = [
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1000, dport=80, flags="S"),
            1.0,
        ),
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1001, dport=80, flags="S"),
            1.1,
        ),
        with_time(
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=1000, flags="A"),
            1.2,
        ),
    ]

    ratio = calc_syn_ack_ratio(packets)

    assert ratio == pytest.approx(2.0)


def test_calc_syn_ack_ratio_non_tcp_returns_nan():
    packets = [
        with_time(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), 1.0)
    ]

    ratio = calc_syn_ack_ratio(packets)

    assert math.isnan(ratio)


def test_calc_manual_features_contains_all_keys():
    packets = [
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="S", window=1024),
            1.0000,
        ),
        with_time(
            IP(src="10.0.0.2", dst="10.0.0.1")
            / TCP(sport=80, dport=12345, flags="SA", window=2048),
            1.0004,
        ),
        with_time(
            IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=12345, dport=80, flags="A", window=4096),
            1.0008,
        ),
    ]

    features = calc_manual_features(packets)

    expected_keys = {
        "iat_mean_ms",
        "iat_std_ms",
        "iat_cv",
        "rtt_estimate_ms",
        "tcp_window_min",
        "tcp_window_max",
        "tcp_window_mean",
        "tcp_window_var",
        "syn_ack_ratio_manual",
    }

    assert expected_keys.issubset(features.keys())

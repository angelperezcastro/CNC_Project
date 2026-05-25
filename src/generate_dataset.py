"""
Dataset generation orchestrator for the CNC Project / NetFlow Analyzer.

This script automates traffic generation and packet capture for each traffic
class. It creates one PCAP per label under data/raw/<label>/ and writes a
dataset statistics report to docs/dataset_stats.md.

Safety:
    The script only uses the local Docker lab targets: server, attacker, client
    and the subnet 172.20.0.0/24.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

from capture import start_capture, stop_capture, run_command


RAW_DIR = Path("data/raw")
DOCS_DIR = Path("docs")

DEFAULT_LABELS = [
    "normal",
    "icmp_flood",
    "syn_scan",
    "udp_scan",
    "port_sweep",
]

CAPTURE_CONTAINER_BY_LABEL = {
    "normal": "server",
    "icmp_flood": "attacker",
    "syn_scan": "attacker",
    "udp_scan": "attacker",
    "port_sweep": "attacker",
}


def ensure_dataset_directories(labels: list[str]) -> None:
    """
    Create data/raw/<label> directories and .gitkeep files.

    Args:
        labels: Traffic labels to prepare.

    Returns:
        None.
    """
    for label in labels:
        label_dir = RAW_DIR / label
        label_dir.mkdir(parents=True, exist_ok=True)
        (label_dir / ".gitkeep").touch()


def run_compose_up() -> None:
    """
    Ensure the Docker lab is running.

    Returns:
        None.
    """
    run_command(["docker", "compose", "up", "-d", "--build"])


def run_normal_traffic(duration_seconds: int) -> None:
    """
    Generate legitimate traffic from the client container.

    Args:
        duration_seconds: Traffic generation duration in seconds.

    Returns:
        None.
    """
    run_command(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "client",
            "generate_normal.sh",
            str(duration_seconds),
        ],
        check=True,
    )


def run_repeated_attack(label: str, duration_seconds: int) -> None:
    """
    Generate attack traffic repeatedly during the capture window.

    Args:
        label: Attack label.
        duration_seconds: Total generation duration in seconds.

    Returns:
        None.
    """
    end_time = time.monotonic() + duration_seconds

    if label == "icmp_flood":
        # A continuous 10-minute hping3 flood can create enormous PCAP files.
        # Controlled bursts keep the dataset useful without producing multi-GB captures.
        command = ["docker", "compose", "exec", "-T", "attacker", "generate_attack.sh", "icmp_flood", "server", "1"]
        interval_seconds = 20

    elif label == "syn_scan":
        command = ["docker", "compose", "exec", "-T", "attacker", "generate_attack.sh", "syn_scan", "server"]
        interval_seconds = 10

    elif label == "udp_scan":
        command = ["docker", "compose", "exec", "-T", "attacker", "generate_attack.sh", "udp_scan", "server"]
        interval_seconds = 30

    elif label == "port_sweep":
        command = ["docker", "compose", "exec", "-T", "attacker", "generate_attack.sh", "port_sweep"]
        interval_seconds = 15

    else:
        raise ValueError(f"Unsupported attack label: {label}")

    iteration = 0

    while time.monotonic() < end_time:
        iteration += 1
        print(f"[dataset] Running {label} iteration {iteration}")
        start = time.monotonic()

        run_command(command, check=False)

        elapsed = time.monotonic() - start
        sleep_time = max(0, interval_seconds - elapsed)
        remaining = max(0, end_time - time.monotonic())

        if remaining <= 0:
            break

        time.sleep(min(sleep_time, remaining))


def generate_label_capture(label: str, duration_seconds: int, tag: str) -> Path:
    """
    Generate one labeled PCAP file.

    Args:
        label: Traffic label.
        duration_seconds: Capture/generation duration in seconds.
        tag: Suffix used in the output filename.

    Returns:
        Path to the generated PCAP.
    """
    if label not in DEFAULT_LABELS:
        raise ValueError(f"Unsupported label: {label}")

    capture_container = CAPTURE_CONTAINER_BY_LABEL[label]
    output_path = RAW_DIR / label / f"{label}_{tag}.pcap"

    print("=" * 80)
    print(f"[dataset] Generating label: {label}")
    print(f"[dataset] Capture container: {capture_container}")
    print(f"[dataset] Output: {output_path}")
    print(f"[dataset] Duration: {duration_seconds}s")
    print("=" * 80)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    start_capture(container=capture_container, output_path=output_path)

    try:
        time.sleep(2)

        if label == "normal":
            run_normal_traffic(duration_seconds)
        else:
            run_repeated_attack(label, duration_seconds)

    finally:
        stop_capture(container=capture_container)

    if not output_path.exists() or output_path.stat().st_size == 0:
        raise RuntimeError(f"Generated PCAP is missing or empty: {output_path}")

    print(f"[dataset] Generated PCAP: {output_path} ({output_path.stat().st_size} bytes)")
    return output_path


def parse_capinfos_text(text: str) -> dict[str, str]:
    """
    Parse relevant fields from capinfos output.

    Args:
        text: Raw capinfos output.

    Returns:
        Dictionary with parsed fields.
    """
    packets = "unknown"
    duration = "unknown"

    for line in text.splitlines():
        lowered = line.lower()

        if lowered.startswith("number of packets:"):
            packets = line.split(":", 1)[1].strip()

        elif lowered.startswith("capture duration:"):
            duration = line.split(":", 1)[1].strip()

    return {
        "packets": packets,
        "duration": duration,
    }


def get_capinfos(pcap_path: Path) -> dict[str, str]:
    """
    Read packet count and duration using capinfos.

    Args:
        pcap_path: PCAP file path.

    Returns:
        Dictionary with file size, packet count and duration.
    """
    result = subprocess.run(
        ["capinfos", str(pcap_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    info = {
        "size": f"{pcap_path.stat().st_size / (1024 * 1024):.2f} MB",
        "packets": "unknown",
        "duration": "unknown",
    }

    if result.returncode == 0:
        info.update(parse_capinfos_text(result.stdout))
    else:
        info["duration"] = "capinfos failed"
        info["packets"] = "capinfos failed"

    return info


def write_dataset_stats(labels: list[str]) -> None:
    """
    Generate docs/dataset_stats.md from all PCAPs in data/raw/<label>/.

    Args:
        labels: Labels to include in the report.

    Returns:
        None.
    """
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, Path, dict[str, str]]] = []

    for label in labels:
        label_dir = RAW_DIR / label
        for pcap in sorted(label_dir.glob("*.pcap")):
            rows.append((label, pcap, get_capinfos(pcap)))

    lines = [
        "# Dataset Statistics",
        "",
        "## Objective",
        "",
        "Summarize the raw PCAP files generated for the NetFlow Analyzer dataset.",
        "",
        "Raw PCAP files are intentionally ignored by Git. This document records their",
        "local existence, size, packet count and capture duration.",
        "",
        "## PCAP Summary",
        "",
        "| Label | PCAP file | Size | Packets | Duration |",
        "|---|---|---:|---:|---|",
    ]

    if not rows:
        lines.append("| _No PCAPs found_ | - | - | - | - |")
    else:
        for label, pcap, info in rows:
            lines.append(
                f"| {label} | `{pcap.as_posix()}` | {info['size']} | "
                f"{info['packets']} | {info['duration']} |"
            )

    lines.extend(
        [
            "",
            "## Labels",
            "",
            "- `normal`: legitimate HTTP, FTP and DNS traffic.",
            "- `icmp_flood`: high-rate ICMP echo traffic.",
            "- `syn_scan`: TCP SYN scan against the server.",
            "- `udp_scan`: UDP scan against the server.",
            "- `port_sweep`: host discovery over the Docker lab subnet.",
            "",
            "## Notes",
            "",
            "The dataset is generated in an isolated Docker bridge network.",
            "The normal traffic class is intentionally heterogeneous, while the attack",
            "classes are generated separately to simplify labeling and later feature analysis.",
            "",
        ]
    )

    output = DOCS_DIR / "dataset_stats.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"[dataset] Wrote {output}")


def main() -> int:
    """
    CLI entrypoint.

    Examples:
        python src/generate_dataset.py --duration 60 --tag smoke --labels normal syn_scan
        python src/generate_dataset.py --duration 600
        python src/generate_dataset.py --stats-only
    """
    parser = argparse.ArgumentParser(description="Generate labeled PCAP dataset.")
    parser.add_argument(
        "--duration",
        type=int,
        default=600,
        help="Duration per label in seconds. Default: 600.",
    )
    parser.add_argument(
        "--labels",
        nargs="+",
        default=DEFAULT_LABELS,
        choices=DEFAULT_LABELS,
        help="Labels to generate.",
    )
    parser.add_argument(
        "--tag",
        default=datetime.now().strftime("%Y%m%d_%H%M%S"),
        help="Filename tag for generated PCAPs.",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Only regenerate docs/dataset_stats.md from existing PCAPs.",
    )

    args = parser.parse_args()

    ensure_dataset_directories(args.labels)

    if not args.stats_only:
        run_compose_up()

        for label in args.labels:
            generate_label_capture(
                label=label,
                duration_seconds=args.duration,
                tag=args.tag,
            )

    write_dataset_stats(args.labels)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

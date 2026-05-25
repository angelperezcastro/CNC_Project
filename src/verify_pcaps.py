"""
PCAP integrity verification script for the CNC Project / NetFlow Analyzer.

This script scans data/raw recursively, validates every PCAP file with capinfos,
checks that tshark can read it, and writes a Markdown report to
docs/pcap_integrity_report.md.

Run:
    python src/verify_pcaps.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path


RAW_DIR = Path("data/raw")
DOCS_DIR = Path("docs")
OUTPUT_REPORT = DOCS_DIR / "pcap_integrity_report.md"


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    """
    Run a command and capture its output.

    Args:
        command: Command and arguments.

    Returns:
        CompletedProcess with stdout/stderr as text.
    """
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def parse_capinfos_output(output: str) -> dict[str, str]:
    """
    Extract relevant metadata from capinfos output.

    Args:
        output: Raw capinfos output.

    Returns:
        Dictionary with packet count, duration and file type.
    """
    info = {
        "file_type": "unknown",
        "packets": "unknown",
        "duration": "unknown",
        "data_size": "unknown",
    }

    for line in output.splitlines():
        lowered = line.lower()

        if lowered.startswith("file type:"):
            info["file_type"] = line.split(":", 1)[1].strip()

        elif lowered.startswith("number of packets:"):
            info["packets"] = line.split(":", 1)[1].strip()

        elif lowered.startswith("capture duration:"):
            info["duration"] = line.split(":", 1)[1].strip()

        elif lowered.startswith("data size:"):
            info["data_size"] = line.split(":", 1)[1].strip()

    return info


def verify_with_tshark(pcap_path: Path) -> bool:
    """
    Check whether tshark can read at least one packet from the PCAP.

    Args:
        pcap_path: PCAP file path.

    Returns:
        True if tshark can read the file, False otherwise.
    """
    result = run_command(["tshark", "-r", str(pcap_path), "-c", "1"])
    return result.returncode == 0


def detect_label(pcap_path: Path) -> str:
    """
    Infer the label from the data/raw subdirectory.

    Args:
        pcap_path: PCAP file path.

    Returns:
        Label name or 'unorganized' if the file is directly under data/raw.
    """
    try:
        relative = pcap_path.relative_to(RAW_DIR)
    except ValueError:
        return "unknown"

    if len(relative.parts) >= 2:
        return relative.parts[0]

    return "unorganized"


def main() -> int:
    """
    Verify all PCAP files and write a Markdown report.

    Returns:
        Exit code 0 if all PCAPs are valid, 1 otherwise.
    """
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    pcaps = sorted(RAW_DIR.rglob("*.pcap"))

    lines = [
        "# PCAP Integrity Report",
        "",
        "## Objective",
        "",
        "Verify that all local PCAP files can be read correctly by Wireshark command-line tools.",
        "",
        "Raw PCAP files are intentionally ignored by Git, but their integrity is documented here.",
        "",
        "## Summary",
        "",
        f"- Total PCAP files found: {len(pcaps)}",
        "",
        "## PCAP Files",
        "",
        "| Label | File | Size | capinfos | tshark readable | Packets | Duration | Type |",
        "|---|---|---:|---|---|---:|---|---|",
    ]

    all_ok = True

    if not pcaps:
        lines.append("| - | No PCAP files found | - | FAIL | FAIL | - | - | - |")
        all_ok = False
    else:
        for pcap in pcaps:
            size_mb = pcap.stat().st_size / (1024 * 1024)
            label = detect_label(pcap)

            capinfos_result = run_command(["capinfos", str(pcap)])
            capinfos_ok = capinfos_result.returncode == 0
            tshark_ok = verify_with_tshark(pcap)

            if capinfos_ok:
                info = parse_capinfos_output(capinfos_result.stdout)
            else:
                info = {
                    "file_type": "unreadable",
                    "packets": "unknown",
                    "duration": "unknown",
                    "data_size": "unknown",
                }

            if not capinfos_ok or not tshark_ok:
                all_ok = False

            lines.append(
                f"| {label} | `{pcap.as_posix()}` | {size_mb:.2f} MB | "
                f"{'OK' if capinfos_ok else 'FAIL'} | "
                f"{'OK' if tshark_ok else 'FAIL'} | "
                f"{info['packets']} | {info['duration']} | {info['file_type']} |"
            )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `capinfos = OK` means the file metadata can be read correctly.",
            "- `tshark readable = OK` means packet data can be parsed.",
            "- PCAP files should not be committed to Git because they can be large and may contain sensitive traffic.",
            "",
        ]
    )

    OUTPUT_REPORT.write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] Wrote {OUTPUT_REPORT}")

    if all_ok:
        print("[SUCCESS] All PCAP files are readable.")
        return 0

    print("[ERROR] Some PCAP files failed validation.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

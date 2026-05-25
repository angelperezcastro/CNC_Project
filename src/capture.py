"""
PCAP capture utilities for the CNC Project / NetFlow Analyzer.

This module starts and stops tcpdump inside a Docker container and stores the
resulting PCAP file in the host-mounted data/raw directory.

Design decision:
    Capturing inside Docker containers is more reliable than capturing from
    Windows Wireshark when using Docker Desktop + WSL2, because internal bridge
    traffic is not always visible from the Windows host interfaces.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path


PROJECT_RAW_DIR = Path("data/raw")


class CaptureError(RuntimeError):
    """Raised when a packet capture operation fails."""


def run_command(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    """
    Run a shell command using subprocess.

    Args:
        command: Command and arguments as a list.
        check: Whether to raise an exception on non-zero exit code.

    Returns:
        CompletedProcess object with stdout and stderr captured as text.
    """
    print(f"$ {' '.join(command)}")

    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if result.stdout:
        print(result.stdout, end="")

    if result.stderr:
        print(result.stderr, end="")

    if check and result.returncode != 0:
        raise CaptureError(
            f"Command failed with exit code {result.returncode}: {' '.join(command)}"
        )

    return result


def ensure_output_inside_raw(output_path: Path) -> Path:
    """
    Validate that the output PCAP is stored inside data/raw.

    Args:
        output_path: Host-side PCAP path.

    Returns:
        Normalized output path.

    Raises:
        CaptureError: If the output path is outside data/raw.
    """
    output_path = output_path.as_posix()
    normalized = Path(output_path)

    if not normalized.as_posix().startswith("data/raw/"):
        raise CaptureError(
            "Output PCAP must be stored inside data/raw/, "
            f"got: {normalized}"
        )

    return normalized


def host_path_to_container_capture_path(output_path: Path) -> str:
    """
    Convert a host-side data/raw path to the corresponding /captures path.

    Args:
        output_path: Host-side path such as data/raw/normal/file.pcap.

    Returns:
        Container-side path such as /captures/normal/file.pcap.
    """
    output_path = ensure_output_inside_raw(output_path)
    relative = output_path.relative_to(PROJECT_RAW_DIR)
    return f"/captures/{relative.as_posix()}"


def start_capture(container: str, output_path: Path, interface: str = "any") -> None:
    """
    Start tcpdump in detached mode inside a Docker container.

    Args:
        container: Docker Compose service name or container name.
        output_path: Host-side output PCAP path under data/raw.
        interface: Network interface used by tcpdump. Default 'any'.

    Returns:
        None.
    """
    output_path = ensure_output_inside_raw(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    container_output = host_path_to_container_capture_path(output_path)
    container_parent = str(Path(container_output).parent)

    command = (
        f"mkdir -p {container_parent} && "
        f"rm -f {container_output} && "
        f"tcpdump -i {interface} -U -w {container_output}"
    )

    run_command(
        ["docker", "compose", "exec", "-d", container, "bash", "-lc", command]
    )


def stop_capture(container: str) -> None:
    """
    Stop tcpdump inside a Docker container.

    Args:
        container: Docker Compose service name or container name.

    Returns:
        None.
    """
    run_command(
        [
            "docker",
            "compose",
            "exec",
            container,
            "bash",
            "-lc",
            "pkill -2 tcpdump || pkill tcpdump || true",
        ],
        check=False,
    )

    # Give tcpdump a moment to flush the PCAP footer.
    time.sleep(2)


def capture_for_duration(container: str, output_path: Path, duration_seconds: int) -> None:
    """
    Capture packets for a fixed duration.

    Args:
        container: Docker Compose service/container where tcpdump runs.
        output_path: Host-side output PCAP path under data/raw.
        duration_seconds: Capture duration in seconds.

    Returns:
        None.
    """
    print(
        f"[capture] Starting capture in container={container}, "
        f"output={output_path}, duration={duration_seconds}s"
    )

    start_capture(container=container, output_path=output_path)

    try:
        time.sleep(duration_seconds)
    finally:
        print("[capture] Stopping capture...")
        stop_capture(container=container)

    if not output_path.exists() or output_path.stat().st_size == 0:
        raise CaptureError(f"Capture failed or empty PCAP: {output_path}")

    print(f"[capture] PCAP created: {output_path} ({output_path.stat().st_size} bytes)")


def main() -> int:
    """
    CLI entrypoint for standalone captures.

    Example:
        python src/capture.py --container server --output data/raw/test.pcap --duration 30
    """
    parser = argparse.ArgumentParser(description="Capture PCAPs from Docker containers.")
    parser.add_argument("--container", required=True, help="Docker Compose service/container.")
    parser.add_argument("--output", required=True, help="Output PCAP path under data/raw.")
    parser.add_argument("--duration", type=int, required=True, help="Capture duration in seconds.")
    args = parser.parse_args()

    capture_for_duration(
        container=args.container,
        output_path=Path(args.output),
        duration_seconds=args.duration,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

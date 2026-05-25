"""
Environment verification script for CNC Project / NetFlow Analyzer.

This script checks that the main Python packages and external tools required
for the project are available in the current WSL environment.

Run:
    python src/check_environment.py
"""

from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version


PYTHON_PACKAGES = {
    "pyshark": "pyshark",
    "scapy": "scapy",
    "pandas": "pandas",
    "numpy": "numpy",
    "nfstream": "nfstream",
    "sklearn": "scikit-learn",
    "plotly": "plotly",
    "streamlit": "streamlit",
    "joblib": "joblib",
    "imblearn": "imbalanced-learn",
}

EXTERNAL_COMMANDS = ["tshark", "docker", "git"]


def check_python_package(import_name: str, package_name: str) -> bool:
    """
    Check whether a Python package can be imported.

    Args:
        import_name: Name used in the import statement.
        package_name: Name used by pip/importlib.metadata.

    Returns:
        True if the package can be imported, False otherwise.
    """
    try:
        importlib.import_module(import_name)

        try:
            package_version = version(package_name)
        except PackageNotFoundError:
            package_version = "installed, version unknown"

        print(f"[OK] Python package: {import_name} ({package_version})")
        return True

    except Exception as exc:
        print(f"[FAIL] Python package: {import_name} -> {exc}")
        return False


def check_external_command(command: str) -> bool:
    """
    Check whether an external command is available in PATH.

    Args:
        command: Command name to locate.

    Returns:
        True if the command exists and can be executed, False otherwise.
    """
    path = shutil.which(command)

    if path is None:
        print(f"[FAIL] External command not found: {command}")
        return False

    try:
        result = subprocess.run(
            [command, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        output = result.stdout or result.stderr
        first_line = output.splitlines()[0] if output else "version output unavailable"

        print(f"[OK] External command: {command} -> {first_line}")
        return True

    except Exception as exc:
        print(f"[FAIL] External command: {command} -> {exc}")
        return False


def main() -> int:
    """
    Run all environment checks.

    Returns:
        Exit code 0 if all checks pass, 1 otherwise.
    """
    print("=== CNC Project / NetFlow Analyzer environment check ===")
    print(f"Python executable: {sys.executable}")
    print(f"Python version: {sys.version.split()[0]}")
    print()

    package_results = [
        check_python_package(import_name, package_name)
        for import_name, package_name in PYTHON_PACKAGES.items()
    ]

    print()

    command_results = [
        check_external_command(command)
        for command in EXTERNAL_COMMANDS
    ]

    print()

    all_ok = all(package_results) and all(command_results)

    if all_ok:
        print("[SUCCESS] Environment is ready for Day 2.")
        return 0

    print("[ERROR] Some checks failed. Review the messages above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

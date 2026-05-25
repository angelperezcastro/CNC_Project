"""
Normalize Docker/WSL PCAP files into Ethernet/IP PCAPs compatible with NFStream.

Some captures made from Docker or WSL interfaces use Linux cooked capture v2
(LINUX_SLL2). tcpdump and Wireshark can read them, but NFStream may fail to
extract flows from that link-layer format.

This script preserves:
- original timestamps
- IP / IPv6 layer
- TCP / UDP / ICMP headers
- transport payload lengths

It replaces only the layer-2 header with a synthetic Ethernet header.

This is acceptable for this project because the feature engineering stage uses
L3/L4 features only, not MAC addresses or Ethernet-layer fields.
"""

from pathlib import Path

from scapy.all import Ether, IP, IPv6, PcapReader, PcapWriter


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUT_DIR = PROJECT_ROOT / "data" / "interim" / "nfstream_compatible"


def normalize_pcap_for_nfstream(src_path: Path, dst_path: Path) -> tuple[int, int]:
    """
    Convert a PCAP into an Ethernet/IP PCAP readable by NFStream.

    Args:
        src_path: Original PCAP file.
        dst_path: Output normalized PCAP file.

    Returns:
        Tuple containing:
            - packets_read: total packets read from the original PCAP.
            - packets_written: IP/IPv6 packets written to the normalized PCAP.

    Network rationale:
        NFStream reconstructs flows from L3/L4 information. Since this project
        does not use Ethernet-layer features, replacing the L2 header does not
        affect the selected ML features.
    """
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    packets_read = 0
    packets_written = 0

    writer = PcapWriter(str(dst_path), sync=True)

    try:
        with PcapReader(str(src_path)) as reader:
            for pkt in reader:
                packets_read += 1

                if IP in pkt:
                    normalized_pkt = (
                        Ether(
                            src="02:00:00:00:00:01",
                            dst="02:00:00:00:00:02",
                            type=0x0800,
                        )
                        / pkt[IP]
                    )

                elif IPv6 in pkt:
                    normalized_pkt = (
                        Ether(
                            src="02:00:00:00:00:01",
                            dst="02:00:00:00:00:02",
                            type=0x86DD,
                        )
                        / pkt[IPv6]
                    )

                else:
                    # ARP and non-IP packets are ignored because the project
                    # focuses on IP/TCP/UDP/ICMP flow features.
                    continue

                normalized_pkt.time = pkt.time
                writer.write(normalized_pkt)
                packets_written += 1

    finally:
        writer.close()

    return packets_read, packets_written


def main() -> None:
    """Normalize every .pcap file under data/raw."""
    pcap_files = sorted(RAW_DIR.rglob("*.pcap"))

    if not pcap_files:
        raise FileNotFoundError(f"No PCAP files found under {RAW_DIR}")

    print(f"Found {len(pcap_files)} PCAP files")

    for src_path in pcap_files:
        relative_path = src_path.relative_to(RAW_DIR)
        dst_path = OUT_DIR / relative_path

        packets_read, packets_written = normalize_pcap_for_nfstream(
            src_path=src_path,
            dst_path=dst_path,
        )

        print(
            f"[OK] {relative_path} | "
            f"read={packets_read} | "
            f"written_ip_packets={packets_written} | "
            f"output={dst_path.relative_to(PROJECT_ROOT)}"
        )

        if packets_written == 0:
            print(f"  WARNING: no IP/IPv6 packets written for {relative_path}")


if __name__ == "__main__":
    main()

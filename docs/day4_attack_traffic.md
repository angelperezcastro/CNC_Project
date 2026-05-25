# Day 4 Attack Traffic Generation

## Objective

Generate and capture four types of anomalous traffic inside the isolated Docker lab:

- ICMP flood
- TCP SYN scan
- UDP scan
- Port sweep / host discovery

Each attack is generated independently and stored in a separate PCAP file.

## Lab Scope

All traffic is generated only inside the Docker lab network:

- server: 172.20.0.10
- client: 172.20.0.20
- attacker: 172.20.0.30
- subnet: 172.20.0.0/24

The attack generator refuses to run against non-lab targets.

## Output PCAP Files

The generated attack PCAP files are:

    data/raw/icmp_flood.pcap
    data/raw/syn_scan.pcap
    data/raw/udp_scan.pcap
    data/raw/port_sweep.pcap

These files are ignored by Git because raw packet captures can be large and may contain sensitive data.

## Attack Modules

| Module | Tool | Main command | Expected pattern |
|---|---|---|---|
| icmp_flood | hping3 | hping3 -1 --flood server | High-rate ICMP echo requests |
| syn_scan | nmap | nmap -sS -p 1-1000 server | Many TCP SYN packets to different ports |
| udp_scan | nmap | nmap -sU -p 1-500 server | UDP probes and possible ICMP unreachable replies |
| port_sweep | nmap | nmap -sn 172.20.0.0/24 | Host discovery across multiple IPs |

## Wireshark Filters

ICMP flood:

    ip.src == 172.20.0.30 and icmp

TCP SYN scan:

    ip.src == 172.20.0.30 and tcp.flags.syn == 1 and tcp.flags.ack == 0

UDP scan:

    udp and ip.src == 172.20.0.30

ICMP unreachable responses during UDP scan:

    icmp.type == 3

Port sweep:

    arp or icmp

## Technical Notes

### ICMP flood

ICMP is connectionless and does not perform a transport-layer handshake. In the capture, the flood appears as many small ICMP echo requests sent at a very high rate.

### TCP SYN scan

A SYN scan sends TCP SYN packets to many ports without establishing normal application-level sessions. This creates short flows with many SYN packets and very little payload.

### UDP scan

UDP has no handshake. UDP scans send probes to multiple destination ports and may trigger ICMP Destination Unreachable responses for closed ports.

### Port sweep

The port sweep / host discovery phase searches for active hosts in the Docker subnet. Unlike a port scan against one host, this traffic is distributed across multiple destination IP addresses.

## Report Notes

These attack captures should be compared against the normal traffic PCAP from Day 3. The expected differences are:

- ICMP flood: high packet rate and very regular packet timing.
- SYN scan: many SYN packets, many destination ports, short-lived flows.
- UDP scan: UDP probes and ICMP unreachable replies, no TCP handshake.
- Port sweep: multiple destination IPs within the subnet.

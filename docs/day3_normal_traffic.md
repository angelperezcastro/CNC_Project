# Day 3 Normal Traffic Generation

## Objective

Generate and capture legitimate network traffic inside the Docker lab.

The generated traffic includes:

- HTTP GET requests with different object sizes.
- HTTP POST requests with JSON payloads.
- FTP uploads using files of 1 MB, 10 MB and 50 MB.
- DNS queries against the internal DNS service.

## Output PCAP

The labeled PCAP generated on this day is:

    data/raw/normal_http_ftp.pcap

This PCAP is intentionally ignored by Git because raw packet captures can be large and may contain sensitive information.

## Traffic Sources

- client: 172.20.0.20
- server: 172.20.0.10

## Generated Traffic Types

| Traffic type | Protocol | Expected behavior | Typical flow characteristics |
|---|---|---|---|
| Small HTTP GET | TCP/HTTP | Short web request | Short duration, low bytes |
| Medium/Large HTTP GET | TCP/HTTP | Static file download | More packets and bytes than small GET |
| HTTP POST | TCP/HTTP | JSON payload upload | Bidirectional request/response |
| FTP 1 MB | TCP/FTP | Small file transfer | Longer than HTTP small GET |
| FTP 10 MB | TCP/FTP | Medium file transfer | Higher byte count, longer flow |
| FTP 50 MB | TCP/FTP | Large file transfer | Long-lived, high-volume flow |
| DNS query | UDP/DNS | Internal name resolution | Very short request/response |

## Wireshark Filters

The following filters were used to verify the capture:

    ip.addr == 172.20.0.10
    http or tcp.port == 80
    ftp or tcp.port == 21
    tcp.port >= 30000 and tcp.port <= 30009
    dns

## Technical Decisions

### Traffic variety

Normal traffic must not consist only of identical HTTP requests. The generator mixes small HTTP requests, larger downloads, POST requests, FTP transfers and DNS queries. This produces flows with different durations, packet counts and byte volumes.

### FTP file sizes

FTP transfers of 1 MB, 10 MB and 50 MB are included to generate longer-lived flows. These flows are useful for distinguishing legitimate data transfer from scan traffic, which is usually short and low-volume.

### Internal DNS

The server runs an internal DNS service with dnsmasq. This allows the client to generate visible DNS traffic inside the Docker network without depending on Internet access.

### Capture location

The PCAP is captured from the server container using tcpdump. This is reliable in Windows 11 + WSL2 + Docker Desktop because host-level Wireshark may not always see internal Docker bridge traffic directly.

## Notes for the Report

The most important observation is that legitimate traffic is heterogeneous:

- HTTP small requests are short and low-volume.
- HTTP downloads and FTP transfers produce larger TCP flows.
- FTP uses a control channel on TCP/21 and passive data channels on TCP/30000-30009.
- DNS traffic is short and UDP-based.
- This variability makes the normal class broader and more realistic for later machine learning.

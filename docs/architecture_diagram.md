# Architecture Diagram

## Docker Lab and Data Pipeline

```mermaid
flowchart LR
    subgraph Host["Windows 11 + WSL2 Ubuntu 22.04"]
        Repo["CNC_Project repository"]
        Raw["data/raw/ labeled PCAPs"]
        Docs["docs/ reports and diagrams"]
        Models["models/ trained ML artifacts"]
    end

    subgraph Docker["Docker Desktop / WSL2 Backend"]
        subgraph Net["Custom Docker bridge: cnc_net 172.20.0.0/24"]
            Server["server\n172.20.0.10\nnginx + vsftpd + dnsmasq + iperf3"]
            Client["client\n172.20.0.20\nnormal traffic generator"]
            Attacker["attacker\n172.20.0.30\nattack traffic generator"]
        end
    end

    Client -->|"HTTP GET/POST\nFTP uploads\nDNS queries"| Server
    Attacker -->|"ICMP flood\nSYN scan\nUDP scan\nPort sweep"| Server
    Attacker -->|"Host discovery"| Client

    Server -->|"tcpdump capture"| Raw
    Attacker -->|"tcpdump capture"| Raw

    Raw -->|"NFStream\nflow reconstruction"| Flows["Flow DataFrame"]
    Raw -->|"Scapy\nmanual packet features"| Manual["RTT, IAT, TCP window,\nSYN/ACK ratio"]

    Flows --> Features["L3/L4 feature dataset"]
    Manual --> Features

    Features --> ML["K-Means + Random Forest"]
    ML --> Models
    ML --> Dashboard["Streamlit dashboard"]
    Docs --> Report["Technical report"]
```

## Main Components

| Component | Role |
|---|---|
| server | Provides HTTP, FTP, DNS and iperf3 services for controlled traffic generation |
| client | Generates legitimate traffic such as HTTP, FTP and DNS |
| attacker | Generates anomalous traffic such as ICMP flood, SYN scan, UDP scan and port sweep |
| data/raw | Stores local PCAP files grouped by label |
| src/capture.py | Starts and stops tcpdump inside Docker containers |
| src/generate_dataset.py | Orchestrates traffic generation and capture by label |
| docs/dataset_stats.md | Records packet counts, durations and file sizes |
| Streamlit dashboard | Final interface for analyzing PCAPs and showing predictions |

## Data Flow

1. Docker containers generate controlled traffic inside the isolated bridge network.
2. tcpdump captures traffic from the relevant container.
3. PCAP files are saved locally under data/raw grouped by traffic label.
4. NFStream reconstructs flows and extracts base L3/L4 features.
5. Scapy computes manual packet-level features.
6. The ML pipeline trains clustering and classification models.
7. The dashboard visualizes classified flows and detected anomalies.

# CNC Project — NetFlow Analyzer

End-to-end network traffic analysis pipeline for a Computer Networks and Communications university project.

## Goal

This project captures network traffic in an isolated Docker environment, reconstructs TCP/UDP flows, extracts Layer 3 and Layer 4 features without payload inspection, applies machine learning models for traffic classification and anomaly detection, and visualizes the results in a Streamlit dashboard.

The main objective is to build a reproducible and modular pipeline capable of analyzing network behavior from PCAP files using protocol-level features such as flow duration, packet counts, byte counts, TCP flags, inter-arrival time, estimated RTT, TCP window size and SYN/ACK ratio.

## Current Status

- [x] WSL2 + Ubuntu 22.04 development environment
- [x] Docker Desktop with WSL2 integration
- [x] Docker available from PowerShell and WSL
- [x] TShark available inside WSL
- [x] Python virtual environment created
- [x] Core dependencies installed
- [x] Initial project structure created
- [x] Docker traffic lab
- [ ] PCAP capture
- [ ] Flow reconstruction
- [ ] Feature engineering
- [ ] Machine learning pipeline
- [ ] Streamlit dashboard

## Tech Stack

| Layer | Tools |
|---|---|
| Environment | Windows 11, WSL2, Ubuntu 22.04 |
| Containerization | Docker Desktop, Docker Compose |
| Packet Capture / Analysis | Wireshark, Npcap, TShark, PyShark |
| Packet Processing | Scapy |
| Flow Extraction | NFStream |
| Data Processing | pandas, NumPy |
| Machine Learning | scikit-learn, imbalanced-learn, joblib |
| Visualization | Streamlit, Plotly, Matplotlib, Seaborn |
| Version Control | Git, GitHub |

## Project Structure

```text
CNC_Project/
├── data/
│   ├── raw/              Raw PCAP files, ignored by Git
│   └── processed/        Processed datasets ready for ML
├── docker/
│   ├── attacker/         Container for anomalous traffic generation
│   ├── client/           Container for legitimate traffic generation
│   └── server/           Container running nginx, vsftpd and iperf3
├── docs/                 Technical documentation and setup notes
├── models/               Trained machine learning models
├── notebooks/            Exploratory analysis notebooks
├── src/                  Source code
├── tests/                Unit and integration tests
├── docker-compose.yml    Docker lab definition
├── README.md             Project documentation
├── requirements.txt      Python dependencies
├── .gitignore            Git ignored files
└── .gitattributes        Line ending configuration
```

## Environment Setup

This project is developed inside WSL2 Ubuntu 22.04.

### 1. Create and activate the virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Upgrade Python packaging tools

```bash
python -m pip install --upgrade pip setuptools wheel
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify the environment

```bash
python src/check_environment.py
```

Expected final output:

```text
[SUCCESS] Environment is ready for Day 2.
```

## Docker Verification

Docker Desktop must be running and WSL2 integration must be enabled for Ubuntu 22.04.

Verify Docker from WSL:

```bash
docker --version
docker compose version
docker run --rm hello-world
```

Expected result:

```text
Hello from Docker!
```

## Packet Analysis Tools

TShark must be available inside WSL because PyShark depends on it.

Verify TShark:

```bash
tshark -v
```

Wireshark and Npcap are installed on Windows for visual packet inspection and manual validation of captured traffic.

## Docker Lab

The project includes an isolated Docker traffic lab with three containers connected through a custom Docker bridge network.

| Container | Role | Static IP |
|---|---|---|
| server | Runs nginx, vsftpd and iperf3 | 172.20.0.10 |
| client | Generates legitimate traffic | 172.20.0.20 |
| attacker | Generates anomalous and reconnaissance traffic | 172.20.0.30 |

### Start the lab

```bash
docker compose up -d --build
```

### Check running containers

```bash
docker compose ps
```

### Verify HTTP connectivity

```bash
docker compose exec client curl -I http://server
```

### Verify FTP upload

```bash
docker compose exec client bash -lc 'echo "FTP smoke test from client" > /tmp/ftp_test.txt && lftp -u ftpuser,ftppass -e "set ftp:ssl-allow no; set ftp:passive-mode on; put /tmp/ftp_test.txt -o upload/ftp_test.txt; ls upload; bye" ftp://server'
```

### Verify iperf3 traffic

```bash
docker compose exec client iperf3 -c server -t 5
```

### Verify reconnaissance traffic

```bash
docker compose exec attacker nmap -sS -p 21,80,5201 server
docker compose exec attacker hping3 -S -c 5 -p 80 server
```

### Stop the lab

```bash
docker compose down
```

This Docker lab is used to generate controlled HTTP, FTP, ICMP, iperf3 and reconnaissance traffic for later PCAP capture, flow reconstruction and feature extraction.

## Dataset Policy

Raw packet captures are intentionally ignored by Git:

```text
*.pcap
*.pcapng
*.cap
```

PCAP files can be large and may contain sensitive traffic. Even though this project uses synthetic traffic generated inside an isolated Docker environment, excluding raw captures from version control keeps the repository lightweight and safer.

## Planned Pipeline

The final system will follow this workflow:

```text
Docker traffic lab
        ↓
Traffic generation
        ↓
PCAP capture
        ↓
Flow reconstruction
        ↓
L3/L4 feature extraction
        ↓
Data cleaning and normalization
        ↓
Machine learning models
        ↓
Streamlit dashboard
```

## Target Traffic Classes

The project will generate and analyze several traffic categories:

| Class | Description |
|---|---|
| normal | Legitimate HTTP, FTP and DNS-like traffic |
| icmp_flood | High-rate ICMP traffic |
| syn_scan | TCP SYN scan behavior |
| port_sweep | Host or port discovery behavior |

## Target Features

The feature engineering phase will focus on Layer 3 and Layer 4 information only, without inspecting application payloads.

Planned features include:

| Feature | Purpose |
|---|---|
| Flow duration | Distinguishes short scans from longer legitimate flows |
| Packet count | Captures flow volume |
| Byte count | Captures transferred data volume |
| Bytes per packet | Separates data transfer from control packets |
| TCP flag counts | Detects SYN, ACK, RST and FIN behavior |
| SYN/ACK ratio | Identifies incomplete TCP handshakes and scans |
| Inter-arrival time | Measures timing regularity between packets |
| Estimated RTT | Approximates network latency from TCP handshake packets |
| TCP window size | Captures TCP stack behavior and congestion control patterns |

## Machine Learning Plan

The project will use two main ML approaches:

1. **K-Means clustering** for unsupervised traffic behavior discovery.
2. **Random Forest classification** for supervised traffic classification.

Random Forest is selected because it is robust, interpretable through feature importance, and well suited for tabular network-flow features.

## Dashboard Plan

The Streamlit dashboard will allow the user to upload or analyze a PCAP file and visualize:

- Total number of flows
- Number of normal and anomalous flows
- Most frequent detected attack class
- Flow classification table
- Class distribution chart
- Scatter plot of flow duration vs bytes
- Timeline of detected flows
- Alert banner when anomalous traffic is detected

## Development Notes

This project is being built incrementally following a weekly plan:

1. Environment setup and Docker traffic generation
2. PCAP capture and flow reconstruction
3. Feature engineering and dataset preparation
4. Machine learning pipeline
5. Streamlit dashboard
6. Final documentation and report

## Repository Status

This repository is currently in the Docker traffic lab setup phase.

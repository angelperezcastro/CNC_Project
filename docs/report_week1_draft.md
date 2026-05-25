# Technical Report Draft — Week 1

# 1. Introduction

Network traffic analysis is a central task in modern computer networks because it allows administrators to understand communication patterns, detect abnormal behavior and support security monitoring. Traditional traffic inspection techniques often rely on payload analysis, but this approach has important limitations: payloads may be encrypted, inspecting application content may violate privacy requirements, and deep packet inspection is computationally expensive.

This project proposes a payload-independent traffic analysis pipeline called NetFlow Analyzer. The system focuses on Layer 3 and Layer 4 information only, using packet metadata and flow-level behavior instead of application payload. This design makes the system suitable for both encrypted and unencrypted traffic, because the selected features are extracted from IP, TCP, UDP and ICMP headers, timing patterns and flow statistics.

The main objective is to build an end-to-end pipeline capable of capturing traffic in a controlled Docker environment, reconstructing network flows, extracting protocol-level features, applying machine learning models and visualizing the results in a dashboard. The project starts from raw PCAP files and progresses toward a structured dataset suitable for clustering, classification and anomaly detection.

The measurable objectives of the project are:

1. Build an isolated Docker network with separate containers for legitimate traffic, anomalous traffic and network services.
2. Generate labeled PCAP files for normal traffic and several anomalous traffic patterns, including ICMP flood, TCP SYN scan, UDP scan and port sweep.
3. Extract Layer 3 and Layer 4 features such as flow duration, byte counts, packet counts, TCP flags, inter-arrival time, estimated RTT, TCP window size and SYN/ACK ratio.
4. Train and evaluate machine learning models for unsupervised clustering and supervised classification.
5. Provide an interactive Streamlit dashboard to analyze PCAP files and show classified flows.

The scope of the current system is intentionally controlled. The traffic is generated inside a Docker bridge network instead of a real production network. This makes the experiments reproducible and avoids capturing private user traffic. The system does not inspect payload contents and therefore does not classify applications based on the data carried inside the packets. The analysis is limited to network and transport layer behavior.

The rest of the report is structured as follows. Section 2 describes the system architecture and the Docker-based traffic laboratory. Section 3 explains how normal and anomalous traffic is generated and captured. Section 4 presents the feature engineering process. Section 5 describes the machine learning pipeline. Section 6 introduces the dashboard. Section 7 discusses conclusions, limitations and future work.

# 2. System Architecture

The system is designed as a modular end-to-end pipeline. It starts with controlled traffic generation inside Docker, stores raw packet captures as PCAP files, reconstructs flows, extracts features and finally applies machine learning models for classification and anomaly detection.

The first architectural layer is the Docker traffic laboratory. It contains three main containers connected through a custom Docker bridge network using the subnet 172.20.0.0/24. Static IP addresses are assigned to make packet filtering and dataset labeling easier:

| Component | IP address | Role |
|---|---:|---|
| server | 172.20.0.10 | Provides HTTP, FTP, DNS and iperf3 services |
| client | 172.20.0.20 | Generates legitimate traffic |
| attacker | 172.20.0.30 | Generates anomalous and reconnaissance traffic |

The server container runs nginx for HTTP traffic, vsftpd for FTP traffic, dnsmasq for internal DNS queries and iperf3 for controlled high-volume TCP traffic. The client container generates normal traffic such as HTTP GET requests, HTTP POST requests, FTP uploads and DNS queries. The attacker container generates anomalous traffic patterns such as ICMP flood, TCP SYN scan, UDP scan and port sweep.

A custom Docker bridge network is used instead of the default Docker network because it provides deterministic addressing, internal DNS resolution and better control over the experiment. This design allows Wireshark and TShark filters such as `ip.addr == 172.20.0.10` or `ip.src == 172.20.0.30` to isolate traffic from a specific component. The network is isolated from real external traffic, which improves reproducibility and prevents accidental collection of private host traffic.

The second architectural layer is packet capture. Captures are performed inside Docker containers using tcpdump. This decision is important in Windows 11 with WSL2 and Docker Desktop because internal Docker bridge traffic is not always visible directly from Wireshark running on Windows. Capturing inside the relevant container ensures that the generated traffic is reliably stored in PCAP format.

The raw PCAP files are stored locally under `data/raw/`, grouped by label:

| Label | Description |
|---|---|
| normal | Legitimate HTTP, FTP and DNS traffic |
| icmp_flood | High-rate ICMP echo traffic |
| syn_scan | TCP SYN scan against server ports |
| udp_scan | UDP scan against server ports |
| port_sweep | Host discovery over the Docker subnet |

Raw PCAP files are excluded from Git because they can be large and may contain sensitive data such as clear-text FTP credentials. Instead of storing PCAPs in the repository, the project stores metadata reports such as packet counts, capture duration and file size.

The third architectural layer is the processing pipeline. The planned feature extraction stage combines NFStream and Scapy. NFStream will be used for bidirectional flow reconstruction and automatic flow-level statistics. Scapy will be used for manual packet-level features that require direct access to packet timestamps and TCP header fields, such as inter-arrival time, estimated RTT, TCP window size and SYN/ACK ratio.

The fourth layer is the machine learning pipeline. The project will use K-Means for unsupervised clustering and Random Forest for supervised classification. K-Means is useful to analyze whether traffic categories form naturally separable groups, while Random Forest is appropriate for tabular network-flow features and provides feature importance values that can be interpreted from a networking perspective.

The final layer is the Streamlit dashboard. The dashboard will allow the user to upload or analyze a PCAP file, execute the processing pipeline and visualize flow classifications, anomaly counts, class distributions and confidence values.

The complete data flow is:

1. The Docker client and attacker containers generate controlled traffic.
2. tcpdump captures packets inside the server or attacker container.
3. PCAP files are stored under `data/raw/` by label.
4. NFStream reconstructs bidirectional flows from PCAP files.
5. Scapy computes manual Layer 3 and Layer 4 features.
6. The dataset is cleaned, normalized and prepared for machine learning.
7. K-Means and Random Forest models analyze and classify the traffic.
8. Streamlit visualizes the results in an interactive dashboard.

This architecture separates traffic generation, capture, feature extraction, machine learning and visualization into independent modules. This modularity makes the system easier to test, debug and extend during the next project phases.

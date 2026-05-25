FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    nmap \
    hping3 \
    iperf3 \
    iputils-ping \
    iproute2 \
    dnsutils \
    netcat-openbsd \
    lftp \
    ftp \
    tcpdump \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]

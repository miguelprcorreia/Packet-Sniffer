<div align="center">

# 🔍 Packet Sniffer

**Network packet sniffer & protocol analyzer built in Python (Scapy)** — project for *Redes de Computadores* @ University of Minho (2025/2026)

![Python](https://img.shields.io/badge/-Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/-Scapy-white?style=for-the-badge&logo=python&logoColor=blue)

</div>

---

## 📖 About

**Packet Sniffer** is a real-time network traffic capture and analysis tool, similar in spirit to Wireshark. It identifies, classifies, and characterizes traffic across multiple protocols, reconstructing protocol-specific interactions such as the TCP three-way handshake, ICMP/ARP request-reply pairs, and the DHCP DORA sequence.

The project was developed and validated in two stages: first in a controlled emulated network (**CORE**), then on a real network interface (Wi-Fi/Ethernet) for real-world traffic analysis. Only passive traffic inspection is performed — no active exploitation (MITM, injection, deauth, etc).

---

## ✨ Features

| Feature | Description |
|---|---|
| **Live capture** | Real-time packet display in the console |
| **File logging** | Save captured packets to a file for later analysis (`-o file.txt`) |
| **Automatic protocol detection** | Identifies ARP, ICMP, TCP, IPv4, DHCP, and IEEE 802.11 (WiFi) |
| **IPv4 fragmentation analysis** | Detects and reassembles fragmented IPv4 datagrams |
| **Protocol-specific handlers** | Reconstructs meaningful interactions per protocol (see below) |
| **Interactive analysis mode** | Post-capture CLI to inspect, filter, and query captured data |
| **Filtering** | By protocol, IP address, or MAC address |
| **Verbosity control** | `verbose` (detailed) or `compact` output |

### 🧩 Protocol analysis highlights

- **ICMP** — pairs Echo Request/Reply, computes RTT (min/max/avg)
- **ARP** — reconstructs request/reply pairs, detects gratuitous ARP, computes resolution RTT
- **TCP** — tracks the three-way handshake (SYN, SYN-ACK, ACK), identifies established connections, initial RTT, and FIN/RST termination events
- **DHCP** — groups messages by transaction ID (XID) to reconstruct the full DORA flow (Discover, Offer, Request, ACK) and measure lease time
- **IPv4** — detects and groups fragmented datagrams by ID, tracks offsets and reassembly status
- **IEEE 802.11 (WiFi)** — classifies Management/Control/Data frames, tracks active BSSIDs (via beacons) and most active devices

---

## 🚀 Getting Started

### Option A — Local install

```bash
pip install scapy
```

### Option B — Docker (recommended for a clean, reproducible environment)

Since packet capture requires raw sockets, the container needs elevated network privileges.

1. Create a `Dockerfile` in the project root:

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy

WORKDIR /app
COPY . /app

ENTRYPOINT ["python3", "packet_sniffer/main.py"]
```

2. Build the image:

```bash
docker build -t packet-sniffer .
```

3. Run the container with host networking and the required capabilities (needed for raw packet capture):

```bash
docker run --rm -it \
  --network host \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  packet-sniffer -i eth0
```

> ℹ️ `--network host` gives the container direct access to the host's network interfaces (required to sniff real traffic — this only works on Linux hosts). Adjust `-i eth0` to the interface you want to capture on.

---

## 🖥️ Usage

### List available interfaces

```bash
ip a
```

### Full syntax

```bash
sudo python3 main.py -i <interface> -m <mode> -o <file> -v <verbosity>
```

### Arguments

| Argument | Short | Values | Default | Description |
|---|---|---|---|---|
| `--interface` | `-i` | interface name | *(required)* | Network interface to capture on (e.g. `eth0`, `wlan0`) |
| `--mode` | `-m` | `live`, `log`, `both` | `live` | Capture mode: console only, file only, or both |
| `--output` | `-o` | file path | `None` | Output file to save captured packets |
| `--verbosity` | `-v` | `verbose`, `compact` | `verbose` | Console output detail level |

### Examples

```bash
# Basic console capture
sudo python3 main.py -i eth0

# Save capture to a file
sudo python3 main.py -i eth0 -m log -o capture.txt

# Console + file, compact mode
sudo python3 main.py -i wlan0 -m both -o capture.txt -v compact
```

---

## 🔎 Interactive Analysis Mode

After stopping the capture (`Ctrl+C`), the program enters an **interactive analysis mode**:

| Command | Description |
|---|---|
| `tcp`, `dhcp`, `icmp`, `ipv4`, `wifi`, `arp` | List captured packets of a given protocol |
| `status <protocol>` | Show detailed stats for `icmp`, `arp`, `tcp`, or `wifi` |
| `fragments ipv4` | Show detailed IPv4 fragment groups |
| `filter ip <IP>` | Isolate traffic for a specific IP address |
| `filter proto <NAME>` | Filter by protocol (e.g. `filter proto ARP`) |
| `filter mac <MAC>` | Filter by a specific MAC address |

---

## 🌐 Validation Environments

The sniffer was validated in two stages:

- **CORE (emulated network)** — used to validate protocol identification in a controlled, reproducible star topology, generating traffic with tools like `ping` and `netcat`.
- **Real network interface** — used to confirm the sniffer's behavior under real, higher-volume traffic (Wi-Fi/Ethernet), including live DHCP renewals and WiFi frame capture.

> The project also runs inside CORE nodes the same way it runs locally (`sudo python3 main.py -i eth0`); see the practical assignment report for the full CORE setup and topology.

---

## 🗂️ Project Structure

```
Packet-Sniffer/
├── packet_sniffer/     # Application source (capture, parsing, handlers, analysis, filters)
└── relatorio/          # Project report (architecture, protocol catalogue, tests, conclusions)
```

---

<div align="center">

🔗 [github.com/miguelprcorreia/Packet-Sniffer](https://github.com/miguelprcorreia/Packet-Sniffer)

</div>

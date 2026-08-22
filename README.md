# 🔎 PCAP Analyzer

A Python-based, forensic-grade network traffic analyzer for `.pcap` / `.pcapng` capture files. It parses a capture and produces a structured, security-oriented report — including ARP/MITM detection, TCP flow analysis, TLS metadata, DNS/HTTP inspection, and severity-tagged findings with packet-level evidence.

Built for network troubleshooting, incident investigation, and Wireshark-style analysis from the command line — no GUI required.

---

## ✨ Features

- 📦 Parses `.pcap` and `.pcapng` capture files
- 🌐 Protocol breakdown and protocol-aware traffic classification (not just port-based)
- 📊 Top talkers by bytes **and** packets, with % of total traffic
- 🔗 Top conversations by volume
- 🧩 **ARP / MITM analysis**
  - ARP request / reply / gratuitous ARP breakdown
  - IP ↔ MAC history table (first seen, last seen, change count)
  - Detects IP/MAC identity conflicts (one IP, multiple MACs)
  - Reconstructs a possible MITM path when an attacker MAC is shared between a victim and a gateway
- 🔄 **TCP flow analysis**
  - Handshake status (complete / SYN with no SYN-ACK / SYN-ACK with no final ACK)
  - SYN, SYN-ACK, FIN, RST counters per conversation
  - Retransmission detection
  - Duplicate ACK detection
  - Out-of-order segment detection
  - Port scan / high-volume unanswered SYN detection
- 🔐 **TLS analysis**
  - Parses ClientHello / ServerHello (no decryption)
  - TLS version, SNI, ALPN, cipher suites
  - **JA3 client fingerprint** (MD5 hash, GREASE-filtered)
- 🧭 **DNS analysis**
  - Queries and responses (A / AAAA / CNAME), NXDOMAIN, TTL
  - Anomaly detection for domains that resolve to multiple distinct IPs in a short window
- 🌍 **HTTP analysis**
  - Request method, path, Host, User-Agent, Referer, Content-Type/Length
  - Response status codes
  - Cookie / Authorization headers reported as **present/absent only** (never logs the actual value)
- 📡 ICMP type/code breakdown (Echo Request/Reply, Unreachable, etc.)
- 📶 UDP application identification by port (DNS, NTP, DHCP, mDNS, QUIC/HTTP3)
- 🚨 Findings with severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`), each with what happened, why it matters, affected hosts, first/last seen, and **evidence packet numbers**
- 📈 ASCII traffic-volume timeline
- 🧾 Text and JSON report output
- ⚡ Single dependency, pure Python, no GUI

---

## 🧠 What does it analyze?

### ARP / MITM
Flags IP/MAC conflicts, gratuitous ARP, and shared attacker MACs, then reconstructs the likely victim → attacker → gateway path with the packet numbers that support the finding.

### TCP
Tracks every TCP conversation and reports handshake completeness, retransmissions, duplicate ACKs, out-of-order segments, and reset activity — useful for spotting packet loss, interception, or scanning.

### TLS
Extracts handshake metadata (version, SNI, ALPN, cipher suites) and computes a JA3 fingerprint per ClientHello, without touching the encrypted payload.

### DNS / HTTP
Surfaces queries, response types, NXDOMAIN answers, and DNS answer instability, plus HTTP request/response metadata — with sensitive headers reported as present/absent only.

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/NetShell-IR/pcap-analyzer.git
cd pcap-analyzer
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

Install the dependency:

```bash
pip install -r requirements.txt
```

### Requirements
- Python 3.8+
- [scapy](https://scapy.net/) — the only third-party dependency

`requirements.txt`:
```
scapy>=2.7.0
```

---

## ▶️ Usage

Basic run — prints the full report to the terminal:

```bash
python3 pcap_analyzer.py capture.pcap
```

Works the same way for PCAPNG:

```bash
python3 pcap_analyzer.py capture.pcapng
```

### Command-line options

| Flag | Description | Default |
|---|---|---|
| `pcap_file` | Path to the `.pcap` / `.pcapng` file (required, positional) | — |
| `--top N` | Number of top items shown per section (top talkers, conversations, ports, SNI, JA3, etc.) | `15` |
| `--out FILE` | Save the full text report to `FILE` | not saved |
| `--json FILE` | Save a machine-readable JSON report to `FILE` | not saved |

### Examples

```bash
# Quick look, top 15 of everything (default)
python3 pcap_analyzer.py capture.pcap

# Show top 25 instead of top 15
python3 pcap_analyzer.py capture.pcap --top 25

# Save a text report to disk
python3 pcap_analyzer.py capture.pcap --out report.txt

# Export findings and raw stats as JSON (for feeding into other tools)
python3 pcap_analyzer.py capture.pcap --json report.json

# Do all of it at once
python3 pcap_analyzer.py capture.pcap --top 20 --out report.txt --json report.json
```

---

## 📁 Project Structure

```
pcap-analyzer/
├── pcap_analyzer.py   # Main analysis engine (ARP/MITM, TCP, DNS, HTTP, ICMP, UDP, findings, reporting)
├── tls_engine.py       # TLS ClientHello/ServerHello parsing + JA3 fingerprinting
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
└── .gitignore          # Ignored files
```

---

## 📊 Example Findings

Depending on the capture, the analyzer may report findings such as:

```
[CRITICAL] Possible MITM path reconstructed
[CRITICAL] MAC address claimed by multiple IPs
[HIGH]     ARP identity conflict on 172.16.1.50
[HIGH]     Possible port scan from 10.0.0.99
[HIGH]     Authorization header sent in cleartext HTTP
[MEDIUM]   Gratuitous ARP observed
[MEDIUM]   Multiple TCP resets on a conversation
[MEDIUM]   DNS answer instability for a domain
[LOW]      Incomplete TCP handshake
```

Each finding includes **what** was observed, **why** it matters, the **affected hosts**, a **time range**, and the **evidence packet numbers** (`#12`, `#47`, ...) so you can jump straight to the relevant packets in Wireshark.

> ⚠️ These findings are indicators, not proof of an attack. Congestion, packet loss, asymmetric routing, DHCP re-leases, VM migrations, and capture-point limitations can produce similar symptoms. Always validate against the surrounding network context.

---

## 🛡️ Use Cases

- 🔧 Network troubleshooting
- 🕵️ Incident response
- 🔐 Security analysis and threat hunting
- 📡 Network engineering
- 🧪 Security labs / CTFs
- 🎓 Learning packet analysis
- 🦈 Wireshark-assisted investigations

---

## ⚠️ Important

- Detection quality depends entirely on the quality and completeness of the capture. A one-sided or truncated capture will produce incomplete or misleading results.
- Retransmission / out-of-order / duplicate-ACK detection uses lightweight sequence-number heuristics — it is not a full TCP reassembly engine like Wireshark's, so treat the numbers as strong indicators rather than exact ground truth.
- **Only analyze traffic you are authorized to inspect.**

---

## 🗺️ Roadmap

- [ ] Application-layer flow graph (ASCII/visual)
- [ ] TLS certificate chain inspection
- [ ] JA4 fingerprinting
- [ ] Streaming/low-memory mode for very large captures (`PcapReader` instead of `rdpcap`)
- [ ] HTML report output
- [ ] IOC extraction / threat-intel matching
- [ ] Capture filtering (BPF-style, by host/port/time range)
- [ ] Unit tests + GitHub Actions CI

---

## 🤝 Contributing

Contributions, bug reports, ideas, and improvements are welcome. If you find a bug or have an idea for a new detection method, open an issue or submit a pull request.

---

## 📜 License

License information will be added to the project.

---

## ⭐ If you find this project useful

Give the repository a star and follow the project as it evolves.

**PCAP Analyzer — Turn packets into evidence.**

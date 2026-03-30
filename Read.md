# SecureSniff

**Network Intrusion Detection System** built from scratch in Python.  
Passive traffic analysis across OSI Layers 2–7, with real-time alerting and automated HTML reporting.

```
Capture → Heuristic Analysis → Deep Packet Inspection → Logging → Visual Report
```

---

## What it detects

| Attack | Method | OSI Layer |
|---|---|---|
| Port Scan | Behavioural heuristics — ports per IP per time window | L4 TCP |
| SYN Flood | Packet rate analysis — SYN packets per second | L4 TCP |
| ARP Spoofing | MAC table validation — detects identity changes | L2 ARP |
| Plaintext credentials | Deep Packet Inspection — HTTP payload keyword search | L7 HTTP |

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    CLI  (Click)                       │
│           capture command │ report command            │
└─────────────────┬─────────────────┬──────────────────┘
                  │                 │
       ┌──────────▼──────┐   ┌──────▼──────────────┐
       │  PacketCapture  │   │   ReportGenerator    │
       │  AsyncSniffer   │   │   Pandas + Plotly    │
       └──────────┬──────┘   └──────▲───────────────┘
                  │                 │
       ┌──────────▼──────┐   ┌──────┴───────────────┐
       │ Detector Engine │   │  Logger              │
       │  PortScan       ├───►  [timestamp] event   │
       │  SynFlood       │   └──────────────────────┘
       │  ArpSpoof       │
       │  HTTPParser     │
       └─────────────────┘
```

Each layer has a single responsibility. The capture engine has no knowledge of the reporting engine. Both are independently invocable via CLI.

---

## Modules

### Capture Engine — `src/capture/live_capture.py`

Opens a raw socket on the network interface with root privileges, intercepting packets before OS processing.

Two deliberate design choices:

- `AsyncSniffer` — runs on a parallel thread, the main process stays responsive
- `store=False` — packets are not accumulated in RAM, allowing indefinite runtime without memory degradation

```python
AsyncSniffer(iface=self.interface, prn=self.process_packet, store=False)
```

---

### Heuristic Detectors — `src/analysis/detectors/`

No signature database. The system analyses **behaviour**, not identity.

**Port Scan** — tracks `{ IP → set of destination ports }` within a rolling time window. A single IP hitting more than 15 distinct ports in 10 seconds is flagged as reconnaissance. Legitimate traffic reuses a small set of ports; scanners generate unique ones.

**SYN Flood** — measures SYN packets per second per source. A legitimate TCP handshake is SYN → SYN-ACK → ACK. A flood sends SYN × N with no response, exhausting server connection queues. Threshold: >100 SYN/s from a single origin.

**ARP Spoofing** — passively builds a `{ IP: MAC }` table. When an ARP Reply changes the MAC of a known IP, a Man-in-the-Middle attack is flagged. This is the standard precursor to LAN traffic interception.

---

### Deep Packet Inspection — `src/parser/http_parser.py`

Operates at Layer 7. Extracts the `Raw` payload from each packet, decodes bytes to UTF-8, and searches for credential keywords: `user=`, `pass=`, `password=`, `login=`, `username=`.

Demonstrates why unencrypted HTTP is a liability — any host on the same network can extract credentials in cleartext. The fix is enforced HTTPS.

---

### Logger — `src/utils/logger.py`

Every alert writes to `logs/attacks.log` in a structured format designed for downstream regex parsing:

```
[2026-01-13 17:29:15] PORT SCAN DETETADO! Origem: 192.168.1.90 | Portas: 16
[2026-01-13 17:29:16] SYN FLOOD DETETADO! Origem: 192.168.1.90 | Taxa: 101 pacotes/s
```

---

### Report Generator — `src/report/generator.py`

A complete ETL pipeline:

1. **Extract** — reads `attacks.log` line by line
2. **Transform** — regex parsing into a Pandas DataFrame
3. **Load** — Plotly donut chart + Jinja2 HTML template → `relatorio_final.html`

The output is a self-contained Bootstrap dashboard: attack count, interactive chart by type, and a timestamped alert table.

---

## Stack

| Library | Purpose |
|---|---|
| `scapy` | Packet capture and dissection, Layers 2–7 |
| `click` | CLI structure |
| `rich` | Terminal output formatting |
| `pandas` | Log parsing and transformation |
| `plotly` | Interactive data visualisation |
| `jinja2` | HTML report templating |

**OS:** Parrot OS / Kali / Ubuntu — **Python:** 3.10+ — **Requires:** root (raw socket)

---

## Setup

```bash
git clone https://github.com/g-rebelo/securesniff.git
cd securesniff

python3 -m venv venv
source venv/bin/activate

pip install scapy click rich pandas plotly jinja2
```

---

## Usage

```bash
# Real-time capture (requires root)
sudo ./venv/bin/python cli/commands.py capture --interface enp2s0

# Generate HTML report from logs
./venv/bin/python cli/commands.py report
```

To simulate attacks in a controlled lab environment:

```bash
# Port scan
nmap -sS -p 1-1000 <target>

# SYN flood
sudo hping3 -S --flood -p 80 <target>

# Plaintext credentials over HTTP
curl -X POST http://<target>/login -d "username=admin&password=test"
```

---

## Project Structure

```
securesniff/
├── cli/
│   └── commands.py
├── src/
│   ├── capture/
│   │   └── live_capture.py
│   ├── analysis/detectors/
│   │   ├── port_scan.py
│   │   ├── syn_flood.py
│   │   └── arp_spoof.py
│   ├── parser/
│   │   └── http_parser.py
│   ├── report/
│   │   └── generator.py
│   ├── templates/
│   │   └── dashboard.html
│   └── utils/
│       └── logger.py
└── logs/
    └── attacks.log
```

---

## Context

Built as part of a cybersecurity portfolio for postgraduate application. The project covers the full defensive pipeline — network capture, behavioural anomaly detection, forensic logging, data engineering, and web reporting — without relying on commercial IDS tools.

---

> For educational and research purposes only, in controlled network environments. Capturing traffic on networks you do not own or have explicit permission to monitor is illegal.
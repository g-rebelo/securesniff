# SecureSniff - Network Intrusion Detection System

A Python project that monitors network traffic in real time and detects common attacks. Built from scratch without using commercial tools like Snort or Suricata.

The idea is straightforward: the program listens to packets going through the network, analyses the behaviour and fires alerts when something looks suspicious. At the end it generates an HTML report with all logged attacks.

---

## What it detects

- **Port Scan** — if an IP tries to reach more than 15 ports in 10 seconds, it gets flagged as reconnaissance (like Nmap)
- **SYN Flood** — measures the SYN packet rate per second. Above 100/s from the same source is considered a DoS attempt
- **ARP Spoofing** — keeps an IP/MAC table and alerts if the MAC of a known IP suddenly changes (MITM)
- **HTTP Credentials** — does Layer 7 packet inspection looking for keywords like `password=` or `user=` in unencrypted traffic

---

## How it works

```
Capture (Scapy) → Detectors → Logger → HTML Report
```

Used `AsyncSniffer` with `store=False` so it doesn't block the process or fill up RAM after running for hours.

The report side reads the log file with Pandas, parses it with regex, and generates an interactive Plotly chart inside a Jinja2 HTML template.

---

## Stack

`scapy` `click` `rich` `pandas` `plotly` `jinja2`

Python 3.10+, runs on Parrot OS / Kali / Ubuntu. Needs sudo to open raw sockets.

---

## Setup

```bash
git clone https://github.com/g-rebelo/securesniff.git
cd securesniff
python3 -m venv venv
source venv/bin/activate
pip install scapy click rich pandas plotly jinja2
```

## Usage

```bash
# real-time capture
sudo ./venv/bin/python cli/commands.py capture --interface enp2s0

# generate report
./venv/bin/python cli/commands.py report
```

To test in a lab environment:

```bash
nmap -sS -p 1-1000 <target>
sudo hping3 -S --flood -p 80 <target>
curl -X POST http://<target>/login -d "username=admin&password=test"
```

---

## Structure

```
securesniff/
├── cli/commands.py
├── src/
│   ├── capture/live_capture.py
│   ├── analysis/detectors/
│   │   ├── port_scan.py
│   │   ├── syn_flood.py
│   │   └── arp_spoof.py
│   ├── parser/http_parser.py
│   ├── report/generator.py
│   ├── templates/dashboard.html
│   └── utils/logger.py
└── logs/attacks.log
```

---

Built for academic and educational purposes in a controlled environment. Don't use it on networks you don't own.
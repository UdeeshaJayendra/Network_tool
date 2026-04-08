# Network Troubleshooting & Mini IDS Tool

Analyses `.pcap` files for TCP issues, DNS failures, packet loss, ICMP errors,
HTTP errors, and detects SSH brute-force, SYN floods, and port scans.

## Requirements

- Python 3.10+
- `tshark` (for live capture only): `sudo apt install tshark`

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Web UI (Streamlit)

```bash
streamlit run app.py
```

Open http://localhost:8501, upload a `.pcap`, and click **Analyse**.

### CLI — analyse a pcap file

```bash
python analyze_pcap.py analyse -i path/to/capture.pcap -o reports
```

### CLI — capture live traffic then analyse

```bash
sudo python analyze_pcap.py capture --interface eth0 --duration 30 -o reports
```

## Output

```
reports/
  network_report_<timestamp>.csv          # all metrics
  network_recommendations_<timestamp>.csv # actionable findings
  graphs/
    tcp_retransmissions_<timestamp>.png
    packet_loss_<timestamp>.png
    handshake_latency_<timestamp>.png
    icmp_errors_<timestamp>.png           # if ICMP errors found
    http_errors_<timestamp>.png           # if HTTP errors found
    ssh_bruteforce_<timestamp>.png        # if brute-force detected
```

## What is detected

| Category | Metric |
|---|---|
| DNS | Failed queries (ancount == 0) |
| TCP | Retransmissions, slow handshakes (>0.5 s), handshake latency |
| Packet loss | Sent vs. received heuristic per IP pair |
| ICMP | Destination unreachable (type 3), TTL exceeded (type 11) |
| HTTP | 4xx and 5xx status codes from raw TCP payloads |
| IDS | SSH brute-force (>5 attempts), SYN flood (>50 SYNs/src), port scan (>20 ports/src) |

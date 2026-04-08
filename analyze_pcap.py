"""
analyze_pcap.py — Core PCAP analysis engine.

Can be used as a library (import run_analysis) or as a CLI script.
"""

import os
import subprocess
from collections import defaultdict
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # non-interactive backend — safe for CLI and Streamlit
import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import DNS, ICMP, IP, TCP, rdpcap


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def run_analysis(pcap_file: str, output_folder: str = "reports") -> dict:
    """
    Analyse a PCAP file and return a results dict.

    Parameters
    ----------
    pcap_file : str
        Path to the .pcap file.
    output_folder : str
        Root folder for CSV reports and PNG graphs.

    Returns
    -------
    dict with keys:
        report_file, recommendation_file, graphs, metrics, recommendations
    """
    if not os.path.isfile(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    os.makedirs(f"{output_folder}/graphs", exist_ok=True)

    print(f"[*] Loading packets from: {pcap_file}")
    packets = rdpcap(pcap_file)

    # ── DNS ────────────────────────────────────────────────────────────────
    dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS)]
    # BUG FIX: old code used ancount==0 which incorrectly flagged all DNS
    # queries (ancount is always 0 in requests) and valid responses with
    # empty answer sections. Correct check: response (qr==1) + rcode!=0.
    failed_dns  = [pkt for pkt in dns_packets
                   if pkt[DNS].qr == 1 and pkt[DNS].rcode != 0]

    # ── TCP ────────────────────────────────────────────────────────────────
    tcp_packets = [pkt for pkt in packets if pkt.haslayer(TCP) and pkt.haslayer(IP)]

    # Retransmissions — same (src, dst, sport, dport, seq) seen twice.
    # BUG FIX: old code counted every duplicate seq including SYN, RST, and
    # pure ACKs (which legitimately repeat seq numbers and are not retransmits).
    # Correct: only count data-carrying segments (payload_len > 0 or FIN).
    seq_seen        = set()
    retransmissions = []
    for pkt in tcp_packets:
        flags       = pkt[TCP].flags
        syn         = bool(flags & 0x02)
        rst         = bool(flags & 0x04)
        ack         = bool(flags & 0x10)
        fin         = bool(flags & 0x01)
        payload_len = len(bytes(pkt[TCP].payload))
        # Skip pure SYNs, RSTs, and pure ACKs with no payload
        if (syn and not ack) or rst:
            continue
        if payload_len == 0 and not fin:
            continue
        key = (pkt[IP].src, pkt[IP].dst,
               pkt[TCP].sport, pkt[TCP].dport,
               pkt[TCP].seq)
        if key in seq_seen:
            retransmissions.append(pkt)
        else:
            seq_seen.add(key)

    # Three-way handshake latency
    # Build lookup tables once so we avoid O(n²) inner loops
    synack_map: dict = {}   # (dst_ip, src_ip, dport, sport) → synack pkt
    for pkt in tcp_packets:
        if pkt[TCP].flags == "SA":
            key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            synack_map[key] = pkt

    handshakes: list[float] = []
    for syn in tcp_packets:
        if syn[TCP].flags != "S":
            continue
        sa_key = (syn[IP].dst, syn[IP].src,
                  syn[TCP].dport, syn[TCP].sport)
        synack = synack_map.get(sa_key)
        if synack:
            handshakes.append(float(synack.time) - float(syn.time))

    slow_handshakes = [t for t in handshakes if t > 0.5]

    # Packet loss — heuristic: IP pairs where retransmission count > 5.
    # BUG FIX: old code subtracted sent[A→B] - received[B→A] which is
    # meaningless (every packet A sends also "increments" received for B→A),
    # producing wildly inflated counts (112 pairs reported vs 27 actual).
    # Correct heuristic: count retransmitted data segments per (src,dst) pair.
    pair_retrans: defaultdict[tuple, int] = defaultdict(int)
    pair_seq_seen: defaultdict[tuple, set] = defaultdict(set)
    for pkt in tcp_packets:
        flags       = pkt[TCP].flags
        syn         = bool(flags & 0x02)
        rst         = bool(flags & 0x04)
        ack         = bool(flags & 0x10)
        fin         = bool(flags & 0x01)
        payload_len = len(bytes(pkt[TCP].payload))
        if (syn and not ack) or rst:
            continue
        if payload_len == 0 and not fin:
            continue
        flow = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
        seq  = pkt[TCP].seq
        if seq in pair_seq_seen[flow]:
            pair_retrans[(pkt[IP].src, pkt[IP].dst)] += 1
        else:
            pair_seq_seen[flow].add(seq)

    packet_loss = dict(pair_retrans)

    # ── ICMP ───────────────────────────────────────────────────────────────
    icmp_packets = [pkt for pkt in packets if pkt.haslayer(ICMP)]
    # Type 3 = destination unreachable, Type 11 = TTL exceeded
    icmp_errors  = [pkt for pkt in icmp_packets
                    if pkt[ICMP].type in (3, 11)]

    # ── HTTP — raw-payload heuristic (Scapy has no built-in HTTP parser) ──
    http_packets = [
        pkt for pkt in tcp_packets
        if pkt[TCP].dport in (80, 8080) or pkt[TCP].sport in (80, 8080)
    ]
    http_4xx: list = []
    http_5xx: list = []
    for pkt in http_packets:
        try:
            payload = bytes(pkt[TCP].payload).decode("utf-8", errors="ignore")
            if payload.startswith("HTTP/"):
                parts = payload.split(" ", 2)
                if len(parts) >= 2:
                    code = int(parts[1])
                    if 400 <= code < 500:
                        http_4xx.append(pkt)
                    elif 500 <= code < 600:
                        http_5xx.append(pkt)
        except (ValueError, IndexError):
            pass

    # ── SSH brute-force ────────────────────────────────────────────────────
    ssh_packets  = [pkt for pkt in tcp_packets if pkt[TCP].dport == 22]
    ssh_attempts: defaultdict[str, int] = defaultdict(int)
    for pkt in ssh_packets:
        ssh_attempts[pkt[IP].src] += 1
    brute_force_ips = [ip for ip, count in ssh_attempts.items() if count > 5]

    # ── SYN flood ─────────────────────────────────────────────────────────
    # BUG FIX: threshold of 50 flagged internal hosts (192.168.3.131 with
    # 274 SYNs and 172.16.255.1 with 91) that are simply active clients.
    # Raised to 200 to target only genuinely anomalous SYN rates.
    syn_counts: defaultdict[str, int] = defaultdict(int)
    for pkt in tcp_packets:
        if pkt[TCP].flags == "S":
            syn_counts[pkt[IP].src] += 1
    syn_flood_ips = [ip for ip, c in syn_counts.items() if c > 200]

    # ── Port scan heuristic ───────────────────────────────────────────────
    ports_per_src: defaultdict[str, set] = defaultdict(set)
    for pkt in tcp_packets:
        ports_per_src[pkt[IP].src].add(pkt[TCP].dport)
    port_scan_ips = [ip for ip, ports in ports_per_src.items()
                     if len(ports) > 20]

    # ── Metrics dict ──────────────────────────────────────────────────────
    avg_latency = (round(sum(handshakes) / len(handshakes), 4)
                   if handshakes else 0.0)
    loss_pairs  = [k for k, v in packet_loss.items() if v > 5]

    metrics = {
        "Total DNS Packets":              len(dns_packets),
        "Failed DNS Queries":             len(failed_dns),
        "Total TCP Packets":              len(tcp_packets),
        "TCP Retransmissions":            len(retransmissions),
        "Total Handshakes":               len(handshakes),
        "Slow Handshakes (>0.5s)":        len(slow_handshakes),
        "Average Handshake Latency (s)":  avg_latency,
        "IP Pairs with Packet Loss":      len(loss_pairs),
        "ICMP Errors":                    len(icmp_errors),
        "HTTP 4xx Errors":                len(http_4xx),
        "HTTP 5xx Errors":                len(http_5xx),
        "SSH Brute-force IPs":            len(brute_force_ips),
        "SYN Flood IPs":                  len(syn_flood_ips),
        "Port Scan IPs":                  len(port_scan_ips),
    }

    # ── Recommendations ───────────────────────────────────────────────────
    recommendations: list[str] = []

    if len(failed_dns) > 0:
        recommendations.append(
            "DNS failures detected — check DNS server config or network connectivity.")
    if len(failed_dns) > 10:
        recommendations.append(
            "High DNS failure count — possible DNS server outage or misconfiguration.")
    if len(retransmissions) > 5:
        recommendations.append(
            "TCP retransmissions elevated — investigate network congestion or unstable links.")
    if len(retransmissions) > 20:
        recommendations.append(
            "TCP retransmissions critically high — check interface errors and link quality.")
    if slow_handshakes:
        recommendations.append(
            "Slow TCP handshakes detected — check latency, firewall rules, or routing.")
    for pair, loss in packet_loss.items():
        if loss > 5:
            recommendations.append(
                f"Packet loss >5 between {pair[0]} → {pair[1]} — investigate link quality.")
    if icmp_errors:
        recommendations.append(
            f"{len(icmp_errors)} ICMP error(s) detected — check routing and TTL settings.")
    if http_4xx:
        recommendations.append(
            f"{len(http_4xx)} HTTP 4xx error(s) — review client requests and server-side access rules.")
    if http_5xx:
        recommendations.append(
            f"{len(http_5xx)} HTTP 5xx error(s) — review server health and application logs.")
    if brute_force_ips:
        recommendations.append(
            f"Possible SSH brute-force from: {', '.join(brute_force_ips)} — consider blocking and auditing.")
    if syn_flood_ips:
        recommendations.append(
            f"Possible SYN flood from: {', '.join(syn_flood_ips)} — consider rate-limiting or firewall rules.")
    if port_scan_ips:
        recommendations.append(
            f"Possible port scan from: {', '.join(port_scan_ips)} — review firewall and IDS rules.")
    if not recommendations:
        recommendations.append("No significant anomalies detected.")

    # ── Save CSVs ─────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_file = os.path.join(output_folder, f"network_report_{timestamp}.csv")
    df_report   = pd.DataFrame({"Metric": list(metrics.keys()),
                                 "Value":  list(metrics.values())})
    df_report.to_csv(report_file, index=False)
    print(f"[+] Report saved:          {report_file}")

    rec_file  = os.path.join(output_folder, f"network_recommendations_{timestamp}.csv")
    df_rec    = pd.DataFrame({"Recommendation": recommendations})
    df_rec.to_csv(rec_file, index=False)
    print(f"[+] Recommendations saved: {rec_file}")

    # ── Graphs ────────────────────────────────────────────────────────────
    graph_folder = os.path.join(output_folder, "graphs")
    saved_graphs: list[str] = []

    def _save(name: str) -> str:
        path = os.path.join(graph_folder, f"{name}_{timestamp}.png")
        plt.savefig(path, dpi=120, bbox_inches="tight")
        plt.close()
        saved_graphs.append(path)
        print(f"[+] Graph saved:           {path}")
        return path

    # TCP retransmissions over time
    if retransmissions:
        times = [float(p.time) for p in retransmissions]
        plt.figure(figsize=(8, 4))
        plt.plot(times, range(1, len(times) + 1), marker="o")
        plt.title("TCP Retransmissions Over Time")
        plt.xlabel("Timestamp (s)")
        plt.ylabel("Cumulative Count")
        plt.grid(True)
        _save("tcp_retransmissions")

    # Packet loss per IP pair
    if loss_pairs:
        plt.figure(figsize=(max(8, len(loss_pairs) * 1.5), 5))
        plt.bar([f"{p[0]}→{p[1]}" for p in loss_pairs],
                [packet_loss[p] for p in loss_pairs], color="orange")
        plt.title("Packet Loss per IP Pair")
        plt.xticks(rotation=45, ha="right")
        plt.ylabel("Packets Lost")
        plt.tight_layout()
        _save("packet_loss")

    # Handshake latency distribution
    if handshakes:
        plt.figure(figsize=(8, 4))
        plt.hist(handshakes, bins=10, color="green", edgecolor="black")
        plt.title("TCP Handshake Latency Distribution")
        plt.xlabel("Latency (s)")
        plt.ylabel("Count")
        plt.grid(True)
        _save("handshake_latency")

    # ICMP errors over time
    if icmp_errors:
        times = [float(p.time) for p in icmp_errors]
        plt.figure(figsize=(8, 4))
        plt.plot(times, range(1, len(times) + 1), marker="x", color="red")
        plt.title("ICMP Errors Over Time")
        plt.xlabel("Timestamp (s)")
        plt.ylabel("Cumulative Count")
        plt.grid(True)
        _save("icmp_errors")

    # HTTP error counts
    if http_4xx or http_5xx:
        plt.figure(figsize=(6, 4))
        plt.bar(["4xx Errors", "5xx Errors"],
                [len(http_4xx), len(http_5xx)], color=["orange", "red"])
        plt.title("HTTP Error Counts")
        plt.ylabel("Count")
        _save("http_errors")

    # SSH brute-force attempts
    if brute_force_ips:
        counts = [ssh_attempts[ip] for ip in brute_force_ips]
        plt.figure(figsize=(max(8, len(brute_force_ips) * 1.5), 5))
        plt.bar(brute_force_ips, counts, color="purple")
        plt.title("SSH Connection Attempts per IP (Brute-force)")
        plt.ylabel("Attempt Count")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        _save("ssh_bruteforce")

    print(f"[+] Analysis complete. {len(saved_graphs)} graph(s) saved.")

    return {
        "report_file":          report_file,
        "recommendation_file":  rec_file,
        "graphs":               saved_graphs,
        "metrics":              metrics,
        "recommendations":      recommendations,
    }


# ---------------------------------------------------------------------------
# Live capture helper
# ---------------------------------------------------------------------------

def live_capture(interface: str, duration: int, output_folder: str) -> str:
    """Capture live traffic with tshark, return path to saved pcap."""
    os.makedirs(output_folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    live_file = os.path.join(output_folder, f"live_capture_{timestamp}.pcap")
    print(f"[*] Capturing on {interface} for {duration}s → {live_file}")
    subprocess.run(
        ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", live_file],
        check=True,
    )
    print(f"[+] Live capture saved: {live_file}")
    return live_file


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _build_parser():
    import argparse
    p = argparse.ArgumentParser(
        description="Automated Network Troubleshooting & Mini IDS Tool"
    )
    sub = p.add_subparsers(dest="command", required=True)

    # analyse sub-command
    a = sub.add_parser("analyse", help="Analyse a .pcap file")
    a.add_argument("-i", "--input",  required=True,
                   help="Path to .pcap file")
    a.add_argument("-o", "--output", default="reports",
                   help="Folder for reports/graphs (default: reports)")

    # capture sub-command
    c = sub.add_parser("capture", help="Capture live traffic then analyse")
    c.add_argument("--interface", "-I", required=True,
                   help="Network interface (e.g. eth0)")
    c.add_argument("--duration",  "-d", type=int, default=30,
                   help="Capture duration in seconds (default: 30)")
    c.add_argument("-o", "--output", default="reports",
                   help="Folder for reports/graphs (default: reports)")

    return p


def main():
    parser = _build_parser()
    args   = parser.parse_args()

    if args.command == "analyse":
        results = run_analysis(args.input, args.output)

    elif args.command == "capture":
        pcap_file = live_capture(args.interface, args.duration, args.output)
        results   = run_analysis(pcap_file, args.output)

    # Print summary to terminal
    print("\n=== Metrics ===")
    for k, v in results["metrics"].items():
        print(f"  {k}: {v}")

    print("\n=== Recommendations ===")
    for r in results["recommendations"]:
        print(f"  • {r}")


if __name__ == "__main__":
    main()

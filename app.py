"""
app.py — Enhanced Streamlit dashboard for the Network Troubleshooting & Mini IDS Tool.

Run with:
    streamlit run app.py
"""

import io
import os
import json
import tempfile
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Network Analyser",
    page_icon="🛡️",
    layout="wide",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        border-radius: 10px; padding: 16px 20px;
        border-left: 4px solid #6c63ff;
        margin-bottom: 10px; background: #f8f9fa;
    }
    .metric-card.danger  { border-left-color:#e74c3c; background:#fff5f5; }
    .metric-card.warning { border-left-color:#f39c12; background:#fffbf0; }
    .metric-card.success { border-left-color:#27ae60; background:#f0fff4; }
    .metric-card.info    { border-left-color:#2980b9; background:#f0f8ff; }
    .metric-title { font-size:12px; color:#666; text-transform:uppercase; letter-spacing:0.5px; }
    .metric-value { font-size:28px; font-weight:700; color:#1a1a2e; margin-top:2px; }
    .metric-label { font-size:11px; color:#999; margin-top:2px; }
    .section-header {
        font-size:18px; font-weight:600; color:#1a1a2e;
        border-bottom:2px solid #6c63ff;
        padding-bottom:6px; margin:24px 0 14px;
    }
    .rec-critical { background:#fff0f0; border-left:3px solid #e74c3c; padding:10px 14px; border-radius:6px; margin:6px 0; }
    .rec-warning  { background:#fffbf0; border-left:3px solid #f39c12; padding:10px 14px; border-radius:6px; margin:6px 0; }
    .rec-ok       { background:#f0fff4; border-left:3px solid #27ae60; padding:10px 14px; border-radius:6px; margin:6px 0; }
    .tag { display:inline-block; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:600; margin:2px; }
    .tag-red    { background:#fde8e8; color:#c0392b; }
    .tag-orange { background:#fef3e2; color:#d35400; }
    .tag-blue   { background:#e8f4fd; color:#1a6fa0; }
    .tag-green  { background:#e8f8f0; color:#1e8449; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Network Analyser")
    st.markdown("---")
    st.markdown("Upload a `.pcap` file and click **Analyse** to get a full network health report.")
    st.markdown("---")
    st.markdown("**Detects:**")
    for item in [
        "TCP retransmissions", "DNS failures", "Packet loss per IP pair",
        "ICMP errors", "HTTP 4xx / 5xx", "SSH brute-force",
        "SYN flood attempts", "Port scans", "Slow handshakes"
    ]:
        st.markdown(f"• {item}")
    st.markdown("---")
    st.caption("Built on Scapy · Pandas · Matplotlib")

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ Network Troubleshooting & Mini IDS")
st.markdown("Upload a packet capture file to analyse TCP health, detect intrusion indicators, and get actionable recommendations.")

col_upload, col_folder = st.columns([3, 1])
with col_upload:
    uploaded = st.file_uploader("Upload PCAP file", type=["pcap", "pcapng"], label_visibility="collapsed")
with col_folder:
    output_folder = st.text_input("Output folder", value="reports")

run_btn = st.button("▶  Analyse", type="primary", disabled=(uploaded is None))

# ── Analysis ──────────────────────────────────────────────────────────────────
if run_btn and uploaded:
    from analyze_pcap import run_analysis

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    bar = st.progress(0, text="Loading packets…")
    try:
        bar.progress(25, text="Analysing TCP, DNS, ICMP…")
        results = run_analysis(tmp_path, output_folder)
        bar.progress(100, text="Done!")
        bar.empty()
    except Exception as exc:
        bar.empty()
        st.error(f"❌ Analysis failed: {exc}")
        st.stop()
    finally:
        os.unlink(tmp_path)

    m   = results["metrics"]
    rec = results["recommendations"]

    st.success(f"✅ Analysis complete — **{uploaded.name}**")

    # ── KPI cards ─────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">Overview</div>', unsafe_allow_html=True)

    def kpi_card(col, title, value, unit, style):
        col.markdown(f"""
        <div class="metric-card {style}">
            <div class="metric-title">{title}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-label">{unit}</div>
        </div>""", unsafe_allow_html=True)

    ids_total = m["SSH Brute-force IPs"] + m["SYN Flood IPs"] + m["Port Scan IPs"]
    k1,k2,k3,k4,k5,k6 = st.columns(6)
    kpi_card(k1, "TCP Packets",       m["Total TCP Packets"],         "",                   "info")
    kpi_card(k2, "Retransmissions",   m["TCP Retransmissions"],       "packets",            "danger" if m["TCP Retransmissions"]>20 else "warning" if m["TCP Retransmissions"]>5 else "success")
    kpi_card(k3, "DNS Failures",      m["Failed DNS Queries"],        f"/ {m['Total DNS Packets']} total", "danger" if m["Failed DNS Queries"]>10 else "warning" if m["Failed DNS Queries"]>0 else "success")
    kpi_card(k4, "Packet Loss Pairs", m["IP Pairs with Packet Loss"], "IP pairs",           "danger" if m["IP Pairs with Packet Loss"]>10 else "warning" if m["IP Pairs with Packet Loss"]>0 else "success")
    kpi_card(k5, "ICMP Errors",       m["ICMP Errors"],               "errors",             "danger" if m["ICMP Errors"]>5 else "warning" if m["ICMP Errors"]>0 else "success")
    kpi_card(k6, "IDS Alerts",        ids_total,                      "active threats",     "danger" if ids_total>0 else "success")

    # ── Main two-column layout ─────────────────────────────────────────────
    left, right = st.columns([1, 1], gap="large")

    with left:
        st.markdown('<div class="section-header">Full Metrics Table</div>', unsafe_allow_html=True)

        df_m = pd.DataFrame({"Metric": list(m.keys()), "Value": list(m.values())})

        def row_style(row):
            v = row["Value"]
            n = row["Metric"]
            if isinstance(v, (int, float)) and v > 0:
                if any(w in n for w in ["Retransmission","Brute","Flood","Scan","5xx"]):
                    return ["background-color:#fff5f5"]*2
                if any(w in n for w in ["Loss","Failed","Slow","4xx","ICMP"]):
                    return ["background-color:#fffbf0"]*2
            return [""]*2

        st.dataframe(df_m.style.apply(row_style, axis=1),
                     use_container_width=True, hide_index=True, height=480)

        st.markdown('<div class="section-header">Handshake Latency</div>', unsafe_allow_html=True)
        hs1, hs2, hs3 = st.columns(3)
        hs1.metric("Total Handshakes",  m["Total Handshakes"])
        hs2.metric("Slow (>0.5 s)",     m["Slow Handshakes (>0.5s)"],
                   delta=f"{m['Slow Handshakes (>0.5s)']} slow" if m["Slow Handshakes (>0.5s)"] else None,
                   delta_color="inverse")
        hs3.metric("Avg Latency",       f"{m['Average Handshake Latency (s)']} s")

    with right:
        st.markdown('<div class="section-header">Recommendations</div>', unsafe_allow_html=True)
        critical_kw = ["critically","brute-force","flood","scan","5xx"]
        ok_kw       = ["no significant"]

        PREVIEW_COUNT = 10

        def render_rec(r):
            rl = r.lower()
            if any(k in rl for k in ok_kw):
                cls, icon = "rec-ok", "✅"
            elif any(k in rl for k in critical_kw):
                cls, icon = "rec-critical", "🚨"
            else:
                cls, icon = "rec-warning", "⚠️"
            st.markdown(f'<div class="{cls}">{icon} {r}</div>', unsafe_allow_html=True)

        if len(rec) <= PREVIEW_COUNT:
            for r in rec:
                render_rec(r)
        else:
            # Show first PREVIEW_COUNT items always
            for r in rec[:PREVIEW_COUNT]:
                render_rec(r)

            # Toggle key per-session
            toggle_key = "rec_show_all"
            if toggle_key not in st.session_state:
                st.session_state[toggle_key] = False

            remaining = len(rec) - PREVIEW_COUNT
            if st.session_state[toggle_key]:
                for r in rec[PREVIEW_COUNT:]:
                    render_rec(r)
                if st.button(f"▲ Show less", key="rec_toggle_btn", use_container_width=True):
                    st.session_state[toggle_key] = False
                    st.rerun()
            else:
                if st.button(f"▼ Show {remaining} more recommendation{'s' if remaining != 1 else ''}", key="rec_toggle_btn", use_container_width=True):
                    st.session_state[toggle_key] = True
                    st.rerun()

        st.markdown('<div class="section-header">IDS Summary</div>', unsafe_allow_html=True)
        tags = []
        if m["SSH Brute-force IPs"] > 0:
            tags.append(f'<span class="tag tag-red">SSH Brute-force · {m["SSH Brute-force IPs"]} IP(s)</span>')
        if m["SYN Flood IPs"] > 0:
            tags.append(f'<span class="tag tag-red">SYN Flood · {m["SYN Flood IPs"]} IP(s)</span>')
        if m["Port Scan IPs"] > 0:
            tags.append(f'<span class="tag tag-orange">Port Scan · {m["Port Scan IPs"]} IP(s)</span>')
        if m["ICMP Errors"] > 0:
            tags.append(f'<span class="tag tag-orange">ICMP Errors · {m["ICMP Errors"]}</span>')
        if m["HTTP 4xx Errors"] > 0:
            tags.append(f'<span class="tag tag-orange">HTTP 4xx · {m["HTTP 4xx Errors"]}</span>')
        if m["HTTP 5xx Errors"] > 0:
            tags.append(f'<span class="tag tag-red">HTTP 5xx · {m["HTTP 5xx Errors"]}</span>')
        if not tags:
            tags.append('<span class="tag tag-green">No IDS alerts detected</span>')
        st.markdown(" ".join(tags), unsafe_allow_html=True)

    # ── Charts ────────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">Protocol & Threat Breakdown</div>', unsafe_allow_html=True)

    fig, axes = plt.subplots(1, 3, figsize=(14, 4))
    fig.patch.set_facecolor("#ffffff")

    # Donut: traffic composition
    ax1 = axes[0]
    lbls = ["TCP", "DNS", "ICMP"]
    vals = [m["Total TCP Packets"], m["Total DNS Packets"], m["ICMP Errors"]]
    cols = ["#6c63ff", "#00b4d8", "#f77f00"]
    pairs = [(l, v, c) for l, v, c in zip(lbls, vals, cols) if v > 0]
    if pairs:
        ls, vs, cs = zip(*pairs)
        wedges, texts, autotexts = ax1.pie(
            vs, labels=ls, colors=cs, autopct="%1.0f%%",
            startangle=140, pctdistance=0.75,
            wedgeprops=dict(width=0.55, edgecolor="white", linewidth=2))
        for at in autotexts:
            at.set_fontsize(9); at.set_color("white"); at.set_fontweight("bold")
    ax1.set_title("Traffic composition", fontsize=11, fontweight="600", pad=10)

    # Horizontal bar: TCP health
    ax2 = axes[1]
    tcp_m = {
        "Retransmissions":    m["TCP Retransmissions"],
        "Slow handshakes":    m["Slow Handshakes (>0.5s)"],
        "Packet loss pairs":  m["IP Pairs with Packet Loss"],
    }
    bcols = ["#e74c3c" if v>20 else "#f39c12" if v>5 else "#27ae60" for v in tcp_m.values()]
    bars  = ax2.barh(list(tcp_m.keys()), list(tcp_m.values()), color=bcols, height=0.45, edgecolor="none")
    for bar, val in zip(bars, tcp_m.values()):
        ax2.text(bar.get_width()+0.3, bar.get_y()+bar.get_height()/2,
                 str(val), va="center", fontsize=10, fontweight="600")
    ax2.set_title("TCP health", fontsize=11, fontweight="600", pad=10)
    ax2.set_xlabel("Count", fontsize=9)
    ax2.spines[["top","right"]].set_visible(False)
    ax2.tick_params(axis="y", labelsize=9)

    # Bar: IDS threats
    ax3 = axes[2]
    ids_m = {
        "SSH\nBrute-force": m["SSH Brute-force IPs"],
        "SYN\nFlood":       m["SYN Flood IPs"],
        "Port\nScans":      m["Port Scan IPs"],
        "ICMP\nErrors":     m["ICMP Errors"],
        "HTTP\n4xx":        m["HTTP 4xx Errors"],
    }
    ic = ["#e74c3c","#c0392b","#f39c12","#e67e22","#3498db"]
    xs = np.arange(len(ids_m))
    b  = ax3.bar(xs, list(ids_m.values()), color=ic, width=0.5, edgecolor="none")
    for bar, val in zip(b, ids_m.values()):
        ax3.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
                 str(val), ha="center", fontsize=9, fontweight="600")
    ax3.set_xticks(xs)
    ax3.set_xticklabels(list(ids_m.keys()), fontsize=8)
    ax3.set_title("IDS threat breakdown", fontsize=11, fontweight="600", pad=10)
    ax3.spines[["top","right"]].set_visible(False)

    plt.tight_layout(pad=2.0)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    buf.seek(0); plt.close(fig)
    st.image(buf, use_container_width=True)

    # ── DNS failure bar ────────────────────────────────────────────────────
    if m["Total DNS Packets"] > 0:
        st.markdown('<div class="section-header">DNS Failure Rate</div>', unsafe_allow_html=True)
        dns_pct = round(m["Failed DNS Queries"] / m["Total DNS Packets"] * 100, 1)
        gc1, gc2 = st.columns([1, 3])
        with gc1:
            icon = "🔴" if dns_pct > 50 else "🟡" if dns_pct > 20 else "🟢"
            st.metric(f"{icon} DNS Failure Rate", f"{dns_pct}%",
                      delta=f"{m['Failed DNS Queries']} of {m['Total DNS Packets']} failed",
                      delta_color="inverse")
        with gc2:
            fig2, ax = plt.subplots(figsize=(8, 0.65))
            fig2.patch.set_facecolor("#ffffff")
            ax.barh([""], [dns_pct],         color="#e74c3c",  height=0.4)
            ax.barh([""], [100 - dns_pct],   color="#27ae60",  height=0.4, left=[dns_pct])
            ax.set_xlim(0, 100); ax.set_xlabel("% queries", fontsize=8)
            ax.spines[["top","right","left"]].set_visible(False)
            ax.tick_params(left=False, labelleft=False)
            ax.legend(handles=[
                mpatches.Patch(color="#e74c3c", label=f"Failed ({dns_pct}%)"),
                mpatches.Patch(color="#27ae60", label=f"OK ({100-dns_pct}%)"),
            ], loc="center right", fontsize=8, frameon=False)
            plt.tight_layout()
            buf2 = io.BytesIO()
            fig2.savefig(buf2, format="png", dpi=150, bbox_inches="tight")
            buf2.seek(0); plt.close(fig2)
            st.image(buf2, use_container_width=True)

    # ── Scapy-generated graphs ─────────────────────────────────────────────
    if results["graphs"]:
        st.markdown('<div class="section-header">Detailed Graphs</div>', unsafe_allow_html=True)
        gcols = st.columns(2)
        for i, gpath in enumerate(results["graphs"]):
            if os.path.isfile(gpath):
                with gcols[i % 2]:
                    parts = os.path.basename(gpath).replace("_", " ").replace(".png", "").split()
                    # strip 15-char timestamp token at end
                    label = " ".join(p for p in parts if not (len(p) == 15 and p.isdigit())).title()
                    st.markdown(f"**{label}**")
                    st.image(gpath, use_container_width=True)

    # ── Downloads ─────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">Download Reports</div>', unsafe_allow_html=True)
    d1, d2, d3 = st.columns(3)
    with d1:
        with open(results["report_file"], "rb") as f:
            st.download_button("📥 Metrics CSV", data=f,
                               file_name=os.path.basename(results["report_file"]),
                               mime="text/csv", use_container_width=True)
    with d2:
        with open(results["recommendation_file"], "rb") as f:
            st.download_button("📥 Recommendations CSV", data=f,
                               file_name=os.path.basename(results["recommendation_file"]),
                               mime="text/csv", use_container_width=True)
    with d3:
        json_out = json.dumps({
            "analysed_at": datetime.now().isoformat(),
            "file": uploaded.name,
            "metrics": m,
            "recommendations": rec,
        }, indent=2)
        st.download_button("📥 Full JSON Report", data=json_out,
                           file_name=f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                           mime="application/json", use_container_width=True)

    st.markdown("---")
    st.caption(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ·  File: {uploaded.name}")

else:
    # Landing state
    st.markdown("---")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.info("**📁 Step 1**\n\nUpload your `.pcap` file using the uploader above.")
    with c2:
        st.info("**▶ Step 2**\n\nClick **Analyse** to run full packet inspection.")
    with c3:
        st.info("**📊 Step 3**\n\nReview metrics, graphs, and download your reports.")

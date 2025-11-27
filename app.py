import streamlit as st
from datetime import datetime
import re

from src.scanner import NetworkScanner
from src.utils import run_ping

st.set_page_config(
    page_title="NetPulse",
    page_icon="📡",
    layout="wide"
)

# -------------------------------------------------
# Sidebar Style
# -------------------------------------------------
st.sidebar.markdown("""
<div style="
    background-color:#1f2937;
    padding:18px;
    border-radius:12px;
    color:white;
">
<h2 style="margin-top:0;">📡 NetPulse</h2>
<b>Network Monitoring Suite</b>
</div>
""", unsafe_allow_html=True)


mode = st.sidebar.radio(
    "🧭 Navigation",
    ["🏠 Network Overview", "🔍 Deep Port Scan", "⚡ Connectivity Test (Ping)"]
)

scanner = NetworkScanner()


# -------------------------------------------------
# MAIN UI
# -------------------------------------------------
def header(title):
    st.markdown(f"## {title}")
    st.markdown("---")


# -------------------------------------------------
# NETWORK OVERVIEW
# -------------------------------------------------
if mode == "🏠 Network Overview":
    header("🏠 Network Overview")

    target = st.text_input("Target CIDR Range", "192.168.1.0/24")

    if st.button("Start Scan", type="primary"):
        df = scanner.scan_network(target)
        if not df.empty:
            st.dataframe(df, use_container_width=True)
        else:
            st.error("No hosts found.")


# -------------------------------------------------
# DEEP PORT SCAN
# -------------------------------------------------
elif mode == "🔍 Deep Port Scan":
    header("🔍 Deep Port Scan")

    ip = st.text_input("Target Host", "192.168.1.1")

    if st.button("Scan Ports", type="primary"):
        df = scanner.scan_ports(ip)
        if not df.empty:
            st.table(df)
        else:
            st.error("No ports detected or host unreachable.")


# -------------------------------------------------
# CONNECTIVITY TEST (PING) – Full Dashboard
# -------------------------------------------------
elif mode == "⚡ Connectivity Test (Ping)":
    header("⚡ Connectivity Test (Ping)")

    col1, col2 = st.columns([2, 1])
    host = col1.text_input("Host to Ping", placeholder="example: 8.8.8.8 / google.com")
    count = col2.number_input("Ping Count", min_value=1, max_value=20, value=4)

    if st.button("Run Ping Test", type="primary"):
        if not host.strip():
            st.warning("⚠ กรุณากรอก Host ก่อนครับเฮีย")
        else:
            with st.spinner("🔄 Running ping test..."):
                output, code = run_ping(host, count)

        # Raw output
        st.markdown("### 📄 Ping Raw Output")
        st.code(output)

        # Regex support Windows / Linux / Mac
        latency = re.findall(r'time[=<\s]+([\d\.]+)\s*ms', output)
        latency = [float(x) for x in latency]

        if latency:
            avg_lat = sum(latency) / len(latency)
            max_lat = max(latency)
            min_lat = min(latency)

            # STATUS badge
            status = "🟢 Success" if code == 0 else "🔴 Failed"
            color = "green" if code == 0 else "red"

            st.markdown(
                f"<h3>Status: <span style='color:{color};'>{status}</span></h3>",
                unsafe_allow_html=True
            )

            # METRICS
            st.markdown("### 📊 Latency Statistics")
            m1, m2, m3 = st.columns(3)
            m1.metric("Avg Latency", f"{avg_lat:.2f} ms")
            m2.metric("Max Latency", f"{max_lat:.2f} ms")
            m3.metric("Min Latency", f"{min_lat:.2f} ms")

            # GRAPH
            st.markdown("### 📈 Latency Graph")
            st.line_chart(latency)

        else:
            st.error("❌ ไม่มีค่า latency — Host อาจไม่ตอบสนอง")

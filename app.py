import streamlit as st
import nmap
import ipaddress
import subprocess
import platform
import re
import pandas as pd
from datetime import datetime

# ---------------------------------------------
# Validate CIDR (fixed strict=False)
# ---------------------------------------------
def validate_cidr(cidr: str):
    try:
        if "/" not in cidr:
            # ถ้าใส่แค่ IP เดี่ยว → ใช้ /32 ให้เลย
            cidr = cidr.strip() + "/32"

        ipaddress.ip_network(cidr, strict=False)
        return True
    except:
        return False


# ---------------------------------------------
# Run Ping (Windows / Linux / Mac)
# ---------------------------------------------
def run_ping(host: str, count: int = 4):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, str(count), host]

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate()

        if proc.returncode != 0 and stderr:
            return stderr, proc.returncode

        return stdout, proc.returncode

    except Exception as e:
        return f"Ping Error: {e}", 1


# ---------------------------------------------
# Network Scan (Nmap)
# ---------------------------------------------
def scan_network(cidr: str):
    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=cidr, arguments='-sn')
    except Exception as e:
        return None, f"Scan error: {e}"

    hosts = nm.all_hosts()
    if len(hosts) == 0:
        return pd.DataFrame(), None

    data = []
    for host in hosts:
        mac = nm[host]['addresses'].get('mac', '-')
        vendor = nm[host]['vendor'].get(mac, 'Unknown')
        hostname = nm[host].hostname() or "-"

        data.append({
            "IP Address": host,
            "Status": "🟢 Online",
            "MAC Address": mac,
            "Vendor": vendor,
            "Hostname": hostname,
            "Last Seen": datetime.now().strftime("%H:%M:%S")
        })

    return pd.DataFrame(data), None


# ---------------------------------------------
# Port Scan
# ---------------------------------------------
def scan_ports(ip: str):
    nm = nmap.PortScanner()

    try:
        nm.scan(ip, "1-1024")
    except Exception as e:
        return None, f"Port scan error: {e}"

    result = []
    try:
        tcp_ports = nm[ip]["tcp"]
    except:
        return pd.DataFrame(), None

    for port, info in tcp_ports.items():
        result.append({
            "Port": port,
            "State": info.get("state", "-"),
            "Service": info.get("name", "-"),
            "Version": info.get("version", "-")
        })

    return pd.DataFrame(result), None


# ---------------------------------------------
# Streamlit App
# ---------------------------------------------
st.set_page_config(page_title="NetPulse", page_icon="📡", layout="wide")

st.sidebar.markdown("""
<div style="background-color:#1f2937;padding:18px;border-radius:12px;color:white;">
<h2 style="margin-top:0;">📡 NetPulse</h2>
<b>Network Monitoring Suite</b>
</div>
""", unsafe_allow_html=True)

mode = st.sidebar.radio(
    "🧭 Navigation",
    ["🏠 Network Overview", "🔍 Deep Port Scan", "⚡ Connectivity Test (Ping)"]
)


# -------------------------------
# HEADER helper
# -------------------------------
def header(title):
    st.markdown(f"## {title}")
    st.markdown("---")


# ---------------------------------------------
# MODE: Network Overview
# ---------------------------------------------
if mode == "🏠 Network Overview":
    header("🏠 Network Overview")

    target = st.text_input("Target CIDR Range", "192.168.13.13/24")

    if st.button("Start Scan", type="primary"):

        if not validate_cidr(target):
            st.error("CIDR ไม่ถูกต้องครับเฮีย ❌")
        else:
            df, err = scan_network(target)

            if err:
                st.error(err)
            elif df.empty:
                st.warning("ไม่พบอุปกรณ์ในเครือข่ายครับเฮีย")
            else:
                st.dataframe(df, use_container_width=True)


# ---------------------------------------------
# MODE: Deep Port Scan
# ---------------------------------------------
elif mode == "🔍 Deep Port Scan":
    header("🔍 Deep Port Scan")

    ip = st.text_input("Target Host", "192.168.13.1")

    if st.button("Scan Ports", type="primary"):
        df, err = scan_ports(ip)

        if err:
            st.error(err)
        elif df.empty:
            st.warning("ไม่พบ port ที่เปิดครับเฮีย")
        else:
            st.dataframe(df, use_container_width=True)


# ---------------------------------------------
# MODE: PING TEST
# ---------------------------------------------
elif mode == "⚡ Connectivity Test (Ping)":
    header("⚡ Connectivity Test (Ping)")

    col1, col2 = st.columns([2, 1])
    host = col1.text_input("Host to Ping", "8.8.8.8")
    count = col2.number_input("Ping Count", 1, 20, 4)

    if st.button("Run Ping Test", type="primary"):
        output, code = run_ping(host, count)

        st.markdown("### 📄 Ping Raw Output")
        st.code(output)

        latency = re.findall(r'time[=<\s]+([\d\.]+)\s*ms', output)
        latency = [float(x) for x in latency]

        if latency:
            m1, m2, m3 = st.columns(3)
            m1.metric("Avg Latency", f"{sum(latency)/len(latency):.2f} ms")
            m2.metric("Max Latency", f"{max(latency):.2f} ms")
            m3.metric("Min Latency", f"{min(latency):.2f} ms")

            st.markdown("### 📈 Latency Graph")
            st.line_chart(latency)
        else:
            st.error("Ping ไม่มีผลลัพธ์ครับเฮีย ❌")

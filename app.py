import streamlit as st
from datetime import datetime

from src.scanner import NetworkScanner
from src.utils import run_ping

st.set_page_config(page_title="NetPulse", page_icon="📡", layout="wide")

def main():
    st.title("📡 NetPulse : Advanced Network Monitor")
    st.markdown("---")

    mode = st.sidebar.radio(
        "Select Mode",
        ["🏠 Network Overview", "🔍 Deep Port Scan", "⚡ Connectivity Test (Ping)"]
    )

    scanner = NetworkScanner()

    if mode == "🏠 Network Overview":
        target = st.text_input("CIDR", "192.168.1.0/24")
        if st.button("Start Scan"):
            df = scanner.scan_network(target)
            if not df.empty:
                st.dataframe(df)

    elif mode == "🔍 Deep Port Scan":
        ip = st.text_input("Target Host", "192.168.1.1")
        if st.button("Scan Ports"):
            df = scanner.scan_ports(ip)
            st.table(df)

    elif mode == "⚡ Connectivity Test (Ping)":
        host = st.text_input("Host to ping")
        if st.button("Ping"):
            output, code = run_ping(host)
            st.code(output)

if __name__ == "__main__":
    main()

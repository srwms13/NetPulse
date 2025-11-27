import nmap
import pandas as pd
from datetime import datetime
import streamlit as st


class NetworkScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            self.available = True
        except nmap.PortScannerError:
            self.nm = None
            self.available = False

    # ---------------------------
    # Scan Network
    # ---------------------------
    def scan_network(self, ip_range: str) -> pd.DataFrame:
        if not self.available:
            st.error("Nmap is not available.")
            return pd.DataFrame()

        progress = st.progress(0)
        status = st.empty()

        try:
            self.nm.scan(hosts=ip_range, arguments='-sn')
            hosts = self.nm.all_hosts()
            total = len(hosts)
            data = []

            for i, host in enumerate(hosts):
                progress.progress((i + 1) / total)

                mac = self.nm[host]['addresses'].get('mac', '-')
                vendor = self.nm[host]['vendor'].get(mac, 'Unknown')
                hostname = self.nm[host].hostname() or "-"

                data.append({
                    "IP Address": host,
                    "Status": "🟢 Online",
                    "MAC Address": mac,
                    "Vendor": vendor,
                    "Hostname": hostname,
                    "Last Seen": datetime.now().strftime("%H:%M:%S"),
                })

            progress.empty()
            status.success("Scan Complete ✔")

            return pd.DataFrame(data)

        except Exception as e:
            st.error(f"Scan error: {e}")
            return pd.DataFrame()

    # ---------------------------
    # Scan Ports
    # ---------------------------
    def scan_ports(self, ip: str) -> pd.DataFrame:
        if not self.available:
            st.error("Nmap is not installed.")
            return pd.DataFrame()

        try:
            result = self.nm.scan(ip, '1-1024')
            ports = []

            if "tcp" in result["scan"].get(ip, {}):
                for port, info in result["scan"][ip]["tcp"].items():
                    ports.append({
                        "Port": port,
                        "State": info.get("state"),
                        "Service": info.get("name"),
                        "Version": info.get("version"),
                    })

            return pd.DataFrame(ports)

        except Exception as e:
            st.error(f"Port scan error: {e}")
            return pd.DataFrame()

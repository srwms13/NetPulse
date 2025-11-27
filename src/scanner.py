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

    def scan_network(self, ip_range: str) -> pd.DataFrame:
        if not self.available:
            st.error("Nmap is not available.")
            return pd.DataFrame()

        progress = st.progress(0)
        results = []

        try:
            self.nm.scan(hosts=ip_range, arguments='-sn')
            hosts = self.nm.all_hosts()
            total = len(hosts)

            for idx, host in enumerate(hosts):
                progress.progress((idx + 1) / total)

                node = self.nm.get(host, {})
                addr = node.get("addresses", {})
                mac = addr.get("mac", "-")

                vendor_data = node.get("vendor", {})
                vendor = vendor_data.get(mac, "Unknown")

                hostnames = node.get("hostnames", [{}])
                hostname = hostnames[0].get("name", "-")

                results.append({
                    "IP Address": host,
                    "Status": "🟢 Online",
                    "MAC Address": mac,
                    "Vendor": vendor,
                    "Hostname": hostname,
                    "Last Seen": datetime.now().strftime("%H:%M:%S"),
                })

            progress.empty()
            return pd.DataFrame(results)

        except Exception as e:
            st.error(f"Scan error: {e}")
            return pd.DataFrame()

    def scan_ports(self, ip: str) -> pd.DataFrame:
        if not self.available:
            st.error("Nmap is not installed.")
            return pd.DataFrame()

        try:
            result = self.nm.scan(ip, '1-1024')
            node = result.get("scan", {}).get(ip)

            if not node or "tcp" not in node:
                st.error("Host ไม่ตอบสนอง หรือไม่พบข้อมูล Port ครับเฮีย")
                return pd.DataFrame()

            ports = []
            for port, info in node["tcp"].items():
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

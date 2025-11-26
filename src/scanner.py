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
            st.error("Nmap is not available in this environment.")
            return pd.DataFrame()

        progress_bar = st.progress(0)
        status_text = st.empty()

        try:
            self.nm.scan(hosts=ip_range, arguments='-sn')
            hosts_data = []
            all_hosts = self.nm.all_hosts()
            total_hosts = len(all_hosts)

            for i, host in enumerate(all_hosts):
                progress_bar.progress((i + 1) / total_hosts)

                mac = self.nm[host]['addresses'].get('mac', '-')
                vendor = self.nm[host]['vendor'].get(mac, 'Unknown Device')
                hostname = self.nm[host].hostname() or "-"

                hosts_data.append({
                    "IP Address": host,
                    "Status": "🟢 Online",
                    "MAC Address": mac,
                    "Vendor": vendor,
                    "Hostname": hostname,
                    "Last Seen": datetime.now().strftime("%H:%M:%S"),
                })

            progress_bar.empty()
            status_text.success("Scan complete!")

            return pd.DataFrame(hosts_data)

        except Exception as e:
            st.error(f"Scan error: {e}")
            return pd.DataFrame()

    def scan_ports(self, ip: str) -> pd.DataFrame:
        if not self.available:
            st.error("Nmap is not available.")
            return pd.DataFrame()

        try:
            result = self.nm.scan(ip, '1-1024')
            ports = []

            if 'tcp' in result['scan'].get(ip, {}):
                for port, info in result['scan'][ip]['tcp'].items():
                    ports.append({
                        "Port": port,
                        "State": info.get("state", "-"),
                        "Service": info.get("name", "-"),
                        "Version": info.get("version", "-"),
                    })

            return pd.DataFrame(ports)

        except Exception:
            return pd.DataFrame()

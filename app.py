import streamlit as st
import nmap
import pandas as pd
import subprocess
import platform
from datetime import datetime

# -------------------------------------------------------
# Page Configuration
# -------------------------------------------------------
st.set_page_config(
    page_title="NetPulse Pro",
    page_icon="📡",
    layout="wide"
)


# -------------------------------------------------------
# Network Scanner Class
# -------------------------------------------------------
class NetworkScanner:
    """
    Wrapper around python-nmap to provide:
    - Network scanning (ping / host discovery)
    - Port scanning
    This class is designed to fail gracefully in environments
    where nmap is not available (e.g. some cloud platforms).
    """

    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            self.available = True
        except nmap.PortScannerError:
            # nmap binary is not installed or cannot be found
            self.nm = None
            self.available = False

    def scan_network(self, ip_range: str) -> pd.DataFrame:
        """
        Scan a network range and return results as a pandas DataFrame.

        :param ip_range: Target network in CIDR format (e.g. 192.168.1.0/24)
        """
        if not self.available:
            st.error(
                "Network scanning is not available in this environment. "
                "The nmap binary is missing or not allowed."
            )
            return pd.DataFrame()

        progress_bar = st.progress(0)
        status_text = st.empty()

        status_text.text(f"🚀 Scanning network: {ip_range}...")

        try:
            # -sn: Ping Scan (no port scan – faster)
            self.nm.scan(hosts=ip_range, arguments='-sn')

            hosts_data = []
            all_hosts = self.nm.all_hosts()
            total_hosts = len(all_hosts)

            for i, host in enumerate(all_hosts):
                # Update Progress Bar
                if total_hosts > 0:
                    progress = (i + 1) / total_hosts
                    progress_bar.progress(progress)

                # Extract information
                host_state = self.nm[host].state()

                mac = self.nm[host]['addresses'].get('mac', '-')
                vendor = self.nm[host]['vendor'].get(mac, 'Unknown Device')
                hostname = self.nm[host].hostname() or "-"

                hosts_data.append({
                    "IP Address": host,
                    "Status": "🟢 Online" if host_state == 'up' else "🔴 Offline",
                    "MAC Address": mac,
                    "Vendor": vendor,
                    "Hostname": hostname,
                    "Last Seen": datetime.now().strftime("%H:%M:%S"),
                })

            progress_bar.empty()
            status_text.success(f"✅ Scan complete! Found {len(hosts_data)} devices.")

            return pd.DataFrame(hosts_data)

        except Exception as e:
            progress_bar.empty()
            status_text.empty()
            st.error(f"Error during network scan: {e}")
            return pd.DataFrame()

    def scan_ports(self, ip: str) -> pd.DataFrame:
        """
        Scan ports 1–1024 on a given IP address and return results as a DataFrame.

        :param ip: Target IP address
        """
        if not self.available:
            st.error(
                "Port scanning is not available in this environment. "
                "The nmap binary is missing or not allowed."
            )
            return pd.DataFrame()

        try:
            # Scan TCP ports 1–1024
            scan_result = self.nm.scan(ip, '1-1024')
            ports_info = []

            if 'tcp' in scan_result['scan'].get(ip, {}):
                for port, info in scan_result['scan'][ip]['tcp'].items():
                    ports_info.append({
                        "Port": port,
                        "State": info.get('state', '-'),
                        "Service": info.get('name', '-'),
                        "Version": info.get('version', '-'),
                    })

            return pd.DataFrame(ports_info)

        except KeyError:
            # Happens when host is down or no data is returned
            return pd.DataFrame()
        except Exception as e:
            st.error(f"Error during port scan: {e}")
            return pd.DataFrame()


# -------------------------------------------------------
# Helper: Ping function (uses system ping)
# -------------------------------------------------------
def run_ping(host: str) -> tuple[str, int]:
    """
    Run a ping command for 4 packets and return (output, return_code).

    :param host: Hostname or IP address to ping
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', host]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()
        return_code = process.returncode

        if return_code != 0 and stderr:
            return stderr, return_code
        return stdout, return_code

    except Exception as e:
        return f"Ping execution error: {e}", 1


# -------------------------------------------------------
# Main UI
# -------------------------------------------------------
def main():
    st.title("📡 NetPulse Pro: Network Monitor")
    st.markdown(
        "A lightweight network monitoring and scanning dashboard built with **Python**, "
        "**Streamlit**, and **Nmap**."
    )
    st.markdown("---")

    # Sidebar controls
    st.sidebar.header("⚙️ Control Panel")
    mode = st.sidebar.radio(
        "Select Mode:",
        [
            "🏠 Network Overview",
            "🔍 Deep Port Scan",
            "⚡ Connectivity Test (Ping)",
        ],
    )

    scanner = NetworkScanner()

    # ---------------------------------------------------
    # 1. Network Overview Mode
    # ---------------------------------------------------
    if mode == "🏠 Network Overview":
        st.subheader("Subnet Scanner")

        col1, col2 = st.columns([3, 1])

        with col1:
            target_ip = st.text_input(
                "Target Network (CIDR)",
                "192.168.1.0/24",
                help="Example: 192.168.0.0/24",
            )
        with col2:
            st.write("")  # Spacer
            st.write("")
            start_btn = st.button("🚀 Start Scan", use_container_width=True)

        if start_btn:
            if not target_ip.strip():
                st.warning("Please enter a valid network in CIDR format.")
            else:
                df = scanner.scan_network(target_ip)

                if not df.empty:
                    # Metrics
                    total_devices = len(df)
                    online_devices = len(df[df['Status'] == "🟢 Online"])

                    m1, m2, m3 = st.columns(3)
                    m1.metric("Total Devices", total_devices)
                    m2.metric("Online Devices", f"{online_devices} Active")
                    m3.metric("Scan Time", datetime.now().strftime("%H:%M"))

                    # Results table
                    st.markdown("### Scan Results")
                    st.dataframe(df, use_container_width=True)

                    # Download CSV
                    csv = df.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        "📥 Download Report (CSV)",
                        csv,
                        "scan_report.csv",
                        "text/csv",
                    )
                else:
                    st.warning(
                        "No devices found, the network might be unreachable, "
                        "or the format may be invalid."
                    )

    # ---------------------------------------------------
    # 2. Port Scan Mode
    # ---------------------------------------------------
    elif mode == "🔍 Deep Port Scan":
        st.subheader("Device Inspector (Port Scanner)")

        target_host = st.text_input(
            "Target IP Address",
            "192.168.1.1",
            help="Enter an IP address to scan ports 1–1024",
        )

        if st.button("🔍 Scan Ports"):
            if target_host.strip():
                with st.spinner(f"Analyzing {target_host}..."):
                    port_df = scanner.scan_ports(target_host)

                if not port_df.empty:
                    st.success(f"✅ Found {len(port_df)} open TCP ports.")
                    st.table(port_df.sort_values("Port"))
                else:
                    st.warning("No open ports found or the host is down.")
            else:
                st.warning("Please enter an IP address.")

    # ---------------------------------------------------
    # 3. Ping Mode
    # ---------------------------------------------------
    elif mode == "⚡ Connectivity Test (Ping)":
        st.subheader("Quick Ping Tool")

        host_ping = st.text_input(
            "IP Address or Hostname to Ping",
            "",
            help="Example: 8.8.8.8 or google.com",
        )

        if st.button("Ping Now"):
            if host_ping.strip():
                with st.spinner(f"Pinging {host_ping}..."):
                    output, code = run_ping(host_ping)

                if code == 0:
                    st.success(f"✅ {host_ping} is reachable!")
                else:
                    st.error(f"❌ {host_ping} seems unreachable.")

                with st.expander("View Ping Output"):
                    st.code(output)
            else:
                st.warning("Please enter an IP address or hostname.")


if __name__ == "__main__":
    main()

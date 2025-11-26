# 📡 NetPulse -- Network Scanner & Monitoring Dashboard

NetPulse is a lightweight **network discovery**, **port scanning**, and
**connectivity testing** dashboard built with **Python**, **Streamlit**,
and **Nmap**.

It provides a clean, real-time UI for quickly inspecting devices and
services on your local network.

------------------------------------------------------------------------

## ✨ Features

### 🏠 Subnet Scanner

-   Scan any CIDR (e.g., `192.168.1.0/24`)
-   Detect active devices in real time
-   Shows: IP, MAC, vendor, hostname, last-seen
-   Export results (.csv)

### 🔍 Port Scanner

-   TCP port scan (1--1024)
-   Shows port state, service name, version (if available)

### ⚡ Ping Tester

-   Ping any host/IP
-   Displays raw output & latency

### 📊 Modern Dashboard UI

-   Progress indicators
-   Clear section layout
-   Works in browser locally or via Docker

------------------------------------------------------------------------

## 🛠 Tech Stack

-   **Python 3.x**
-   **Streamlit** -- web dashboard
-   **Nmap / python-nmap** -- scanning engine
-   **pandas** -- data handling
-   **Docker** (optional)

------------------------------------------------------------------------

## 🚀 Getting Started

### 1. Clone the repository

``` bash
git clone https://github.com/<your-username>/netpulse.git
cd netpulse
```

### 2. Install dependencies

``` bash
pip install -r requirements.txt
```

### 3. Run the dashboard

``` bash
streamlit run app.py
```

------------------------------------------------------------------------

## 📦 Project Structure

    NetPulse/
    │── app.py                 # Main Streamlit app (UI + logic)
    │── src/
    │    ├── scanner.py        # Network & port scanning engine
    │    └── utils.py          # Ping + shared helper functions
    │
    │── requirements.txt       # Dependencies
    │── README.md              # Documentation
    │── .gitignore             # Ignored files

------------------------------------------------------------------------

## 🐳 Docker (Optional)

### Build image

``` bash
docker build -t netpulse .
```

### Run container

``` bash
docker run -p 8501:8501 netpulse
```

------------------------------------------------------------------------

## 📸 Demo Preview

*Add screenshots or GIFs here after hosting the demo.*

------------------------------------------------------------------------

## 🤝 Contributing

Pull requests are welcome.\
For major changes, please open an issue to discuss your proposal.

------------------------------------------------------------------------

## 📄 License

MIT License\
© 2025 NetPulse

# 📡 NetPulse – Network Scanner & Monitoring Dashboard

NetPulse is a lightweight **network monitoring** and **scanning** dashboard built with  
**Python**, **Streamlit**, and **Nmap**. It provides a simple, visual way to:

- Discover devices on your network  
- Inspect open ports on a specific host  
- Quickly test connectivity with ping  

---

## ✨ Features

### 🏠 Network Overview (Subnet Scanner)
- Scan any CIDR range (e.g., `192.168.1.0/24`)
- Detect online devices
- Show IP, MAC, vendor, hostname, last‑seen timestamp
- Export results as CSV

### 🔍 Deep Port Scan
- Scan TCP ports 1–1024
- Show port state, service name, and version (if available)

### ⚡ Connectivity Test (Ping)
- Ping any IP or hostname
- Show raw ping output

### 📊 Clean Dashboard UI
- Metrics & progress bars  
- Modern Streamlit layout  
- Ready to demo as a web dashboard

---

## 🛠 Tech Stack

- **Language:** Python 3.x  
- **Web Framework:** Streamlit  
- **Scanner Engine:** Nmap (`python-nmap`)  
- **Data Processing:** pandas  
- **Container Support:** Docker (optional)

---

## 🚀 Getting Started (Local)

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/netpulse.git
cd netpulse
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the dashboard
```bash
streamlit run app.py
```

---

## 📦 Project Structure

```
netpulse/
│── app.py              # Main Streamlit dashboard
│── scanner/
│     ├── subnet_scan.py
│     ├── port_scan.py
│     └── ping_test.py
│── assets/
│     └── icons/
│── README.md
│── requirements.txt
```

---

## 🐳 Run with Docker (Optional)

### Build the image:
```bash
docker build -t netpulse .
```

### Run the container:
```bash
docker run -p 8501:8501 netpulse
```

---

## 📸 Demo Preview

> You can add screenshots or GIF demos here once hosted.

---

## 🤝 Contributing

Pull requests are welcome!  
For major changes, please open an issue first to discuss what you want to modify.

---

## 📄 License

MIT License  
© 2025 NetPulse

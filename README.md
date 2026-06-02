# DDoS Detection System

A cross-platform DDoS detection, monitoring, and testing toolkit developed for educational and laboratory environments.

---

## 📁 Project Structure

```text
ddos_enhanced/
├── detector_core.py       # Core detection engine
├── gui_detector.py        # GUI application
├── traffic_generator.py   # Traffic simulation tool
├── server.py              # Test HTTP server
├── detector_config.json   # Configuration file (auto-generated)
├── requirements.txt       # Required dependencies
└── README.md
```

---

## 🚀 Getting Started

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Test Server

```bash
python server.py --port 8080
```

### 3. Launch the Detection GUI

```bash
python gui_detector.py
```

### 4. Generate Test Traffic

```bash
python traffic_generator.py 127.0.0.1 --port 8080 --type http --rate 200 --threads 4 --duration 30
```

---

## ✨ Features

### Cross-Platform Support

- Windows
- Linux
- macOS

### Attack Detection

The system supports detection of:

- TCP Flood
- UDP Flood
- SYN Flood
- HTTP Flood
- Slowloris Attack
- Amplification-style Traffic

### Monitoring and Visualization

- Real-time traffic monitoring
- Live statistics dashboard
- Event feed
- Attack logging
- Interactive charts and graphs

### Automated Response

- Automatic IP blocking
- Temporary firewall rules
- Configurable block duration

### Notifications

- Email alerts via SMTP
- Severity-based attack notifications

---

## 🌐 Traffic Generator Modes

| Mode | Description |
|--------|-------------|
| normal | Legitimate HTTP traffic |
| tcp | TCP connection flood |
| udp | UDP packet flood |
| syn | SYN flood simulation |
| http | High-rate HTTP GET/POST requests |
| slowloris | Long-lived HTTP connections |
| amplification | UDP amplification-style traffic |

---

## 🧪 Example Commands

### TCP Flood

```bash
python traffic_generator.py 127.0.0.1 --type tcp --rate 100 --threads 10 --duration 60
```

### Slowloris Attack Simulation

```bash
python traffic_generator.py 127.0.0.1 --type slowloris --connections 500 --port 8080
```

### UDP Flood

```bash
python traffic_generator.py 127.0.0.1 --type udp --rate 300 --port 8080
```

---

## 🖥️ GUI Overview

### 📊 Dashboard

- Live traffic statistics
- Detection summaries
- Recent events
- Quick system status

### 🚨 Alerts

- Attack logs
- Severity indicators
- Export to CSV

### 🌐 IP Monitor

- Active IP tracking
- Connection statistics
- Manual IP blocking

### 📈 Charts

- Real-time traffic graphs
- Attack distribution charts

### ⚙️ Settings

- Detection thresholds
- Auto-block configuration
- Email settings
- Logging preferences

### 📋 Logs

- View stored logs
- Refresh and clear entries
- Export records

---

## 🚫 Auto-Blocking

Auto-blocking can be enabled through the Settings tab.

### Linux

```bash
sudo python gui_detector.py
```

### Windows

Run the application as Administrator.

### macOS

```bash
sudo python gui_detector.py
```

Blocked IP addresses are automatically removed after the configured timeout period.

---

## 📧 Email Alerts

To enable email notifications:

1. Open **Settings**
2. Enable **Email Alerts**
3. Enter:
   - SMTP Server
   - Port Number
   - Sender Email
   - App Password
   - Recipient Email

For Gmail, use an **App Password** instead of your account password.

---

## ⚙️ Detection Parameters

| Parameter | Default | Description |
|------------|---------|-------------|
| threshold_connections | 100 | TCP connections per window |
| threshold_period | 5 sec | Monitoring window size |
| udp_threshold | 200 | UDP packet threshold |
| syn_threshold | 80 | SYN connection threshold |
| http_threshold | 150 | HTTP request threshold |
| slowloris_threshold | 40 | Long-lived connections threshold |
| amplification_threshold | 100 | Amplification traffic threshold |

All parameters can be modified through the Settings page.

---

## ⚠️ Disclaimer

This project was developed for educational, research, and authorized testing purposes only.

The traffic generation module should only be used on systems that you own or have explicit permission to test. Unauthorized use against third-party systems may violate laws, regulations, or organizational policies.

---

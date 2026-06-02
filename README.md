A cross-platform DDoS detection, monitoring and testing toolkit built for learning and lab environments.

📁 File Structure
ddos/
├── detector_core.py       # Core detection engine (all platforms)
├── gui_detector.py        # Enhanced GUI application
├── traffic_generator.py   # Multi-attack-type traffic simulator
├── server.py              # Enhanced test HTTP server
├── detector_config.json   # Configuration (auto-created on first run)
├── requirements.txt       # Python dependencies
└── README.md

🚀 Quick Start

1. Install dependencies
pip install -r requirements.txt
2. Start the test server
python server.py --port 8080
3. Launch the GUI detector
python gui_detector.py
4. Run a traffic simulation (in a third terminal)
python traffic_generator.py 127.0.0.1 --port 8080 --type http --rate 200 --threads 4 --duration 30

🔍 What's New vs Original
Feature	Original	Enhanced
OS Support	Windows only (netstat)	✅ Windows + Linux (/proc/net/tcp) + Mac
Attack Types	TCP flood only	✅ TCP, UDP, SYN, HTTP, Slowloris, Amplification
Detection	Single threshold	✅ Per-attack-type thresholds with severity levels
GUI	Basic tkinter	✅ Dark cyberpunk theme, stat cards, event feed
Charts	None	✅ Real-time live chart (matplotlib) + sparklines
Auto-Block	None	✅ iptables / netsh / pfctl integration
Logging	Text file only	✅ Colour-coded log viewer + CSV export
Email Alerts	None	✅ SMTP email on detection
Rate Limiting	None	✅ Server-side per-IP rate limiting (429 responses)
Config	Fixed values	✅ Full settings tab, live reload
False Positives	High (single metric)	✅ Deduplication, per-attack cooldowns

🌐 Attack Types (traffic_generator.py)
Type	Description	Key Args
normal	Legit HTTP GET traffic (baseline)	--rate, --threads
tcp	Raw TCP connection flood	--rate, --threads
udp	UDP datagram flood	--rate, --threads
syn	SYN flood (connect + immediate close)	--rate, --threads
http	HTTP GET/POST flood, random paths + agents	--rate, --threads
slowloris	Slow HTTP header attack	--connections
amplification	DNS/NTP-style small-UDP simulation	--rate

Examples
# TCP flood — 10 threads × 100 conn/s for 60s
python traffic_generator.py 127.0.0.1 --type tcp --rate 100 --threads 10 --duration 60

# Slowloris — hold 500 connections open
python traffic_generator.py 127.0.0.1 --type slowloris --connections 500 --port 8080

# UDP flood
python traffic_generator.py 127.0.0.1 --type udp --rate 300 --port 8080

🖥️ GUI Tabs
Tab	Description
📊 Dashboard	Live stat cards, recent event feed, sparkline graphs
🚨 Alerts	Full attack log table with severity colours, CSV export
🌐 IP Monitor	Top-talker table, manual IP block input
📈 Charts	Real-time matplotlib line chart + attack-type bar chart
⚙️ Settings	All thresholds, auto-block, email config, file paths
📋 Logs	Colour-coded log viewer with refresh/clear/open

🚫 Auto-Blocking
Enable in Settings → Auto-Blocking. Requires elevated privileges:

Linux: sudo python gui_detector.py (uses iptables)
Windows: Run as Administrator (uses netsh advfirewall)
Mac: sudo python gui_detector.py (uses pfctl)
Blocked IPs are automatically unblocked after block_duration seconds.

📧 Email Alerts
Enable in Settings → Email Alerts
Fill in SMTP server, port, sender email, password, recipient
For Gmail: use an App Password

⚙️ Detection Thresholds
Config Key	Default	Meaning
threshold_connections	100	TCP connections in threshold_period seconds
threshold_period	5	Sliding window in seconds
udp_threshold	200	UDP datagrams per window
syn_threshold	80	Half-open (SYN) connections
http_threshold	150	HTTP requests per window
slowloris_threshold	40	Long-lived connections from same IP
amplification_threshold	100	Small UDP to DNS/NTP ports

⚠️ Disclaimer
This tool is for educational and authorised lab use only.
Do not use the traffic generator against systems you do not own or have written permission to test."

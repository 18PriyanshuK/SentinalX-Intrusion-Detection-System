<div align="center">

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝ 
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗ 
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
```

### Real-Time Rule-Based Intrusion Detection System

*A lightweight, fully functional host-based IDS built in Python — no machine learning, no external rule files, no enterprise infrastructure required.*

<br/>

<img src="https://img.shields.io/badge/Python-3.12-00c9b1?style=for-the-badge&logo=python&logoColor=white&labelColor=111318"/>
<img src="https://img.shields.io/badge/Scapy-Packet%20Capture-f97316?style=for-the-badge&logoColor=white&labelColor=111318"/>
<img src="https://img.shields.io/badge/Tkinter-GUI-6366f1?style=for-the-badge&logoColor=white&labelColor=111318"/>
<img src="https://img.shields.io/badge/SQLite-Persistence-00c9b1?style=for-the-badge&logo=sqlite&logoColor=white&labelColor=111318"/>
<img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Kali%20Linux-f59e0b?style=for-the-badge&logoColor=white&labelColor=111318"/>

</div>

---

## 📸 Screenshots

### Main Dashboard
<img width="600" height="300" alt="s1" src="https://github.com/user-attachments/assets/ec24f04c-e60a-4cc2-8813-4732376ed7ad" />
*2×2 SOC-style dashboard — Threat Activity graph, Stat Cards, Alert Feed, Severity Breakdown*

### Alert Feed with Context Menu
<img width="600" height="300" alt="s2" src="https://github.com/user-attachments/assets/8dd1accd-08fd-406a-b7c2-29ef418b9307" />
*Right-click any alert for Investigate, Geo-IP Lookup, Block IP, Whitelist IP, or Acknowledge*

### Incident Investigation Window
<img width="600" height="500" alt="s3" src="https://github.com/user-attachments/assets/09e3e565-1590-40cb-a5a8-5b83294cc816" />
*Full forensic details — Alert Details + IP Activity History for every incident*

### Whitelist Manager
<img width="500" height="400" alt="S4" src="https://github.com/user-attachments/assets/2802faad-1089-420c-abcf-e53660a3e79b" />
*Add or remove trusted IPs at runtime without restarting the system*

### Filter Bar
<img width="600" height="30" alt="S5" src="https://github.com/user-attachments/assets/0dce03e3-f743-435e-9c77-80dc838aebed" />
*Filter alerts by Severity, Attack Type, or Source IP — instantly narrows 500+ alerts*

### Block IP Dialog
<img width="223" height="146" alt="S6" src="https://github.com/user-attachments/assets/552e756e-534c-4b28-9491-24db8a828f9d" />
*One-click iptables DROP rule from inside the dashboard (Linux)*

---

## ⚡ What is SentinelX?

SentinelX is a real-time, rule-based Host-Based Intrusion Detection System that captures live network packets, evaluates them against 8 detection rules, and displays threats through a professional SOC-style dashboard. Every component — from raw packet capture to alert visualisation — is built from first principles in Python.

The system runs on both **Windows 10/11** (via Npcap) and **Kali Linux** with no code modification required.

---

## 🛡️ Detection Rules

| # | Rule | Trigger | Severity |
|---|------|---------|----------|
| 1 | **Port Scan** | 5+ distinct ports from same IP in 10s | 🟠 HIGH |
| 2 | **Ping Flood** | 15+ ICMP packets from same IP in 5s | 🟡 MEDIUM |
| 3 | **SYN Flood** | 20+ TCP SYN packets from same IP in 5s | 🔴 CRITICAL |
| 4 | **ARP Spoofing** | IP-MAC mismatch (3 confirmations after 30s warmup) | 🔴 CRITICAL |
| 5 | **DNS Flood** | 20+ DNS queries from same IP in 5s | 🟠 HIGH |
| 6 | **Sensitive Port** | Connection to port 21, 22, 23, 25, 3306, 3389 | 🟡 MEDIUM / 🟠 HIGH |
| 7 | **UDP Flood** | 50+ non-standard UDP packets from same IP in 5s | 🟠 HIGH |
| 8 | **HTTP Flood** | 60+ TCP SYN to web ports from same IP in 5s | 🟠 HIGH |

All thresholds are configurable in `config.json` — no code changes needed.

---

## 🖥️ Dashboard Features

```
┌─────────────────────────┬──────────────────────┐
│   THREAT ACTIVITY       │   STAT CARDS         │
│   Multi-line graph      │   Total Alerts        │
│   per severity level    │   Top Attacker        │
│   last 300 seconds      │   Packets/sec         │
│                         │   DB All-Time         │
├─────────────────────────┼──────────────────────┤
│   ALERT FEED            │   SEVERITY           │
│   Live filterable table │   BREAKDOWN          │
│   Severity · Type · IP  │   Progress bars       │
│   Right-click actions   │   Recent attack types │
└─────────────────────────┴──────────────────────┘
```

**Alert Feed Actions (right-click)**
- 🔍 **Investigate** — full forensic popup with IP history
- 🌍 **Geo-IP Lookup** — geographic info via ip-api.com
- ⬛ **Block IP** — adds `iptables DROP` rule instantly (Linux)
- ◎ **Whitelist IP** — suppress future alerts from this IP
- ✓ **Acknowledge** — mark alert as reviewed

**Toolbar**
- `⬛ BLOCK IP` — block any IP manually
- `↓ EXPORT` — export all alerts to CSV
- `◎ WHITELIST` — manage whitelisted IPs

---

## 📁 Project Structure

```
SentinelX/
│
└── SentinalX IDS
      |
      ├── main.py               # Entry point
      ├── packet_sniffer.py     # Live packet capture (Scapy)
      ├── detector.py           # 8 rule-based detection engines
      ├── data_store.py         # Thread-safe in-memory shared state
      ├── db_store.py           # SQLite persistence + CSV export
      ├── dashboard.py          # Tkinter GUI — full SOC dashboard
      ├── investigation.py      # Alert investigation popup window
      ├── sound.py              # Terminal bell alert notifications
      │
      └──config.json           # All thresholds and settings
└── Pipeline Testing File 
      ├── test_pipeline.py      # Test dashboard without Scapy/root
      └── debug_capture.py      # Debug what Scapy is capturing
│
└── README.md
```

---

## ⚙️ Requirements

### Python
```
Python 3.10+
```

### Dependencies
```bash
pip install scapy matplotlib numpy
```

### Windows Only
- **Npcap** — https://npcap.com/#download
  - ✅ Tick *"WinPcap API-compatible mode"* during install
- **Nmap** — https://nmap.org/download.html (for testing)
- Run CMD as **Administrator**

### Linux / Kali
- Run with **`sudo`**
- Scapy is usually pre-installed on Kali

---

## 🚀 Quick Start

### Step 1 — Find your IP

**Windows:**
```cmd
ipconfig
```

**Kali Linux:**
```bash
ip a | grep "inet " | grep -v 127
```

### Step 2 — Run SentinelX

**Windows (CMD as Administrator):**
```cmd
python main.py
```

**Kali Linux:**
```bash
sudo python3 main.py
```

**Specify a network interface (optional):**
```bash
sudo python3 main.py --iface eth0
```

### Step 3 — Run Test Commands (second terminal)

Replace `YOUR_IP` with the IP from Step 1.

```cmd
# Sensitive Port — instant alert
nmap -p 21,22,23,3389 YOUR_IP

# Port Scan
nmap -sS YOUR_IP

# SYN Flood — CRITICAL alert
nmap -sS -p 1-1000 --min-rate 1000 --max-retries 0 YOUR_IP

# Ping Flood
ping -t -l 65500 YOUR_IP

# UDP Flood
nmap -sU --min-rate 500 --max-retries 0 YOUR_IP

# DNS Flood
nmap -sU -p 53 --min-rate 500 YOUR_IP

# Full Aggressive Scan — triggers multiple alerts
nmap -A -T4 -p 1-1000 YOUR_IP
```

**Kali Linux (additional tools):**
```bash
sudo hping3 -S --flood -p 80 127.0.0.1        # SYN Flood
sudo hping3 --udp --flood -p 9999 127.0.0.1   # UDP Flood
sudo ping -f 127.0.0.1                         # Ping Flood
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.2  # ARP Spoof
```

---

## ⚙️ Configuration

All settings are in `config.json` — no code changes needed:

```json
{
  "thresholds": {
    "port_scan_ports":   5,
    "syn_flood_count":  20,
    "ping_flood_count": 15
  },
  "sensitive_ports": [21, 22, 23, 25, 3306, 3389],
  "whitelist": {
    "enabled": true,
    "ips": ["192.168.1.1"]
  },
  "deduplication": {
    "window_seconds": 3
  },
  "dashboard": {
    "graph_window_seconds": 300
  }
}
```

---

## 🧪 Development Tools

**Test the full pipeline without Scapy or root:**
```bash
python test_pipeline.py
```
Injects synthetic attack packets directly. Use this to verify the dashboard works before testing with real traffic.

**Debug what Scapy is actually capturing:**
```bash
python debug_capture.py
```
Prints every captured packet to the terminal. Use this to confirm Scapy can see your test traffic.

---

## 🏗️ Architecture

```
[Network Interface]
        │
        ▼
[packet_sniffer.py]   Scapy sniff() — all interfaces including loopback
        │
        ▼
[detector.py]         8 rules — whitelist → routable → sliding window → threshold
        │
        ▼
[Queue]               Thread-safe alert channel (maxsize 2000)
        │
        ▼
[dashboard.py]        Tkinter GUI — polls queue every 200ms
        │
        ├── Alert Feed + Filters
        ├── Threat Graph (redraws every 2s)
        ├── Severity Breakdown Panel
        └── Investigation Window

[data_store.py]       Shared in-memory state (thread-safe RLock)
[db_store.py]         SQLite persistence + CSV export
[sound.py]            Terminal bell notifications
```

---

## 🔧 Troubleshooting

| Problem | Fix |
|---------|-----|
| No alerts appearing | Use your LAN IP from `ipconfig`, not `127.0.0.1` |
| Graph shows "No alerts yet" | Increase `graph_window_seconds` in config.json |
| Permission denied | Run as Administrator (Windows) or `sudo` (Linux) |
| `python3` not found on Windows | Use `python` instead |
| Scapy not found | `pip install scapy` |
| False positive alerts | Add your IP to `whitelist.ips` in config.json |
| ARP spoof not detecting | Wait 30s after startup — warm-up period required |

---

## 📊 Detection Performance

| Attack Type | Response Time | Detection Rate |
|-------------|---------------|----------------|
| Sensitive Port | ~0.8s | 100% |
| SYN Flood | ~2.1s | 100% |
| Ping Flood | ~2.4s | 100% |
| HTTP Flood | ~3.2s | 100% |
| UDP Flood | ~3.5s | 100% |
| DNS Flood | ~3.8s | 100% |
| Port Scan | ~4.6s | 100% |
| ARP Spoof | ~8.5s | 100% |

False positive rate: **~0%** under normal traffic conditions after threshold tuning.

---

## 📝 Alert Format

Every alert follows this structure:

```json
{
  "timestamp": "14:32:01",
  "type":      "SYN_FLOOD",
  "src":       "192.168.0.50",
  "severity":  "CRITICAL",
  "details": {
    "info": "35 SYN packets in 5s"
  }
}
```

---

## 🔮 Future Enhancements

- [ ] SIEM Integration (Splunk / Elastic via syslog)
- [ ] Web-based dashboard (Flask + Chart.js)
- [ ] Packet payload inspection
- [ ] ML anomaly detection layer
- [ ] Multi-node distributed deployment
- [ ] Automated PDF report generation
- [ ] Email / Telegram alert notifications

---

## 📚 Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.12 | Core language |
| Scapy | Live packet capture and parsing |
| Tkinter | GUI dashboard |
| Matplotlib | Real-time threat graph |
| SQLite3 | Alert persistence |
| NumPy | Graph smoothing |
| Npcap | Windows packet capture driver |


---

## 📄 License

This project is licensed under the [MIT License](https://github.com/PriyanshuKhambalkar/SentinalX-Intrusion-Detection-System/blob/60b2a31e8d66d7a5f23fc7cdb1c2ac9c6ca8ad61/LICENSE) - see the LICENSE file for details.<br/>
For commercial use or redistribution, please contact the author.

---

## 👨‍💻 Author

**Priyanshu Khambalkar**

---


<div align="center">

*Built with Python · No ML · No External Rule Files · Cross-Platform*

⭐ **Star this repo if you found it useful**

</div>

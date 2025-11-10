"""Log analysis module with heuristic detection"""
import re
import time
from collections import Counter

def _safe_int(x, default=0):
    """Safely convert to integer"""
    try:
        return int(x)
    except (ValueError, TypeError):
        try:
            return int(float(x))
        except (ValueError, TypeError):
            return default

def analyze_text(filename, text):
    """
    Analyze uploaded log file using heuristic rules.
    Returns: (incidents, file_metrics, summary)
    """
    start = time.time()
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    incidents = []
    severity_count = Counter()
    ioc_set = set()
    
    lname = filename.lower()
    events_count = len(lines)
    
    # === PROCESS LOGS ===
    if "proc" in lname or "process" in lname or filename.lower().endswith('.log'):
        proc_starts = {}
        for line in lines:
            parts = [p.strip() for p in line.split(',')]
            
            # Check for suspicious Windows Event IDs
            if line.startswith('{') and '"EventID"' in line:
                m = re.search(r'"EventID"\s*:\s*(\d+)', line, re.IGNORECASE)
                if m:
                    event_id = int(m.group(1))
                    # Suspicious event IDs: Kerberos (4672), TGT Granted (4769),
                    # Logon Success (4624), Logon Failure (4625)
                    if event_id in (4672, 4769, 4624, 4625):
                        incidents.append({
                            'type': 'suspicious_event_id',
                            'severity': 'high',
                            'detail': f'EventID {event_id}: {line[:150]}'
                        })
                        severity_count['high'] += 1
                        ioc_set.add(f"EventID:{event_id}")
                    continue
            
            # Track orphan processes (start without end)
            if len(parts) >= 5:
                flag = parts[-1].lower()
                proc = parts[3] if len(parts) > 3 else 'unknown'
                
                if flag == 'start':
                    proc_starts[proc] = proc_starts.get(proc, 0) + 1
                elif flag == 'end':
                    if proc in proc_starts and proc_starts[proc] > 0:
                        proc_starts[proc] -= 1
        
        # Report orphan processes
        for proc, count in proc_starts.items():
            if count > 0:
                incidents.append({
                    'type': 'orphan_process',
                    'severity': 'medium',
                    'detail': f'Process "{proc}" has {count} unmatched starts'
                })
                severity_count['medium'] += 1
                ioc_set.add(f"Process:{proc}")
    
    # === NETWORK FLOW LOGS ===
    if "flow" in lname or "flows" in lname or "net" in lname:
        for line in lines:
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 9:
                try:
                    duration = float(parts[1])
                except (ValueError, IndexError):
                    duration = 0.0
                
                dst_port = parts[5] if len(parts) > 5 else "0"
                bytes_count = _safe_int(parts[8] if len(parts) > 8 else 0)
                
                # Suspicious pattern: zero duration but large bytes
                if duration == 0 and bytes_count > 1000:
                    incidents.append({
                        'type': 'short_flow_large_bytes',
                        'severity': 'high',
                        'detail': f'Zero-duration flow with {bytes_count} bytes'
                    })
                    severity_count['high'] += 1
                
                # Check for suspicious ports
                if dst_port.isdigit():
                    dp = int(dst_port)
                    if dp in (3389, 4444, 1433, 3306) or (dp < 1024 and dp not in (80, 443, 53, 22, 25)):
                        incidents.append({
                            'type': 'suspicious_port',
                            'severity': 'high',
                            'detail': f'Suspicious destination port: {dp}'
                        })
                        severity_count['high'] += 1
                        ioc_set.add(f"Port:{dp}")
                
                # Large data exfiltration
                if bytes_count > 1000000:
                    incidents.append({
                        'type': 'large_data_transfer',
                        'severity': 'high',
                        'detail': f'Large data transfer: {bytes_count / (1024*1024):.2f} MB'
                    })
                    severity_count['high'] += 1
    
    # === DNS LOGS ===
    if "dns" in lname or 'dns' in filename.lower():
        host_counts = Counter()
        for line in lines:
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 3:
                host = parts[2]
                host_counts[host] += 1
        
        for host, count in host_counts.items():
            # DNS flood detection
            if count > 100:
                incidents.append({
                    'type': 'dns_flood',
                    'severity': 'high',
                    'detail': f'Host {host}: {count} DNS queries'
                })
                severity_count['high'] += 1
                ioc_set.add(f"DNS:{host}")
            
            # Suspicious domain patterns
            if host.lower().endswith(('.xyz', '.tk', '.ml')) or host.count('.') > 4:
                incidents.append({
                    'type': 'suspicious_domain',
                    'severity': 'medium',
                    'detail': f'Suspicious domain: {host}'
                })
                severity_count['medium'] += 1
                ioc_set.add(f"Domain:{host}")
    
    # === RED TEAM / ATTACK INDICATORS ===
    if "redteam" in lname or "attack" in lname or "exploit" in lname:
        for line in lines:
            incidents.append({
                'type': 'redteam_indicator',
                'severity': 'critical',
                'detail': line[:200]
            })
            severity_count['critical'] += 1
    
    # === GENERIC SUSPICIOUS PATTERNS ===
    # Look for known malware domains, C2 indicators, etc.
    c2_patterns = ['bin.js', 'evil.com', 'malware', 'payload', 'shellcode']
    for line in lines:
        for pattern in c2_patterns:
            if pattern.lower() in line.lower():
                incidents.append({
                    'type': 'c2_indicator',
                    'severity': 'critical',
                    'detail': f'C2 pattern "{pattern}": {line[:150]}'
                })
                severity_count['critical'] += 1
                ioc_set.add(f"C2:{pattern}")
                break
    
    # Build metrics
    file_metrics = {
        'events_count': events_count,
        'critical_count': int(severity_count.get('critical', 0)),
        'high_count': int(severity_count.get('high', 0)),
        'medium_count': int(severity_count.get('medium', 0)),
        'low_count': int(severity_count.get('low', 0)),
        'total_incidents': len(incidents),
        'ioc_count': len(ioc_set)
    }
    
    elapsed = time.time() - start
    summary = {
        'file': filename,
        'lines': events_count,
        'analysis_time': elapsed,
        'incident_count': len(incidents)
    }
    
    return incidents, file_metrics, summary, list(ioc_set)[:10]  # Top 10 IOCs
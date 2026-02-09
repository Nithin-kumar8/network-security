"""
Rule Engine Module
Implements security rules for threat detection
"""

from datetime import datetime, timedelta
from collections import defaultdict, Counter

class RuleEngine:
    def __init__(self, config):
        self.config = config
        self.blacklisted_ips = set(config.get('blacklisted_ips', []))
        self.restricted_endpoints = config.get('restricted_endpoints', [])
        
        # Tracking data structures
        self.login_attempts = defaultdict(list)
        self.request_counts = defaultdict(list)
        self.unique_ips = set()
        self.failed_login_attempts = 0
        
        # Alert counters
        self.alerts_by_type = defaultdict(int)
        self.ip_activity = Counter()
    
    def analyze_logs(self, log_entries, log_file):
        """Analyze log entries for security threats"""
        alerts = []
        
        for entry in log_entries:
            ip = self.get_ip_from_entry(entry)
            if ip:
                self.unique_ips.add(ip)
            
            # Apply all detection rules
            entry_alerts = self.apply_detection_rules(entry, log_file)
            alerts.extend(entry_alerts)
            
            # Track IP activity
            if ip:
                self.ip_activity[ip] += 1
        
        return alerts
    
    def get_ip_from_entry(self, entry):
        """Extract IP address from log entry"""
        if 'ip' in entry:
            return entry['ip']
        elif 'src_ip' in entry:
            return entry['src_ip']
        return None
    
    def apply_detection_rules(self, entry, log_file):
        """Apply all detection rules to a log entry"""
        alerts = []
        
        # Rule 1: Blacklisted IP Detection
        ip = self.get_ip_from_entry(entry)
        if ip and ip in self.blacklisted_ips:
            alerts.append(self.create_alert(
                entry, 
                "blacklisted_ip",
                f"Access from blacklisted IP: {ip}",
                "HIGH"
            ))
        
        # Rule 2: Brute Force Detection
        if entry.get('log_type') == 'auth':
            brute_force_alert = self.detect_brute_force(entry)
            if brute_force_alert:
                alerts.append(brute_force_alert)
        
        # Rule 3: High Traffic Detection
        high_traffic_alert = self.detect_high_traffic(entry)
        if high_traffic_alert:
            alerts.append(high_traffic_alert)
        
        # Rule 4: Unauthorized Access Detection
        if self.detect_unauthorized_access(entry):
            alerts.append(self.create_alert(
                entry,
                "unauthorized_access",
                f"Attempt to access restricted endpoint",
                "HIGH"
            ))
        
        # Rule 5: Firewall Block Detection
        if self.detect_firewall_block(entry):
            alerts.append(self.create_alert(
                entry,
                "firewall_block",
                f"Firewall blocked connection",
                "HIGH"
            ))
        
        # Rule 6: Failed Login Detection
        if self.detect_failed_login(entry):
            self.failed_login_attempts += 1
            alerts.append(self.create_alert(
                entry,
                "failed_login",
                f"Failed login attempt",
                "MEDIUM"
            ))
        
        return alerts
    
    def detect_brute_force(self, entry):
        """Detect brute force login attempts"""
        ip = self.get_ip_from_entry(entry)
        if not ip:
            return None
        
        timestamp = entry.get('timestamp')
        result = entry.get('result', '').lower()
        
        if 'fail' in result or 'invalid' in result:
            # Record failed login attempt
            self.login_attempts[ip].append(timestamp)
            
            # Check for brute force pattern
            threshold = self.config['thresholds']['failed_login_attempts']
            timeframe = self.config['thresholds']['failed_login_timeframe_minutes']
            
            # Filter attempts within timeframe
            try:
                now = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                cutoff = now - timedelta(minutes=timeframe)
                
                recent_attempts = [
                    t for t in self.login_attempts[ip]
                    if datetime.strptime(t, '%Y-%m-%d %H:%M:%S') >= cutoff
                ]
                
                if len(recent_attempts) >= threshold:
                    # Reset after detection
                    self.login_attempts[ip] = recent_attempts[-threshold:]  # Keep recent
                    
                    return self.create_alert(
                        entry,
                        "brute_force",
                        f"Brute force detected: {len(recent_attempts)} failed logins in {timeframe} minutes",
                        "MEDIUM"
                    )
            except ValueError:
                pass
        
        return None
    
    def detect_high_traffic(self, entry):
        """Detect high traffic from single IP"""
        ip = self.get_ip_from_entry(entry)
        if not ip:
            return None
        
        timestamp = entry.get('timestamp')
        
        # Record request
        if ip not in self.request_counts:
            self.request_counts[ip] = []
        
        self.request_counts[ip].append(timestamp)
        
        # Check for high traffic
        threshold = self.config['thresholds']['high_traffic_requests']
        timeframe = self.config['thresholds']['high_traffic_timeframe_seconds']
        
        try:
            now = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            cutoff = now - timedelta(seconds=timeframe)
            
            # Filter recent requests
            recent_requests = [
                t for t in self.request_counts[ip]
                if datetime.strptime(t, '%Y-%m-%d %H:%M:%S') >= cutoff
            ]
            
            if len(recent_requests) >= threshold:
                # Keep only recent requests
                self.request_counts[ip] = recent_requests[-threshold:]  # Keep recent
                
                return self.create_alert(
                    entry,
                    "high_traffic",
                    f"High traffic detected: {len(recent_requests)} requests in {timeframe} seconds",
                    "MEDIUM"
                )
        except ValueError:
            pass
        
        return None
    
    def detect_unauthorized_access(self, entry):
        """Detect unauthorized access to restricted endpoints"""
        if entry.get('log_type') in ['access', 'api']:
            request = entry.get('request', '')
            
            for restricted in self.restricted_endpoints:
                if restricted in request:
                    return True
        
        return False
    
    def detect_firewall_block(self, entry):
        """Detect firewall blocks"""
        raw_line = entry.get('raw_line', '').lower()
        action = entry.get('action', '').lower()
        
        return 'block' in raw_line or 'blocked' in raw_line or 'deny' in action or 'drop' in action
    
    def detect_failed_login(self, entry):
        """Detect failed login attempts"""
        if entry.get('log_type') == 'auth':
            result = entry.get('result', '').lower()
            return any(word in result for word in ['fail', 'invalid', 'denied', 'rejected', 'locked'])
        
        # Also check in access logs for 401/403
        if entry.get('log_type') == 'access':
            status = entry.get('status', 0)
            return status in [401, 403]
        
        return False
    
    def create_alert(self, entry, rule, activity, severity):
        """Create alert dictionary"""
        ip = self.get_ip_from_entry(entry)
        
        # Increment alert counter
        self.alerts_by_type[rule] += 1
        
        return {
            'timestamp': entry.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'ip': ip or 'Unknown',
            'activity': activity,
            'rule': rule,
            'severity': severity,
            'log_type': entry.get('log_type', 'unknown'),
            'raw_entry': entry.get('raw_line', '')[:100]
        }
    
    def get_top_active_ips(self, n=5):
        """Get top n most active IPs"""
        return self.ip_activity.most_common(n)
    
    def get_alerts_by_type(self):
        """Get count of alerts by type"""
        return dict(self.alerts_by_type)
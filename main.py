"Enterprise Network Log Analyzer "

import os
import json
import sys
from datetime import datetime
from modules.log_parser import LogParser
from modules.rule_engine import RuleEngine
from modules.reporter import SecurityReporter
from modules.dashboard import SecurityDashboard

class NetworkSecurityAnalyzer:
    def __init__(self, config_path="config.json"):
        
        self.load_config(config_path)
        self.setup_directories()
        
        # Initialize modules
        self.parser = LogParser(self.config)
        self.rule_engine = RuleEngine(self.config)
        self.reporter = SecurityReporter(self.config)
        self.dashboard = SecurityDashboard()
        
        self.logs_processed = 0
        self.alerts = []
        self.critical_alerts = []
        
    def load_config(self, config_path):
        
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
            print(f"✓ Configuration loaded from {config_path}")
        except FileNotFoundError:
            print(f"✗ Configuration file {config_path} not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"✗ Invalid JSON in {config_path}")
            sys.exit(1)
    
    def setup_directories(self):
        
        directories = [
            'network_logs',
            'output',
            'output/reports',
            'logs'
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                print(f"✓ Directory ready: {directory}")
            except Exception as e:
                print(f"⚠ Warning: Could not create directory {directory}: {e}")
                # Check if it's a file instead of directory
                if os.path.exists(directory):
                    print(f"  {directory} exists but may be a file. Consider removing it.")
    
    def process_logs(self, logs_dir="network_logs"):
        
        print(f"\n{'='*60}")
        print("PROCESSING NETWORK LOGS")
        print('='*60)
        
        if not os.path.exists(logs_dir):
            print(f"✗ Logs directory '{logs_dir}' not found")
            print(f"  Creating sample logs for demonstration...")
            self.create_sample_logs()
            return
        
        
        if not os.path.isdir(logs_dir):
            print(f"✗ '{logs_dir}' is not a directory")
            return
        
        
        log_files = [f for f in os.listdir(logs_dir) 
                    if f.endswith(('.log', '.txt')) and os.path.isfile(os.path.join(logs_dir, f))]
        
        if not log_files:
            print(f"⚠ No log files found in '{logs_dir}'")
            print(f"  Creating sample logs for demonstration...")
            self.create_sample_logs()
            logs_dir = "network_logs"
            log_files = os.listdir(logs_dir)
        
        for log_file in log_files:
            file_path = os.path.join(logs_dir, log_file)
            print(f"\n📁 Processing: {log_file}")
            
            try:
                
                log_entries = self.parser.parse_log_file(file_path)
                
                # Analyzation of threats
                file_alerts = self.rule_engine.analyze_logs(
                    log_entries, 
                    log_file
                )
                
                # divison of alerts
                for alert in file_alerts:
                    self.alerts.append(alert)
                    if alert['severity'] == 'HIGH':
                        self.critical_alerts.append(alert)
                
                self.logs_processed += len(log_entries)
                print(f"   Processed {len(log_entries)} entries, "
                      f"found {len(file_alerts)} alerts")
                
            except Exception as e:
                print(f"   ✗ Error processing {log_file}: {str(e)}")
                import traceback
                traceback.print_exc()
    
    def create_sample_logs(self):
        """Create sample log files for demonstration"""
        print("\n📝 Creating sample log files...")
        
        sample_logs = {
            "firewall.log": self.generate_firewall_log(),
            "auth.log": self.generate_auth_log(),
            "access.log": self.generate_access_log()
        }
        
        for filename, content in sample_logs.items():
            filepath = os.path.join("network_logs", filename)
            with open(filepath, 'w') as f:
                f.write("\n".join(content))
            print(f"   Created: {filename} ({len(content)} entries)")
    
    def generate_firewall_log(self):
        """Generate sample firewall log entries"""
        import random
        from datetime import datetime, timedelta
        
        entries = []
        actions = ['ALLOW', 'BLOCK', 'ALLOW', 'ALLOW', 'DROP']
        protocols = ['TCP', 'UDP', 'ICMP']
        ports = [80, 443, 22, 3389, 21, 25]
        
        base_time = datetime.now() - timedelta(hours=24)
        
        
        suspicious_ips = ['192.168.1.100', '10.0.0.77']  
        
        for i in range(100):
            timestamp = (base_time + timedelta(minutes=i*3)).strftime('%Y-%m-%d %H:%M:%S')
            
            # rarely use blacklisted IPs
            if i % 20 == 0 and suspicious_ips:
                src_ip = random.choice(suspicious_ips)
            else:
                src_ip = f"192.168.1.{random.randint(1, 50)}"
                
            dst_ip = f"10.0.0.{random.randint(1, 20)}"
            action = random.choice(actions)
            protocol = random.choice(protocols)
            port = random.choice(ports)
            
            entries.append(f"{timestamp} {src_ip} {dst_ip} {action} {protocol} {port}")
        
        return entries
    
    def generate_auth_log(self):
        
        import random
        from datetime import datetime, timedelta
        
        entries = []
        users = ['admin', 'user1', 'user2', 'guest', 'service']
        results = ['SUCCESS', 'FAILED', 'SUCCESS', 'SUCCESS', 'INVALID', 'LOCKED']
        
        base_time = datetime.now() - timedelta(hours=24)
        
        
        brute_ip = '192.168.1.100'
        for minute in range(10):
            timestamp = (base_time + timedelta(minutes=minute*0.5)).strftime('%Y-%m-%d %H:%M:%S')
            entries.append(f"{timestamp} {brute_ip} admin LOGIN FAILED")
        
        
        for i in range(50):
            timestamp = (base_time + timedelta(minutes=i*2)).strftime('%Y-%m-%d %H:%M:%S')
            ip = f"192.168.1.{random.randint(1, 100)}"
            user = random.choice(users)
            result = random.choice(results)
            entries.append(f"{timestamp} {ip} {user} LOGIN {result}")
        
        return entries
    
    def generate_access_log(self):
        
        import random
        from datetime import datetime, timedelta
        
        entries = []
        endpoints = ['/', '/admin', '/login', '/api/data', '/dashboard', '/config']
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        status_codes = [200, 200, 200, 200, 404, 403, 500]
        
        base_time = datetime.now() - timedelta(hours=24)
        
        for i in range(150):
            timestamp = (base_time + timedelta(minutes=i)).strftime('%Y-%m-%d %H:%M:%S')
            ip = f"172.16.0.{random.randint(1, 255)}"
            user_id = f"user{random.randint(1, 10)}" if random.random() > 0.3 else "-"
            method = random.choice(methods)
            endpoint = random.choice(endpoints)
            status = random.choice(status_codes)
            
            entries.append(f'{timestamp} {ip} {user_id} "{method} {endpoint} HTTP/1.1" {status}')
        
        return entries
    
    def generate_alerts(self):
        
        print(f"\n{'='*60}")
        print("GENERATING ALERTS")
        print('='*60)
        
        
        os.makedirs('logs', exist_ok=True)
        
        
        with open('logs/alerts.log', 'w') as f:
            for alert in self.alerts:
                alert_line = f"[{alert['timestamp']}] [{alert['severity']}] " \
                           f"IP: {alert['ip']} - {alert['activity']} " \
                           f"(Rule: {alert['rule']})\n"
                f.write(alert_line)
        
        print(f"✓ Generated alerts.log with {len(self.alerts)} total alerts")
        
        
        if self.critical_alerts:
            with open('logs/critical_alerts.log', 'w') as f:
                for alert in self.critical_alerts:
                    alert_line = f"[{alert['timestamp']}] [CRITICAL] " \
                               f"IP: {alert['ip']} - {alert['activity']} " \
                               f"(Rule: {alert['rule']})\n"
                    f.write(alert_line)
            print(f"✓ Generated critical_alerts.log with {len(self.critical_alerts)} critical alerts")
        else:
            print("⚠ No critical alerts to write")
    
    def generate_report(self):
        """Generate security report"""
        print(f"\n{'='*60}")
        print("GENERATING SECURITY REPORT")
        print('='*60)
        
        report_data = {
            'total_logs': self.logs_processed,
            'total_alerts': len(self.alerts),
            'critical_alerts': len(self.critical_alerts),
            'alerts': self.alerts,
            'critical_alerts_list': self.critical_alerts,
            'unique_ips': list(self.rule_engine.unique_ips),
            'failed_logins': self.rule_engine.failed_login_attempts
        }
        
        try:
            report_path = self.reporter.generate_daily_report(report_data)
            print(f"✓ Daily security report generated: {report_path}")
        except Exception as e:
            print(f"✗ Error generating report: {e}")
    
    def display_dashboard(self):
        
        print(f"\n{'='*60}")
        print("SECURITY DASHBOARD")
        print('='*60)
        
        dashboard_data = {
            'total_logs': self.logs_processed,
            'total_alerts': len(self.alerts),
            'critical_alerts': len(self.critical_alerts),
            'unique_ips': len(self.rule_engine.unique_ips),
            'failed_logins': self.rule_engine.failed_login_attempts,
            'top_ips': self.rule_engine.get_top_active_ips(5),
            'alerts_by_type': self.rule_engine.get_alerts_by_type()
        }
        
        try:
            self.dashboard.display(dashboard_data)
        except Exception as e:
            print(f"✗ Error displaying dashboard: {e}")
    
    def run(self):
        
        print("\n" + "="*60)
        print("🚀 Enterprise Network Log Analyzer")
        print("🔒 Security Event Detection Automation")
        print("="*60)
        
        
        self.process_logs()
        
        if self.logs_processed == 0:
            print("\n⚠ No logs processed. Exiting.")
            return
        
        
        self.generate_alerts()
        
        
        self.display_dashboard()
        
        
        self.generate_report()
        
        print(f"\n{'='*60}")
        print("ANALYSIS COMPLETE")
        print('='*60)
        print(f"✅ Total logs processed: {self.logs_processed:,}")
        print(f"⚠ Total alerts detected: {len(self.alerts)}")
        print(f"🚨 Critical alerts: {len(self.critical_alerts)}")
        print(f"📊 Reports saved in 'output/reports/'")
        print(f"📝 Alerts saved in 'logs/'")
        print("\n📋 Next Steps:")
        print("   1. Review alerts.log for all security events")
        print("   2. Check critical_alerts.log for urgent issues")
        print("   3. Examine the daily security report")
        print("   4. Add real log files to 'network_logs/' folder")

if __name__ == "__main__":
    try:
        analyzer = NetworkSecurityAnalyzer()
        analyzer.run()
    except KeyboardInterrupt:
        print("\n\n⚠ Analysis interrupted by user")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
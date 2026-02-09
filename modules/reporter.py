"""
Report Generator Module
Generates security reports and summaries
"""

import json
from datetime import datetime
import os
from collections import Counter

class SecurityReporter:
    def __init__(self, config):
        self.config = config
        self.reports_dir = "output/reports"
        
    def generate_daily_report(self, report_data):
        """Generate daily security report"""
        today = datetime.now().strftime("%Y-%m-%d")
        report_path = os.path.join(self.reports_dir, f"security_report_{today}.txt")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            self.write_report_header(f, today)
            self.write_summary_section(f, report_data)
            self.write_alerts_section(f, report_data)
            self.write_threat_analysis(f, report_data)
            self.write_ip_analysis(f, report_data)
            self.write_time_chart(f, report_data)
            self.write_recommendations(f, report_data)
        
        return report_path
    
    def write_report_header(self, file, date):
        """Write report header"""
        file.write("=" * 70 + "\n")
        file.write(f"ENTERPRISE SECURITY REPORT\n")
        file.write(f"Date: {date}\n")
        file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write("=" * 70 + "\n\n")
    
    def write_summary_section(self, file, data):
        """Write summary section"""
        file.write("1. SECURITY SUMMARY\n")
        file.write("-" * 40 + "\n")
        file.write(f"Total Logs Processed:    {data['total_logs']:,}\n")
        file.write(f"Unique IP Addresses:     {len(data['unique_ips']):,}\n")
        file.write(f"Total Alerts Detected:   {data['total_alerts']}\n")
        file.write(f"Critical Alerts:         {data['critical_alerts']}\n")
        file.write(f"Failed Login Attempts:   {data['failed_logins']}\n")
        file.write("\n")
    
    def write_alerts_section(self, file, data):
        """Write alerts breakdown"""
        file.write("2. ALERTS BREAKDOWN\n")
        file.write("-" * 40 + "\n")
        
        # Count alerts by type
        alert_types = Counter([alert['rule'] for alert in data['alerts']])
        
        for alert_type, count in alert_types.most_common():
            severity = "HIGH" if alert_type in ['blacklisted_ip', 'unauthorized_access', 'firewall_block'] else "MEDIUM"
            alert_name = alert_type.replace('_', ' ').title()
            file.write(f"{alert_name:<25} {count:>4} ({severity})\n")
        
        file.write("\n")
    
    def write_threat_analysis(self, file, data):
        """Write threat analysis section"""
        file.write("3. THREAT ANALYSIS\n")
        file.write("-" * 40 + "\n")
        
        if data['critical_alerts'] > 0:
            file.write("CRITICAL THREATS DETECTED:\n")
            file.write("-" * 30 + "\n")
            for alert in data['critical_alerts_list'][:10]:  # Show top 10
                file.write(f"* [{alert['timestamp'][11:19]}] {alert['ip']} - {alert['activity']}\n")
        else:
            file.write("No critical threats detected.\n")
        
        file.write("\n")
    
    def write_ip_analysis(self, file, data):
        """Write IP analysis section"""
        file.write("4. TOP SUSPICIOUS IP ADDRESSES\n")
        file.write("-" * 40 + "\n")
        
        # Count alerts by IP
        ip_alerts = Counter([alert['ip'] for alert in data['alerts'] if alert['ip'] != 'Unknown'])
        
        if ip_alerts:
            for ip, count in ip_alerts.most_common(10):
                file.write(f"{ip:<20} {count:>4} alerts\n")
        else:
            file.write("No suspicious IPs detected.\n")
        
        file.write("\n")
    
    def write_time_chart(self, file, data):
        """Write ASCII time-based activity chart"""
        file.write("5. TIME-BASED ACTIVITY CHART\n")
        file.write("-" * 40 + "\n")
        
        if not data['alerts']:
            file.write("No activity data available.\n")
            return
        
        # Extract hours from alerts
        hours = []
        for alert in data['alerts']:
            try:
                hour = int(alert['timestamp'][11:13])
                hours.append(hour)
            except (ValueError, IndexError):
                continue
        
        if not hours:
            file.write("No timestamp data available.\n")
            return
        
        # Create histogram
        hour_counts = Counter(hours)
        
        file.write("Hour | Alerts | Chart\n")
        file.write("-" * 40 + "\n")
        
        for hour in range(24):
            count = hour_counts.get(hour, 0)
            bar = '#' * min(count, 20)  # Cap at 20 for display
            file.write(f"{hour:02d}:00 | {count:6} | {bar}\n")
        
        file.write("\n")
    
    def write_recommendations(self, file, data):
        """Write security recommendations"""
        file.write("6. SECURITY RECOMMENDATIONS\n")
        file.write("-" * 40 + "\n")
        
        recommendations = []
        
        if data['critical_alerts'] > 5:
            recommendations.append("Investigate critical alerts immediately")
        
        if data['failed_logins'] > 50:
            recommendations.append("Review authentication systems and consider implementing MFA")
        elif data['failed_logins'] > 20:
            recommendations.append("Monitor login attempts and consider account lockout policies")
        
        if len(data['unique_ips']) > 1000:
            recommendations.append("Consider implementing rate limiting and IP filtering")
        
        if data['total_alerts'] / max(1, data['total_logs']) > 0.3:
            recommendations.append("High alert rate detected. Review security policies and thresholds")
        
        if not recommendations:
            recommendations.append("Monitor logs regularly and review security policies")
        
        for i, rec in enumerate(recommendations, 1):
            file.write(f"{i}. {rec}\n")
        
        file.write("\n" + "=" * 70 + "\n")
        file.write("END OF REPORT\n")
        file.write("=" * 70 + "\n")
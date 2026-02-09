"""
Generate sample log files for testing
"""

import random
from datetime import datetime, timedelta

def generate_firewall_log():
    """Generate firewall log entries"""
    entries = []
    actions = ['ALLOW', 'BLOCK', 'ALLOW', 'ALLOW', 'DROP']
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = [80, 443, 22, 3389, 21, 25]
    
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(500):
        timestamp = (base_time + timedelta(minutes=i)).strftime('%Y-%m-%d %H:%M:%S')
        src_ip = f"192.168.1.{random.randint(1, 50)}"
        dst_ip = f"10.0.0.{random.randint(1, 20)}"
        action = random.choice(actions)
        protocol = random.choice(protocols)
        port = random.choice(ports)
        
        entries.append(f"{timestamp} {src_ip} {dst_ip} {action} {protocol} {port}")
    
    return entries

def generate_auth_log():
    """Generate authentication log entries"""
    entries = []
    users = ['admin', 'user1', 'user2', 'guest', 'service']
    results = ['SUCCESS', 'FAILED', 'SUCCESS', 'SUCCESS', 'INVALID', 'LOCKED']
    
    base_time = datetime.now() - timedelta(hours=24)
    
    # Generate some brute force patterns
    for ip_suffix in [100, 77]:  # Suspicious IPs
        for minute in range(10):  # 10 failed attempts in 10 minutes
            timestamp = (base_time + timedelta(minutes=minute)).strftime('%Y-%m-%d %H:%M:%S')
            ip = f"10.0.0.{ip_suffix}"
            user = random.choice(users)
            result = 'FAILED'
            
            entries.append(f"{timestamp} {ip} {user} LOGIN {result}")
    
    # Generate normal entries
    for i in range(200):
        timestamp = (base_time + timedelta(minutes=i)).strftime('%Y-%m-%d %H:%M:%S')
        ip = f"192.168.1.{random.randint(1, 100)}"
        user = random.choice(users)
        result = random.choice(results)
        
        entries.append(f"{timestamp} {ip} {user} LOGIN {result}")
    
    return entries

def generate_access_log():
    """Generate access log entries"""
    entries = []
    endpoints = ['/', '/admin', '/login', '/api/data', '/dashboard', '/config']
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    status_codes = [200, 200, 200, 200, 404, 403, 500]
    
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(1000):
        timestamp = (base_time + timedelta(minutes=i//2)).strftime('%Y-%m-%d %H:%M:%S')
        ip = f"172.16.0.{random.randint(1, 255)}"
        user_id = f"user{random.randint(1)}"
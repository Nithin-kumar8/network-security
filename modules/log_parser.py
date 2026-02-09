"""
Log Parser Module
Handles parsing of various log file formats
"""

import re
from datetime import datetime

class LogParser:
    def __init__(self, config):
        self.config = config
        self.log_patterns = {
            'firewall': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\S+) (\S+) (\S+) (\d+)',
            'access': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\S+) "(\S+ \S+ \S+)" (\d{3})',
            'auth': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\S+) (\S+) (\S+)',
            'api': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (\S+) (\S+) (\S+) (\d{3})'
        }
    
    def parse_log_file(self, file_path):
        """Parse a log file and return structured entries"""
        log_entries = []
        
        # Detect log type from filename
        log_type = self.detect_log_type(file_path)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                entry = self.parse_log_line(line, log_type, line_num)
                if entry:
                    log_entries.append(entry)
        
        return log_entries
    
    def detect_log_type(self, file_path):
        """Detect log type based on filename"""
        filename = file_path.lower()
        
        if 'firewall' in filename:
            return 'firewall'
        elif 'access' in filename:
            return 'access'
        elif 'auth' in filename or 'login' in filename:
            return 'auth'
        elif 'api' in filename:
            return 'api'
        else:
            return 'access'  # Default
    
    def parse_log_line(self, line, log_type, line_num):
        """Parse a single log line based on log type"""
        try:
            if log_type == 'firewall':
                match = re.match(self.log_patterns['firewall'], line)
                if match:
                    return {
                        'timestamp': match.group(1),
                        'src_ip': match.group(2),
                        'dst_ip': match.group(3),
                        'action': match.group(4),
                        'protocol': match.group(5),
                        'port': int(match.group(6)),
                        'log_type': 'firewall',
                        'raw_line': line,
                        'line_num': line_num
                    }
            
            elif log_type == 'access':
                # Try standard format first
                match = re.match(self.log_patterns['access'], line)
                if match:
                    return {
                        'timestamp': match.group(1),
                        'ip': match.group(2),
                        'user_id': match.group(3) if match.group(3) != '-' else None,
                        'request': match.group(4),
                        'status': int(match.group(5)),
                        'log_type': 'access',
                        'raw_line': line,
                        'line_num': line_num
                    }
            
            elif log_type == 'auth':
                match = re.match(self.log_patterns['auth'], line)
                if match:
                    return {
                        'timestamp': match.group(1),
                        'ip': match.group(2),
                        'user': match.group(3),
                        'event': match.group(4),
                        'result': match.group(5),
                        'log_type': 'auth',
                        'raw_line': line,
                        'line_num': line_num
                    }
        
        except (AttributeError, ValueError, IndexError) as e:
            # If parsing fails, create a basic entry
            return {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'raw_line': line,
                'log_type': 'unknown',
                'line_num': line_num,
                'parse_error': str(e)
            }
        
        return None
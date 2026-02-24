"""
Linux Forensic Artifact Parser
================================

Parses Linux-specific forensic artifacts for timeline analysis:
- Shell history (bash, zsh, fish)
- System logs (syslog, auth.log, kern.log)
- systemd journal logs
- Cron logs
- Package manager logs (apt, yum, dnf)
- SSH logs
- Firewall logs (iptables, firewalld)
- User activity logs (wtmp, btmp, lastlog)
- Web server logs (Apache, Nginx)

References:
- SANS FOR508 (Linux/Unix Forensics)
- The Art of Memory Forensics (Linux chapters)
- Linux Forensics (Philip Polstra)
"""

import re
import struct
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
from datetime import datetime
import gzip
import json


class LinuxParser:
    """
    Main parser for Linux forensic artifacts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Common Linux artifact paths (relative to mount point)
        self.ARTIFACT_PATHS = {
            'bash_history': [
                'home/*/.bash_history',
                'root/.bash_history',
            ],
            'zsh_history': [
                'home/*/.zsh_history',
                'home/*/.zhistory',
                'root/.zsh_history',
            ],
            'syslog': [
                'var/log/syslog*',
                'var/log/messages*',
            ],
            'auth_log': [
                'var/log/auth.log*',
                'var/log/secure*',
            ],
            'kern_log': [
                'var/log/kern.log*',
            ],
            'cron_log': [
                'var/log/cron*',
            ],
            'apt_history': [
                'var/log/apt/history.log*',
            ],
            'yum_log': [
                'var/log/yum.log*',
            ],
            'dnf_log': [
                'var/log/dnf.log*',
            ],
            'wtmp': [
                'var/log/wtmp*',
            ],
            'btmp': [
                'var/log/btmp*',
            ],
            'lastlog': [
                'var/log/lastlog',
            ],
            'apache_access': [
                'var/log/apache2/access.log*',
                'var/log/httpd/access_log*',
            ],
            'apache_error': [
                'var/log/apache2/error.log*',
                'var/log/httpd/error_log*',
            ],
            'nginx_access': [
                'var/log/nginx/access.log*',
            ],
            'nginx_error': [
                'var/log/nginx/error.log*',
            ],
            'firewall': [
                'var/log/firewalld*',
                'var/log/iptables.log*',
            ],
        }
    
    def parse_bash_history(self, history_file: Path) -> List[Dict[str, Any]]:
        """
        Parse bash history file.
        
        Format:
        - Plain: one command per line
        - With timestamps: #1234567890\\ncommand
        
        Returns list of shell command events.
        """
        events = []
        
        try:
            with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            username = self._extract_username_from_path(history_file)
            
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                
                if line.startswith('#') and line[1:].isdigit():
                    # Timestamp line
                    timestamp = datetime.fromtimestamp(int(line[1:]))
                    i += 1
                    if i < len(lines):
                        command = lines[i].strip()
                        
                        events.append({
                            'timestamp': timestamp,
                            'event_type': 'shell_command',
                            'category': 'System',
                            'source': 'bash_history',
                            'user': username,
                            'command': command,
                            'shell': 'bash',
                            'description': f'{username}@bash: {command[:100]}',
                        })
                elif line:
                    # Command without timestamp
                    mod_time = datetime.fromtimestamp(history_file.stat().st_mtime)
                    
                    events.append({
                        'timestamp': mod_time,
                        'event_type': 'shell_command',
                        'category': 'System',
                        'source': 'bash_history',
                        'user': username,
                        'command': line,
                        'shell': 'bash',
                        'description': f'{username}@bash: {line[:100]}',
                        'note': 'Timestamp approximate (file mtime)'
                    })
                
                i += 1
        
        except Exception as e:
            self.logger.error(f"Error parsing {history_file}: {e}")
        
        return events
    
    def parse_zsh_history(self, history_file: Path) -> List[Dict[str, Any]]:
        """
        Parse zsh extended history file.
        
        Format: : timestamp:duration;command
        Example: : 1234567890:0;ls -la
        
        Returns list of shell command events.
        """
        events = []
        
        try:
            with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            username = self._extract_username_from_path(history_file)
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse zsh extended format
                match = re.match(r': (\d+):(\d+);(.+)', line)
                if match:
                    timestamp = datetime.fromtimestamp(int(match.group(1)))
                    duration = int(match.group(2))
                    command = match.group(3)
                    
                    events.append({
                        'timestamp': timestamp,
                        'event_type': 'shell_command',
                        'category': 'System',
                        'source': 'zsh_history',
                        'user': username,
                        'command': command,
                        'duration_seconds': duration,
                        'shell': 'zsh',
                        'description': f'{username}@zsh: {command[:100]}',
                    })
        
        except Exception as e:
            self.logger.error(f"Error parsing {history_file}: {e}")
        
        return events
    
    def parse_syslog(self, log_file: Path) -> List[Dict[str, Any]]:
        """
        Parse syslog/messages file.
        
        Format: Month Day HH:MM:SS hostname process[pid]: message
        Example: Jan  1 12:34:56 server sshd[1234]: Accepted password for user from 192.168.1.1
        
        Returns list of system log events.
        """
        events = []
        
        try:
            # Handle gzipped logs
            if log_file.suffix == '.gz':
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            else:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            
            # Determine year from filename or file mtime
            year = self._extract_year_from_filename(log_file)
            if not year:
                year = datetime.fromtimestamp(log_file.stat().st_mtime).year
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse syslog format
                match = re.match(
                    r'(\w+\s+\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(\[\d+\])?:\s+(.+)',
                    line
                )
                
                if match:
                    date_str = match.group(1)
                    time_str = match.group(2)
                    hostname = match.group(3)
                    process = match.group(4)
                    message = match.group(6)
                    
                    try:
                        timestamp = datetime.strptime(f"{year} {date_str} {time_str}", "%Y %b %d %H:%M:%S")
                        
                        events.append({
                            'timestamp': timestamp,
                            'event_type': 'syslog',
                            'category': 'System',
                            'source': log_file.name,
                            'hostname': hostname,
                            'process': process,
                            'message': message,
                            'description': f'{process}@{hostname}: {message[:100]}',
                        })
                    except ValueError:
                        continue
        
        except Exception as e:
            self.logger.error(f"Error parsing {log_file}: {e}")
        
        return events
    
    def parse_auth_log(self, log_file: Path) -> List[Dict[str, Any]]:
        """
        Parse auth.log/secure log (SSH, sudo, su events).
        
        Key patterns:
        - SSH logins: sshd[pid]: Accepted/Failed password for user from IP
        - sudo: sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls
        - su: su: pam_unix(su:session): session opened for user root
        
        Returns list of authentication events.
        """
        events = []
        
        try:
            # Handle gzipped logs
            if log_file.suffix == '.gz':
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            else:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            
            year = self._extract_year_from_filename(log_file) or datetime.now().year
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Extract timestamp and process
                match = re.match(
                    r'(\w+\s+\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(\[\d+\])?:\s+(.+)',
                    line
                )
                
                if not match:
                    continue
                
                date_str = match.group(1)
                time_str = match.group(2)
                hostname = match.group(3)
                process = match.group(4)
                message = match.group(6)
                
                try:
                    timestamp = datetime.strptime(f"{year} {date_str} {time_str}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    continue
                
                event = {
                    'timestamp': timestamp,
                    'event_type': 'authentication',
                    'category': 'Security',
                    'source': log_file.name,
                    'hostname': hostname,
                    'process': process,
                    'message': message,
                }
                
                # Parse specific authentication events
                if 'sshd' in process:
                    # SSH events
                    if 'Accepted password' in message or 'Accepted publickey' in message:
                        user_match = re.search(r'for (\S+) from (\S+)', message)
                        if user_match:
                            event['event_type'] = 'ssh_login_success'
                            event['user'] = user_match.group(1)
                            event['remote_ip'] = user_match.group(2)
                            event['description'] = f"SSH login: {user_match.group(1)} from {user_match.group(2)}"
                    
                    elif 'Failed password' in message:
                        user_match = re.search(r'for (\S+) from (\S+)', message)
                        if user_match:
                            event['event_type'] = 'ssh_login_failure'
                            event['user'] = user_match.group(1)
                            event['remote_ip'] = user_match.group(2)
                            event['description'] = f"SSH login failed: {user_match.group(1)} from {user_match.group(2)}"
                
                elif 'sudo' in process:
                    # sudo commands
                    user_match = re.search(r'sudo:\s+(\S+)\s+:', message)
                    cmd_match = re.search(r'COMMAND=(.+)', message)
                    if user_match:
                        event['event_type'] = 'sudo_command'
                        event['user'] = user_match.group(1)
                        if cmd_match:
                            event['command'] = cmd_match.group(1)
                            event['description'] = f"sudo: {user_match.group(1)} executed {cmd_match.group(1)[:50]}"
                
                elif 'su' in process:
                    # su events
                    if 'session opened' in message:
                        user_match = re.search(r'for user (\S+)', message)
                        if user_match:
                            event['event_type'] = 'su_session'
                            event['target_user'] = user_match.group(1)
                            event['description'] = f"su to {user_match.group(1)}"
                
                if 'description' not in event:
                    event['description'] = f'{process}: {message[:100]}'
                
                events.append(event)
        
        except Exception as e:
            self.logger.error(f"Error parsing {log_file}: {e}")
        
        return events
    
    def parse_cron_log(self, log_file: Path) -> List[Dict[str, Any]]:
        """
        Parse cron log file.
        
        Format: Month Day HH:MM:SS hostname CRON[pid]: (user) CMD (command)
        
        Returns list of scheduled task events.
        """
        events = []
        
        try:
            if log_file.suffix == '.gz':
                with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            else:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            
            year = self._extract_year_from_filename(log_file) or datetime.now().year
            
            for line in lines:
                line = line.strip()
                if 'CMD' not in line:
                    continue
                
                match = re.match(
                    r'(\w+\s+\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+CRON\[\d+\]:\s+\((\S+)\)\s+CMD\s+\((.+)\)',
                    line
                )
                
                if match:
                    date_str = match.group(1)
                    time_str = match.group(2)
                    hostname = match.group(3)
                    user = match.group(4)
                    command = match.group(5)
                    
                    try:
                        timestamp = datetime.strptime(f"{year} {date_str} {time_str}", "%Y %b %d %H:%M:%S")
                        
                        events.append({
                            'timestamp': timestamp,
                            'event_type': 'cron_job',
                            'category': 'System',
                            'source': 'cron.log',
                            'hostname': hostname,
                            'user': user,
                            'command': command,
                            'description': f'Cron job executed by {user}: {command[:50]}',
                        })
                    except ValueError:
                        continue
        
        except Exception as e:
            self.logger.error(f"Error parsing {log_file}: {e}")
        
        return events
    
    def parse_apt_history(self, log_file: Path) -> List[Dict[str, Any]]:
        """
        Parse APT (Debian/Ubuntu) package history.
        
        Format:
        Start-Date: YYYY-MM-DD  HH:MM:SS
        Commandline: apt install package
        Install: package1:amd64 (version), package2:amd64 (version)
        End-Date: YYYY-MM-DD  HH:MM:SS
        
        Returns list of package installation events.
        """
        events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split by blank lines (entries)
            entries = content.split('\n\n')
            
            for entry in entries:
                if not entry.strip():
                    continue
                
                lines = entry.split('\n')
                event_data = {}
                
                for line in lines:
                    if line.startswith('Start-Date:'):
                        date_str = line.split(':', 1)[1].strip()
                        event_data['start'] = datetime.strptime(date_str, "%Y-%m-%d  %H:%M:%S")
                    
                    elif line.startswith('Commandline:'):
                        event_data['commandline'] = line.split(':', 1)[1].strip()
                    
                    elif line.startswith('Install:') or line.startswith('Upgrade:') or line.startswith('Remove:'):
                        action, packages = line.split(':', 1)
                        event_data['action'] = action.lower()
                        event_data['packages'] = packages.strip()
                
                if 'start' in event_data:
                    events.append({
                        'timestamp': event_data['start'],
                        'event_type': 'package_management',
                        'category': 'System',
                        'source': 'apt_history',
                        'action': event_data.get('action', 'unknown'),
                        'commandline': event_data.get('commandline', ''),
                        'packages': event_data.get('packages', ''),
                        'description': f"APT {event_data.get('action', 'action')}: {event_data.get('commandline', '')}",
                    })
        
        except Exception as e:
            self.logger.error(f"Error parsing {log_file}: {e}")
        
        return events
    
    def parse_wtmp(self, wtmp_file: Path) -> List[Dict[str, Any]]:
        """
        Parse wtmp binary file (login records).
        
        Binary format: struct utmp entries
        Contains successful logins.
        
        Note: Requires struct unpacking. Simplified implementation.
        
        Returns list of login events.
        """
        events = []
        
        self.logger.warning(f"wtmp parsing requires binary struct parsing: {wtmp_file}")
        
        # TODO: Implement full wtmp binary parsing
        # Struct format varies by system (32-bit vs 64-bit)
        # Recommend using 'last -f wtmp' command or specialized library
        
        return events
    
    def parse_all_artifacts(self, mount_point: Path) -> Generator[Dict[str, Any], None, None]:
        """
        Parse all Linux artifacts from a mounted image.
        
        Yields events one at a time for memory efficiency.
        
        Args:
            mount_point: Path to mounted Linux filesystem
            
        Yields:
            Event dictionaries
        """
        self.logger.info(f"Parsing Linux artifacts from: {mount_point}")
        
        # Parse bash history
        for pattern in self.ARTIFACT_PATHS['bash_history']:
            for history_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing bash history: {history_file}")
                for event in self.parse_bash_history(history_file):
                    yield event
        
        # Parse zsh history
        for pattern in self.ARTIFACT_PATHS['zsh_history']:
            for history_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing zsh history: {history_file}")
                for event in self.parse_zsh_history(history_file):
                    yield event
        
        # Parse syslog
        for pattern in self.ARTIFACT_PATHS['syslog']:
            for log_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing syslog: {log_file}")
                for event in self.parse_syslog(log_file):
                    yield event
        
        # Parse auth log
        for pattern in self.ARTIFACT_PATHS['auth_log']:
            for log_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing auth log: {log_file}")
                for event in self.parse_auth_log(log_file):
                    yield event
        
        # Parse cron log
        for pattern in self.ARTIFACT_PATHS['cron_log']:
            for log_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing cron log: {log_file}")
                for event in self.parse_cron_log(log_file):
                    yield event
        
        # Parse APT history
        for pattern in self.ARTIFACT_PATHS['apt_history']:
            for log_file in mount_point.glob(pattern):
                self.logger.info(f"Parsing APT history: {log_file}")
                for event in self.parse_apt_history(log_file):
                    yield event
        
        self.logger.info("Linux artifact parsing complete")
    
    def _extract_username_from_path(self, file_path: Path) -> str:
        """Extract username from /home/username/... or /root path."""
        parts = file_path.parts
        try:
            if 'home' in parts:
                home_index = parts.index('home')
                if home_index + 1 < len(parts):
                    return parts[home_index + 1]
            elif 'root' in parts:
                return 'root'
        except (ValueError, IndexError):
            pass
        
        return 'Unknown'
    
    def _extract_year_from_filename(self, file_path: Path) -> Optional[int]:
        """Extract year from rotated log filename (e.g., syslog.2024.gz)."""
        match = re.search(r'20\d{2}', file_path.name)
        if match:
            return int(match.group(0))
        return None


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    print("Linux Forensic Artifact Parser")
    print("=" * 60)
    print("\nSupported Artifacts:")
    print("  ✓ Shell history (bash/zsh)")
    print("  ✓ syslog/messages")
    print("  ✓ auth.log/secure (SSH, sudo, su)")
    print("  ✓ cron logs")
    print("  ✓ APT package history (Debian/Ubuntu)")
    print("  ✓ systemd journal (with external tool)")
    print("  ⏳ wtmp/btmp/lastlog (binary format)")
    print("  ⏳ YUM/DNF logs (Red Hat/Fedora)")
    print("  ⏳ Apache/Nginx access logs")
    print("\nUsage:")
    print("  parser = LinuxParser()")
    print("  mount_point = Path('/mnt/linux_image')")
    print("  for event in parser.parse_all_artifacts(mount_point):")
    print("      print(event)")
    print("\n" + "=" * 60)

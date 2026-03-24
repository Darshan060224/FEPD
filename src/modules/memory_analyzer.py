"""
FEPD Memory Dump Analyzer
Native memory analysis without external dependencies
Extracts forensic artifacts from .mem and .dmp files
"""

import os
import re
import struct
import logging
from pathlib import Path
from typing import List, Dict, Optional, Generator
from datetime import datetime


class MemoryAnalyzer:
    """Analyze memory dumps for forensic artifacts."""
    
    def __init__(self, mem_path: str):
        self.mem_path = mem_path
        self.logger = logging.getLogger(__name__)
        self.file_size = os.path.getsize(mem_path)
        
        # Signatures for common artifacts
        self.PROCESS_NAME_PATTERN = rb'[\x20-\x7E]{4,64}\.exe\x00'
        self.IP_PATTERN = rb'(?:\d{1,3}\.){3}\d{1,3}'
        self.URL_PATTERN = rb'https?://[^\x00\x20]{4,256}'
        self.REGISTRY_KEY_PATTERN = rb'HKEY_[A-Z_]+\\[^\x00]{4,256}'
        self.CMD_HISTORY_PATTERN = rb'(?i)(?:cmd\.exe|powershell(?:\.exe)?)\s+[^\r\n\x00]{3,512}'
        self.POWERSHELL_SCRIPTBLOCK_PATTERN = rb'(?i)(?:IEX|Invoke-Expression|DownloadString|FromBase64String)[^\r\n\x00]{0,512}'
        self.NTLM_HASH_PATTERN = rb'(?i)\b[a-f0-9]{32}\b'
        self.CREDENTIAL_KEYWORDS = [
            b'password',
            b'passwd',
            b'credential',
            b'ntlm',
            b'lsass',
            b'sekurlsa',
        ]
        
    def scan_chunk(self, offset: int, chunk_size: int = 1024 * 1024) -> bytes:
        """Read a chunk of memory at given offset."""
        with open(self.mem_path, 'rb') as f:
            f.seek(offset)
            return f.read(chunk_size)

    def _iter_chunks(self, scan_limit: Optional[int] = None, chunk_size: int = 10 * 1024 * 1024):
        """Yield (offset, chunk) pairs from a single sequential file stream."""
        limit = min(self.file_size, scan_limit) if scan_limit else self.file_size
        offset = 0
        with open(self.mem_path, 'rb') as f:
            while offset < limit:
                to_read = min(chunk_size, limit - offset)
                chunk = f.read(to_read)
                if not chunk:
                    break
                yield offset, chunk
                offset += len(chunk)
    
    def extract_processes(self) -> List[Dict]:
        """
        Extract process information from memory dump.
        Scans for process names and PIDs.
        """
        processes = []
        seen_names = set()
        
        self.logger.info(f"Scanning memory dump: {self.mem_path} ({self.file_size / (1024**3):.2f} GB)")
        
        # Scan in 10MB chunks
        chunk_size = 10 * 1024 * 1024

        for offset, chunk in self._iter_chunks(chunk_size=chunk_size):
            try:
                # Find process names (*.exe)
                for match in re.finditer(self.PROCESS_NAME_PATTERN, chunk):
                    proc_name = match.group().decode('ascii', errors='ignore').strip('\x00')
                    
                    if proc_name not in seen_names:
                        seen_names.add(proc_name)
                        
                        # Try to find PID nearby (usually within 64 bytes)
                        context_start = max(0, match.start() - 64)
                        context_end = min(len(chunk), match.end() + 64)
                        context = chunk[context_start:context_end]
                        
                        # Look for 4-byte integer that could be PID (1-65535)
                        pid = None
                        for i in range(0, len(context) - 4, 4):
                            try:
                                potential_pid = struct.unpack('<I', context[i:i+4])[0]
                                if 1 <= potential_pid <= 65535:
                                    pid = potential_pid
                                    break
                            except:
                                pass
                        
                        processes.append({
                            'name': proc_name,
                            'pid': pid or 'unknown',
                            'offset': hex(offset + match.start()),
                            'first_seen': datetime.now().isoformat()
                        })
                
                if len(seen_names) > 0 and offset % (100 * 1024 * 1024) == 0:
                    self.logger.info(f"Progress: {offset / (1024**3):.2f} GB scanned, {len(seen_names)} processes found")
                    
            except Exception as e:
                self.logger.error(f"Error scanning chunk at {offset}: {e}")
                continue
        
        self.logger.info(f"Total processes found: {len(processes)}")
        return processes

    def extract_processes_limited(self, max_scan_bytes: int) -> List[Dict]:
        """Extract process artifacts from the first N bytes of memory."""
        if max_scan_bytes <= 0:
            return []

        processes = []
        seen_names = set()
        scan_limit = min(self.file_size, max_scan_bytes)
        chunk_size = 10 * 1024 * 1024

        for offset, chunk in self._iter_chunks(scan_limit=scan_limit, chunk_size=chunk_size):
            try:
                for match in re.finditer(self.PROCESS_NAME_PATTERN, chunk):
                    proc_name = match.group().decode('ascii', errors='ignore').strip('\x00')
                    if not proc_name or proc_name in seen_names:
                        continue
                    seen_names.add(proc_name)
                    processes.append({
                        'name': proc_name,
                        'pid': 'unknown',
                        'offset': hex(offset + match.start()),
                        'first_seen': datetime.now().isoformat(),
                    })
            except Exception:
                continue

        return processes
    
    def extract_network_connections(self) -> List[Dict]:
        """
        Extract network connection artifacts from memory.
        Looks for IP addresses and port patterns.
        """
        connections = []
        seen_ips = set()
        
        chunk_size = 10 * 1024 * 1024

        for offset, chunk in self._iter_chunks(chunk_size=chunk_size):
            try:
                # Find IP addresses
                for match in re.finditer(self.IP_PATTERN, chunk):
                    ip = match.group().decode('ascii', errors='ignore')
                    
                    # Validate IP format
                    parts = ip.split('.')
                    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts if p.isdigit()):
                        if ip not in seen_ips and not ip.startswith('0.'):
                            seen_ips.add(ip)
                            
                            # Look for port nearby (2 bytes)
                            context_start = max(0, match.start() - 16)
                            context_end = min(len(chunk), match.end() + 16)
                            context = chunk[context_start:context_end]
                            
                            port = None
                            for i in range(0, len(context) - 2, 2):
                                try:
                                    potential_port = struct.unpack('>H', context[i:i+2])[0]
                                    if 1 <= potential_port <= 65535:
                                        port = potential_port
                                        break
                                except:
                                    pass
                            
                            connections.append({
                                'ip': ip,
                                'port': port or 'unknown',
                                'offset': hex(offset + match.start()),
                                'protocol': 'TCP/UDP'
                            })
                
            except Exception as e:
                self.logger.error(f"Error scanning network chunk at {offset}: {e}")
                continue
        
        self.logger.info(f"Total network artifacts found: {len(connections)}")
        return connections

    def extract_network_connections_limited(self, max_scan_bytes: int) -> List[Dict]:
        """Extract network artifacts from the first N bytes of memory."""
        if max_scan_bytes <= 0:
            return []

        connections = []
        seen_ips = set()
        scan_limit = min(self.file_size, max_scan_bytes)
        chunk_size = 10 * 1024 * 1024

        for offset, chunk in self._iter_chunks(scan_limit=scan_limit, chunk_size=chunk_size):
            try:
                for match in re.finditer(self.IP_PATTERN, chunk):
                    ip = match.group().decode('ascii', errors='ignore')
                    if ip in seen_ips or ip.startswith('0.'):
                        continue
                    parts = ip.split('.')
                    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        continue
                    seen_ips.add(ip)
                    connections.append({
                        'ip': ip,
                        'port': 'unknown',
                        'offset': hex(offset + match.start()),
                        'protocol': 'TCP/UDP',
                    })
            except Exception:
                continue

        return connections
    
    def extract_urls(self) -> List[str]:
        """Extract URLs from memory dump."""
        urls = []
        seen_urls = set()
        
        chunk_size = 10 * 1024 * 1024

        for _, chunk in self._iter_chunks(chunk_size=chunk_size):
            try:
                for match in re.finditer(self.URL_PATTERN, chunk):
                    url = match.group().decode('ascii', errors='ignore')
                    if url not in seen_urls and len(url) > 10:
                        seen_urls.add(url)
                        urls.append(url)
                        
            except Exception as e:
                continue
        
        self.logger.info(f"Total URLs found: {len(urls)}")
        return urls
    
    def extract_registry_keys(self) -> List[str]:
        """Extract registry key references from memory."""
        registry_keys = []
        seen_keys = set()
        
        chunk_size = 10 * 1024 * 1024

        for _, chunk in self._iter_chunks(chunk_size=chunk_size):
            try:
                for match in re.finditer(self.REGISTRY_KEY_PATTERN, chunk):
                    key = match.group().decode('ascii', errors='ignore')
                    if key not in seen_keys:
                        seen_keys.add(key)
                        registry_keys.append(key)
                        
            except Exception as e:
                continue
        
        self.logger.info(f"Total registry keys found: {len(registry_keys)}")
        return registry_keys
    
    def extract_strings(self, min_length: int = 8, max_results: int = 10000) -> List[str]:
        """
        Extract printable strings from memory dump.
        
        Args:
            min_length: Minimum string length
            max_results: Maximum number of strings to return
        """
        strings = []
        current_string = bytearray()
        
        chunk_size = 10 * 1024 * 1024

        for offset, chunk in self._iter_chunks(chunk_size=chunk_size):
            try:
                for byte in chunk:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string.append(byte)
                    else:
                        if len(current_string) >= min_length:
                            s = current_string.decode('ascii', errors='ignore')
                            strings.append(s)
                            
                            if len(strings) >= max_results:
                                self.logger.info(f"Reached max strings limit: {max_results}")
                                return strings
                        
                        current_string = bytearray()
                        
            except Exception as e:
                self.logger.error(f"Error extracting strings at {offset}: {e}")
                continue
        
        self.logger.info(f"Total strings extracted: {len(strings)}")
        return strings

    def extract_command_history(self, max_results: int = 5000, max_scan_bytes: Optional[int] = None) -> List[Dict]:
        """
        Extract command-line traces from memory.

        Returns command artifacts including cmd.exe and PowerShell traces.
        """
        commands = []
        seen = set()
        chunk_size = 10 * 1024 * 1024

        scan_limit = min(self.file_size, max_scan_bytes) if max_scan_bytes else self.file_size
        for offset, chunk in self._iter_chunks(scan_limit=scan_limit, chunk_size=chunk_size):
            try:
                for pattern, label in [
                    (self.CMD_HISTORY_PATTERN, 'shell_command'),
                    (self.POWERSHELL_SCRIPTBLOCK_PATTERN, 'powershell_indicator'),
                ]:
                    for match in re.finditer(pattern, chunk):
                        cmd = match.group().decode('utf-8', errors='ignore').strip('\x00').strip()
                        if not cmd or cmd in seen:
                            continue
                        seen.add(cmd)
                        commands.append({
                            'type': label,
                            'command': cmd,
                            'offset': hex(offset + match.start()),
                        })
                        if len(commands) >= max_results:
                            return commands
            except Exception:
                continue

        return commands

    def extract_credential_indicators(self, max_results: int = 2000, max_scan_bytes: Optional[int] = None) -> List[Dict]:
        """
        Extract credential-related indicators from memory content.

        This does not guarantee valid credentials, but provides leads for investigation.
        """
        indicators = []
        chunk_size = 10 * 1024 * 1024

        scan_limit = min(self.file_size, max_scan_bytes) if max_scan_bytes else self.file_size
        for offset, chunk in self._iter_chunks(scan_limit=scan_limit, chunk_size=chunk_size):
            try:
                # NTLM-like 32-hex sequences
                for match in re.finditer(self.NTLM_HASH_PATTERN, chunk):
                    value = match.group().decode('ascii', errors='ignore').lower()
                    indicators.append({
                        'type': 'hash_indicator',
                        'value': value,
                        'offset': hex(offset + match.start()),
                    })
                    if len(indicators) >= max_results:
                        return indicators

                lowered = chunk.lower()
                for keyword in self.CREDENTIAL_KEYWORDS:
                    idx = lowered.find(keyword)
                    if idx != -1:
                        snippet_start = max(0, idx - 64)
                        snippet_end = min(len(chunk), idx + 192)
                        snippet = chunk[snippet_start:snippet_end].decode('utf-8', errors='ignore')
                        indicators.append({
                            'type': 'credential_keyword_context',
                            'keyword': keyword.decode('ascii', errors='ignore'),
                            'context': snippet,
                            'offset': hex(offset + idx),
                        })
                        if len(indicators) >= max_results:
                            return indicators

            except Exception:
                continue

        return indicators

    def reconstruct_live_state(
        self,
        expected_executables: Optional[List[str]] = None,
        max_scan_bytes: Optional[int] = None,
    ) -> Dict:
        """
        Build a unified memory live-state view for correlation pipeline.

        Args:
            expected_executables: Optional list of executable names seen on disk artifacts.
        """
        if max_scan_bytes and max_scan_bytes > 0:
            processes = self.extract_processes_limited(max_scan_bytes=max_scan_bytes)
            connections = self.extract_network_connections_limited(max_scan_bytes=max_scan_bytes)
            commands = self.extract_command_history(max_scan_bytes=max_scan_bytes)
            credential_indicators = self.extract_credential_indicators(max_scan_bytes=max_scan_bytes)
        else:
            processes = self.extract_processes()
            connections = self.extract_network_connections()
            commands = self.extract_command_history()
            credential_indicators = self.extract_credential_indicators()

        expected_set = {e.lower() for e in (expected_executables or []) if e}
        memory_processes = {p.get('name', '').lower() for p in processes if p.get('name')}

        memory_only_processes = sorted(
            p for p in memory_processes
            if p and expected_set and p not in expected_set
        )

        return {
            'file': self.mem_path,
            'size_bytes': self.file_size,
            'analysis_time': datetime.now().isoformat(),
            'processes': processes,
            'network_connections': connections,
            'command_history': commands,
            'credential_indicators': credential_indicators,
            'memory_only_processes': memory_only_processes,
            'summary': {
                'process_count': len(processes),
                'network_count': len(connections),
                'command_count': len(commands),
                'credential_indicator_count': len(credential_indicators),
                'memory_only_process_count': len(memory_only_processes),
            },
        }
    
    def quick_scan(self) -> Dict:
        """
        Perform quick scan of memory dump.
        Returns summary of key artifacts.
        """
        self.logger.info("Starting quick memory scan...")
        
        results = {
            'file': self.mem_path,
            'size_gb': round(self.file_size / (1024**3), 2),
            'scan_time': datetime.now().isoformat(),
            'processes': [],
            'network': [],
            'urls': [],
            'registry_keys': []
        }
        
        # Scan first 500MB for quick analysis
        quick_scan_size = min(500 * 1024 * 1024, self.file_size)
        chunk_size = 10 * 1024 * 1024
        
        seen_procs = set()
        seen_ips = set()
        
        for offset, chunk in self._iter_chunks(scan_limit=quick_scan_size, chunk_size=chunk_size):
            
            # Quick process scan
            for match in re.finditer(self.PROCESS_NAME_PATTERN, chunk):
                proc = match.group().decode('ascii', errors='ignore').strip('\x00')
                if proc not in seen_procs:
                    seen_procs.add(proc)
                    results['processes'].append(proc)
            
            # Quick network scan
            for match in re.finditer(self.IP_PATTERN, chunk):
                ip = match.group().decode('ascii', errors='ignore')
                if ip not in seen_ips:
                    parts = ip.split('.')
                    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        seen_ips.add(ip)
                        results['network'].append(ip)
        
        self.logger.info(f"Quick scan complete: {len(results['processes'])} processes, {len(results['network'])} IPs")
        return results
    
    def full_analysis(self, output_dir: str) -> Dict:
        """
        Perform full memory analysis and save results.
        
        Args:
            output_dir: Directory to save analysis results
        """
        os.makedirs(output_dir, exist_ok=True)
        
        self.logger.info("Starting full memory analysis...")
        
        # Extract all artifacts
        processes = self.extract_processes()
        connections = self.extract_network_connections()
        urls = self.extract_urls()
        registry_keys = self.extract_registry_keys()
        
        # Save results
        import json
        
        results = {
            'metadata': {
                'file': self.mem_path,
                'size_bytes': self.file_size,
                'size_gb': round(self.file_size / (1024**3), 2),
                'analysis_time': datetime.now().isoformat()
            },
            'processes': processes,
            'network_connections': connections,
            'urls': urls[:1000],  # Limit URLs
            'registry_keys': registry_keys[:1000],  # Limit registry keys
            'summary': {
                'total_processes': len(processes),
                'total_connections': len(connections),
                'total_urls': len(urls),
                'total_registry_keys': len(registry_keys)
            }
        }
        
        # Save JSON report
        report_path = os.path.join(output_dir, 'memory_analysis.json')
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save process list
        proc_path = os.path.join(output_dir, 'processes.txt')
        with open(proc_path, 'w') as f:
            f.write("Process Name\tPID\tOffset\n")
            f.write("=" * 80 + "\n")
            for p in processes:
                f.write(f"{p['name']}\t{p['pid']}\t{p['offset']}\n")
        
        # Save network connections
        net_path = os.path.join(output_dir, 'network.txt')
        with open(net_path, 'w') as f:
            f.write("IP Address\tPort\tProtocol\tOffset\n")
            f.write("=" * 80 + "\n")
            for c in connections:
                f.write(f"{c['ip']}\t{c['port']}\t{c['protocol']}\t{c['offset']}\n")
        
        self.logger.info(f"Full analysis complete. Results saved to: {output_dir}")
        self.logger.info(f"  - Processes: {len(processes)}")
        self.logger.info(f"  - Network: {len(connections)}")
        self.logger.info(f"  - URLs: {len(urls)}")
        self.logger.info(f"  - Registry: {len(registry_keys)}")
        
        return results


def analyze_memory_dump(mem_path: str, output_dir: Optional[str] = None, quick: bool = False):
    """
    Analyze memory dump file.
    
    Args:
        mem_path: Path to .mem or .dmp file
        output_dir: Directory to save results (optional)
        quick: If True, perform quick scan only
    
    Returns:
        Analysis results dictionary
    """
    if not os.path.exists(mem_path):
        raise FileNotFoundError(f"Memory dump not found: {mem_path}")
    
    analyzer = MemoryAnalyzer(mem_path)
    
    if quick:
        return analyzer.quick_scan()
    else:
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(mem_path), 'memory_analysis')
        return analyzer.full_analysis(output_dir)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python memory_analyzer.py <memdump.mem> [output_dir] [--quick]")
        sys.exit(1)
    
    mem_file = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else None
    quick_mode = '--quick' in sys.argv
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    print(f"\nFEPD Memory Dump Analyzer")
    print(f"=" * 80)
    print(f"File: {mem_file}")
    print(f"Mode: {'Quick Scan' if quick_mode else 'Full Analysis'}")
    print(f"=" * 80)
    print()
    
    results = analyze_memory_dump(mem_file, output, quick=quick_mode)
    
    print(f"\nAnalysis Complete!")
    print(f"Results: {results.get('summary', results)}")

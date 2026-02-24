"""Create a demo case with sample evidence for FEPD OS Terminal."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.fepd_os.case_context import CaseContextManager
from src.fepd_os.indexer import EvidenceIndexer
import sqlite3


def create_demo_case():
    """Create corp-leak demo case with sample artifacts."""
    print("Creating demo case: corp-leak")
    
    cc = CaseContextManager('.')
    db_path = cc.create_case('corp-leak')
    idx = EvidenceIndexer(db_path)
    
    # Sample evidence artifacts
    artifacts = [
        # Alice's files
        ('Users/alice/Desktop/budget.xlsx', 'alice', 'E01_corporate.dd'),
        ('Users/alice/Documents/strategy.pdf', 'alice', 'E01_corporate.dd'),
        ('Users/alice/Downloads/meeting_notes.docx', 'alice', 'E01_corporate.dd'),
        
        # Bob's files (suspicious)
        ('Users/bob/Desktop/report.docx', 'bob', 'E01_corporate.dd'),
        ('Users/bob/Desktop/payload.exe', 'bob', 'E01_corporate.dd'),
        ('Users/bob/Desktop/exfil_tool.py', 'bob', 'E01_corporate.dd'),
        ('Users/bob/Documents/credentials.txt', 'bob', 'E01_corporate.dd'),
        ('Users/bob/Downloads/tor-browser.exe', 'bob', 'E01_corporate.dd'),
        
        # System files
        ('System/config.ini', 'SYSTEM', 'E01_corporate.dd'),
        ('System/Windows/System32/cmd.exe', 'SYSTEM', 'E01_corporate.dd'),
        
        # Network captures
        ('Network/capture_2025-12-15.pcap', 'analyst', 'PCAP'),
        ('Network/dns_queries.log', 'analyst', 'PCAP'),
    ]
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    for path, owner, origin in artifacts:
        # Insert with synthetic metadata
        cur.execute(
            "INSERT OR REPLACE INTO files (path, owner, origin, size, created, modified, hash, ml_score) VALUES (?,?,?,?,?,?,?,?)",
            (
                path,
                owner,
                origin,
                1024 * (hash(path) % 500),  # synthetic size
                '2025-12-15T22:30:00Z',
                '2025-12-15T23:45:00Z',
                f"{hash(path):064x}",  # synthetic hash
                (hash(path) % 1000) / 1000.0  # synthetic score
            )
        )
    
    # Add timeline events
    events = [
        ('2025-12-15T22:30:15Z', 'FILE_CREATED', 'payload.exe created by bob'),
        ('2025-12-15T22:35:00Z', 'NETWORK_CONN', 'Outbound connection to 192.168.100.50:4444'),
        ('2025-12-15T22:40:30Z', 'FILE_ACCESS', 'credentials.txt read by payload.exe'),
        ('2025-12-15T23:00:00Z', 'NETWORK_CONN', 'Large data transfer detected'),
        ('2025-12-15T23:45:00Z', 'FILE_DELETED', 'exfil_tool.py removed'),
    ]
    
    for ts, etype, details in events:
        cur.execute("INSERT INTO events (ts, type, details) VALUES (?,?,?)", (ts, etype, details))
    
    conn.commit()
    conn.close()
    
    print(f"✓ Created case: corp-leak")
    print(f"  - {len(artifacts)} artifacts indexed")
    print(f"  - {len(events)} timeline events")
    print(f"  - 2 users: alice, bob")
    print("\nLaunch terminal: python src/fepd_os/cli_entry.py")
    print("Then run: use case corp-leak")


if __name__ == '__main__':
    create_demo_case()

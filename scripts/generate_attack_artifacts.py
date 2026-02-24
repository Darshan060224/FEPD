"""
Synthetic Forensic Artifact Generator
Generates realistic attack timeline artifacts for November 9, 2025
"""

import os
import json
import sqlite3
import struct
from datetime import datetime, timedelta
from pathlib import Path
import random
import hashlib

# Base timestamp: November 9, 2025, 02:00 AM
BASE_TIME = datetime(2025, 11, 9, 2, 0, 0)

def create_timestamp(offset_minutes):
    """Create timestamp offset from base time"""
    return BASE_TIME + timedelta(minutes=offset_minutes)

def create_windows_timestamp(dt):
    """Convert datetime to Windows FILETIME (100-nanosecond intervals since 1601-01-01)"""
    epoch_start = datetime(1601, 1, 1)
    delta = dt - epoch_start
    return int(delta.total_seconds() * 10000000)

def generate_documents():
    """Generate suspicious documents"""
    docs_dir = Path("Users/compromised_user/Documents")
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    # Q4 Strategy Plan (decoy)
    strategy = docs_dir / "Q4_Strategy_Plan.docx"
    with open(strategy, 'wb') as f:
        # Minimal DOCX header
        f.write(b'PK\x03\x04' + b'\x00' * 100)
    os.utime(strategy, (create_timestamp(0).timestamp(), create_timestamp(-120).timestamp()))
    
    # Suspicious passwords.txt
    passwords = docs_dir / "passwords.txt"
    with open(passwords, 'w') as f:
        f.write("bank_account: P@ssw0rd123\n")
        f.write("email_admin: CompanySecret2025\n")
        f.write("vpn_access: RemoteConnect99\n")
    os.utime(passwords, (create_timestamp(50).timestamp(), create_timestamp(50).timestamp()))
    
    # Suspicious contracts ZIP
    contracts = docs_dir / "suspicious_contracts.zip"
    with open(contracts, 'wb') as f:
        # ZIP header
        f.write(b'PK\x03\x04' + b'\x00' * 200)
    os.utime(contracts, (create_timestamp(75).timestamp(), create_timestamp(75).timestamp()))
    
    print("✅ Documents created")

def generate_malware():
    """Generate malicious executables"""
    downloads_dir = Path("Users/compromised_user/Downloads")
    downloads_dir.mkdir(parents=True, exist_ok=True)
    
    # Malicious invoice_reader.exe
    malware = downloads_dir / "invoice_reader.exe"
    with open(malware, 'wb') as f:
        # PE header
        f.write(b'MZ\x90\x00')
        f.write(b'\x00' * 60)
        f.write(b'PE\x00\x00')
        # Fake code section
        f.write(b'\xCC' * 5000)  # INT3 instructions (debugger trap)
        f.write('C2 server: 192.0.2.100:8443\n'.encode())
    os.utime(malware, (create_timestamp(12).timestamp(), create_timestamp(12).timestamp()))
    
    print("✅ Malware created")

def generate_ransomware_note():
    """Generate ransomware note on desktop"""
    desktop_dir = Path("Users/compromised_user/Desktop")
    desktop_dir.mkdir(parents=True, exist_ok=True)
    
    note = desktop_dir / "ransomware_note.txt"
    with open(note, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("YOUR FILES HAVE BEEN ENCRYPTED\n")
        f.write("=" * 60 + "\n\n")
        f.write("All your important files have been encrypted with military-grade encryption.\n\n")
        f.write("To recover your files, you must pay 5 BTC to:\n")
        f.write("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n\n")
        f.write("Contact: darknet_support@onion.link\n")
        f.write("Time: 2025-11-09 23:47:32\n")
    
    # Set timestamp to attack completion time
    ransom_time = create_timestamp(105)  # 03:45 AM
    os.utime(note, (ransom_time.timestamp(), ransom_time.timestamp()))
    
    print("✅ Ransomware note created")

def generate_temp_payload():
    """Generate temporary payload (will be marked as deleted)"""
    temp_dir = Path("Users/compromised_user/AppData/Local/Temp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    payload = temp_dir / "payload.tmp"
    with open(payload, 'wb') as f:
        f.write(b'\x4D\x5A\x90\x00')  # MZ header
        f.write(b'\xFF' * 2048)  # Encrypted payload
    
    # Set early timestamp
    os.utime(payload, (create_timestamp(35).timestamp(), create_timestamp(35).timestamp()))
    
    print("✅ Temp payload created")

def generate_chrome_history():
    """Generate Chrome browsing history with C2 connections"""
    chrome_dir = Path("Users/compromised_user/AppData/Local/Google/Chrome/User Data/Default")
    chrome_dir.mkdir(parents=True, exist_ok=True)
    
    history_db = chrome_dir / "History"
    
    # Delete if exists
    if history_db.exists():
        history_db.unlink()
    
    # Create SQLite database
    conn = sqlite3.connect(history_db)
    cursor = conn.cursor()
    
    # Create urls table
    cursor.execute('''
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL,
            hidden INTEGER DEFAULT 0
        )
    ''')
    
    # Create visits table
    cursor.execute('''
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER,
            transition INTEGER DEFAULT 0
        )
    ''')
    
    # Insert suspicious URLs
    urls = [
        (1, "https://c2-backdoor.ru/login", "Secure Login Portal", create_timestamp(30)),
        (2, "https://anonshare.xyz/upload", "Anonymous File Upload", create_timestamp(65)),
        (3, "https://pastebin.com/raw/xK9mP2zL", "Pastebin Raw", create_timestamp(45)),
        (4, "https://google.com/search?q=remote+desktop", "Google Search", create_timestamp(-10)),  # Decoy
        (5, "https://outlook.office365.com", "Outlook Mail", create_timestamp(-5)),  # Decoy
        (6, "http://192.0.2.100:8443/callback", "Direct IP Access", create_timestamp(70)),
    ]
    
    for url_id, url, title, visit_time in urls:
        webkit_time = create_windows_timestamp(visit_time)
        cursor.execute('''
            INSERT INTO urls (id, url, title, visit_count, last_visit_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (url_id, url, title, 1, webkit_time))
        
        cursor.execute('''
            INSERT INTO visits (url, visit_time)
            VALUES (?, ?)
        ''', (url_id, webkit_time))
    
    conn.commit()
    conn.close()
    
    print("✅ Chrome history created")

def generate_prefetch_files():
    """Generate Windows Prefetch files for executed programs"""
    prefetch_dir = Path("Windows/Prefetch")
    prefetch_dir.mkdir(parents=True, exist_ok=True)
    
    executables = [
        ("INVOICE_READER.EXE", 12, b'\x01'),
        ("CMD.EXE", 15, b'\x0A'),
        ("POWERSHELL.EXE", 15, b'\x05'),
        ("CHROME.EXE", 30, b'\x03'),
        ("EXPLORER.EXE", 0, b'\xFF'),  # System process
    ]
    
    for exe_name, offset, run_count in executables:
        # Generate hash (simplified)
        hash_val = hashlib.md5(exe_name.encode()).hexdigest()[:8].upper()
        pf_name = f"{exe_name}-{hash_val}.pf"
        pf_path = prefetch_dir / pf_name
        
        with open(pf_path, 'wb') as f:
            # Prefetch header (simplified version)
            f.write(b'SCCA')  # Signature
            f.write(struct.pack('<I', 26))  # Version (Win10)
            f.write(struct.pack('<I', 230))  # File size placeholder
            f.write(exe_name.encode('utf-16-le').ljust(60, b'\x00'))
            f.write(struct.pack('<Q', create_windows_timestamp(create_timestamp(offset))))
            f.write(run_count * 10)  # Run count
            f.write(b'\x00' * 100)  # Padding
        
        os.utime(pf_path, (create_timestamp(offset).timestamp(), create_timestamp(offset).timestamp()))
    
    print("✅ Prefetch files created")

def generate_event_logs():
    """Generate Windows Event Logs (EVTX format - simplified)"""
    evtx_dir = Path("Windows/System32/winevt/Logs")
    evtx_dir.mkdir(parents=True, exist_ok=True)
    
    # Security.evtx - Login events
    security_log = evtx_dir / "Security.evtx"
    with open(security_log, 'wb') as f:
        # EVTX header
        f.write(b'ElfFile\x00')
        f.write(struct.pack('<Q', 0x01))  # Version
        f.write(b'\x00' * 120)  # Header padding
        
        # Event 4624 - Successful login from external IP
        event_data = f'''
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>4624</EventID>
            <TimeCreated SystemTime="2025-11-09T02:00:15.000Z"/>
            <Computer>WORKSTATION-01</Computer>
          </System>
          <EventData>
            <Data Name="SubjectUserName">compromised_user</Data>
            <Data Name="IpAddress">203.0.113.45</Data>
            <Data Name="LogonType">10</Data>
            <Data Name="AuthenticationPackageName">Negotiate</Data>
          </EventData>
        </Event>
        '''.encode('utf-16-le')
        f.write(event_data)
    
    # System.evtx - Service starts
    system_log = evtx_dir / "System.evtx"
    with open(system_log, 'wb') as f:
        f.write(b'ElfFile\x00')
        f.write(struct.pack('<Q', 0x01))
        f.write(b'\x00' * 120)
        
        # Event 7045 - New service installed
        event_data = f'''
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>7045</EventID>
            <TimeCreated SystemTime="2025-11-09T02:20:00.000Z"/>
            <Computer>WORKSTATION-01</Computer>
          </System>
          <EventData>
            <Data Name="ServiceName">WindowsUpdateHelper</Data>
            <Data Name="ImagePath">C:\\Users\\compromised_user\\Downloads\\invoice_reader.exe</Data>
            <Data Name="ServiceType">user mode service</Data>
            <Data Name="StartType">auto start</Data>
          </EventData>
        </Event>
        '''.encode('utf-16-le')
        f.write(event_data)
    
    print("✅ Event logs created")

def generate_registry_artifacts():
    """Generate registry hive files with persistence keys"""
    reg_dir = Path("Windows/System32/config")
    reg_dir.mkdir(parents=True, exist_ok=True)
    
    # SYSTEM hive - RunOnce persistence
    system_hive = reg_dir / "SYSTEM"
    with open(system_hive, 'wb') as f:
        # Registry hive header
        f.write(b'regf')  # Signature
        f.write(struct.pack('<I', 1))  # Sequence
        f.write(struct.pack('<I', 1))  # Sequence2
        f.write(struct.pack('<Q', create_windows_timestamp(create_timestamp(20))))
        f.write(b'\x00' * 100)
        
        # Fake key data with persistence entry
        persistence_data = b'RunOnce\x00\x00WindowsUpdateHelper\x00C:\\Users\\compromised_user\\Downloads\\invoice_reader.exe\x00'
        f.write(persistence_data)
        f.write(b'\x00' * 500)
    
    # SAM hive - User account modifications
    sam_hive = reg_dir / "SAM"
    with open(sam_hive, 'wb') as f:
        f.write(b'regf')
        f.write(struct.pack('<I', 1))
        f.write(struct.pack('<I', 1))
        f.write(struct.pack('<Q', create_windows_timestamp(create_timestamp(40))))
        f.write(b'\x00' * 100)
        
        # User added to Administrators group
        sam_data = b'SAM\\Domains\\Account\\Users\\000001F4\x00Administrators\x00'
        f.write(sam_data)
        f.write(b'\x00' * 500)
    
    # NTUSER.DAT - User activity
    ntuser = Path("Users/compromised_user/NTUSER.DAT")
    ntuser.parent.mkdir(parents=True, exist_ok=True)
    with open(ntuser, 'wb') as f:
        f.write(b'regf')
        f.write(struct.pack('<I', 1))
        f.write(struct.pack('<I', 1))
        f.write(struct.pack('<Q', create_windows_timestamp(create_timestamp(30))))
        f.write(b'\x00' * 100)
        
        # TypedPaths and MRU entries
        user_data = b'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\x00'
        user_data += b'C:\\Users\\compromised_user\\Downloads\\invoice_reader.exe\x00'
        user_data += b'RecentDocs\x00suspicious_contracts.zip\x00passwords.txt\x00'
        f.write(user_data)
        f.write(b'\x00' * 500)
    
    print("✅ Registry hives created")

def generate_mft_simulation():
    """Generate MFT-like file listing for timeline reconstruction"""
    mft_file = Path("$MFT_simulation.csv")
    
    events = [
        # Format: Filename, Action, Timestamp, Size
        ("invoice_reader.exe", "CREATE", create_timestamp(12), 5120),
        ("payload.tmp", "CREATE", create_timestamp(35), 2048),
        ("passwords.txt", "MODIFY", create_timestamp(50), 156),
        ("suspicious_contracts.zip", "CREATE", create_timestamp(75), 8192),
        ("payload.tmp", "DELETE", create_timestamp(80), 0),
        ("ransomware_note.txt", "CREATE", create_timestamp(105), 512),
        ("Q4_Strategy_Plan.docx", "DELETE_ATTEMPT", create_timestamp(110), 0),
    ]
    
    with open(mft_file, 'w') as f:
        f.write("Timestamp,Filename,Action,Size,EntryNumber\n")
        for idx, (filename, action, timestamp, size) in enumerate(events):
            ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ts_str},{filename},{action},{size},{48000+idx}\n")
    
    print("✅ MFT simulation created")

def generate_network_logs():
    """Generate Zeek-style network connection logs"""
    logs_dir = Path("Logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    conn_log = logs_dir / "conn.log"
    with open(conn_log, 'w') as f:
        f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n")
        
        connections = [
            (create_timestamp(0), "192.168.1.100", 49152, "203.0.113.45", 3389, "tcp", "rdp", 1800, 5000, 12000),
            (create_timestamp(30), "192.168.1.100", 49153, "198.51.100.77", 443, "tcp", "ssl", 120, 2048, 4096),
            (create_timestamp(70), "192.168.1.100", 49154, "192.0.2.100", 8443, "tcp", "-", 300, 10240, 512),
        ]
        
        for ts, src_ip, src_port, dst_ip, dst_port, proto, service, duration, orig_bytes, resp_bytes in connections:
            ts_unix = int(ts.timestamp())
            uid = hashlib.md5(f"{ts_unix}{src_ip}".encode()).hexdigest()[:16]
            f.write(f"{ts_unix}\t{uid}\t{src_ip}\t{src_port}\t{dst_ip}\t{dst_port}\t{proto}\t{service}\t{duration}\t{orig_bytes}\t{resp_bytes}\tSF\n")
    
    print("✅ Network logs created")

def generate_lnk_files():
    """Generate LNK shortcut files to deleted payload"""
    recent_dir = Path("Users/compromised_user/AppData/Roaming/Microsoft/Windows/Recent")
    recent_dir.mkdir(parents=True, exist_ok=True)
    
    lnk_file = recent_dir / "payload.tmp.lnk"
    with open(lnk_file, 'wb') as f:
        # LNK header (simplified)
        f.write(b'\x4C\x00\x00\x00')  # Header size
        f.write(b'\x01\x14\x02\x00')  # CLSID
        f.write(b'\x00' * 60)
        # Target path
        target = "C:\\Users\\compromised_user\\AppData\\Local\\Temp\\payload.tmp"
        f.write(target.encode('utf-16-le'))
    
    os.utime(lnk_file, (create_timestamp(35).timestamp(), create_timestamp(35).timestamp()))
    
    print("✅ LNK files created")

def generate_srum_simulation():
    """Generate SRUM (System Resource Usage Monitor) simulation"""
    srum_file = Path("Windows/System32/sru/SRUDB.dat")
    srum_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(srum_file, 'wb') as f:
        # ESE database header (simplified)
        f.write(b'\xEF\xCD\xAB\x89')  # Magic
        f.write(b'\x00' * 100)
        
        # Simulate CPU/Network bursts during attack
        burst_data = struct.pack('<Q', create_windows_timestamp(create_timestamp(15)))
        burst_data += b'invoice_reader.exe\x00\x00'
        burst_data += struct.pack('<I', 95)  # CPU usage 95%
        burst_data += struct.pack('<Q', 10240000)  # Network bytes
        f.write(burst_data)
    
    print("✅ SRUM data created")

def main():
    """Generate all forensic artifacts"""
    print("\n" + "="*60)
    print("🔐 Synthetic Forensic Artifact Generator")
    print("Attack Timeline: November 9, 2025, 02:00-04:00 AM")
    print("="*60 + "\n")
    
    os.chdir("c:/Users/darsh/Desktop/FEPD/testttt")
    
    generate_documents()
    generate_malware()
    generate_ransomware_note()
    generate_temp_payload()
    generate_chrome_history()
    generate_prefetch_files()
    generate_event_logs()
    generate_registry_artifacts()
    generate_mft_simulation()
    generate_network_logs()
    generate_lnk_files()
    generate_srum_simulation()
    
    print("\n" + "="*60)
    print("✅ ALL ARTIFACTS GENERATED SUCCESSFULLY")
    print("="*60)
    print("\n📊 Summary:")
    print("  • Documents: 3 files (passwords, strategy, contracts)")
    print("  • Malware: 1 executable (invoice_reader.exe)")
    print("  • Ransomware Note: 1 file")
    print("  • Temp Payload: 1 file (marked for deletion)")
    print("  • Chrome History: 6 URLs (3 malicious, 3 decoy)")
    print("  • Prefetch: 5 files")
    print("  • Event Logs: 2 files (Security, System)")
    print("  • Registry Hives: 3 files (SYSTEM, SAM, NTUSER.DAT)")
    print("  • MFT Simulation: 7 events")
    print("  • Network Logs: 3 connections")
    print("  • LNK Files: 1 file")
    print("  • SRUM Data: 1 file")
    print("\n🎯 Next Steps:")
    print("  1. Ready for FEPD ingestion (folder-based)")
    print("  2. Or use FTK Imager/ewfacquire to convert to .E01:")
    print("     ewfacquire -t attack_2025-11-09.E01 -s 512M ./testttt/")
    print("  3. Ingest into FEPD pipeline")
    print("\n")

if __name__ == "__main__":
    main()

"""
Interactive FEPD Terminal Demo
Demonstrates all key features in a scripted session
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.fepd_os.shell import FEPDShellEngine


def demo_session():
    """Run a complete demo session."""
    print("="*70)
    print(" FEPD FORENSIC OPERATING SYSTEM - INTERACTIVE DEMO")
    print("="*70)
    print()
    
    engine = FEPDShellEngine('.')
    
    commands = [
        # Setup
        ("create_case corp-leak", "Creating case..."),
        ("use case corp-leak", "Mounting case..."),
        
        # Discovery
        ("users", "Listing users in case..."),
        ("use bob", "Switching to user bob..."),
        
        # Navigation
        ("pwd", "Current directory..."),
        ("ls Desktop", "Listing bob's Desktop..."),
        ("tree Users/bob", "Tree view of bob's files..."),
        
        # Inspection
        ("stat Users/bob/Desktop/payload.exe", "Inspecting payload.exe..."),
        ("hash Users/bob/Desktop/payload.exe", "Getting file hash..."),
        
        # ML Analysis
        ("score Users/bob/Desktop/payload.exe", "ML risk scoring..."),
        ("explain Users/bob/Desktop/payload.exe", "Explaining anomaly..."),
        
        # Timeline
        ("timeline", "Viewing timeline events..."),
        
        # Search
        ("find exe", "Finding executables..."),
        ("search payload", "Searching for 'payload'..."),
        
        # Context switching
        ("exit_user", "Clearing user context..."),
        ("use alice", "Switching to alice..."),
        ("ls Desktop", "Alice's Desktop..."),
        
        # Immutability test
        ("rm payload.exe", "Testing immutability..."),
        ("touch test.txt", "Testing write block..."),
        
        # Help
        ("help", "Showing help..."),
    ]
    
    for cmd, description in commands:
        print(f"\n{'─'*70}")
        print(f"💡 {description}")
        print(f"{'─'*70}")
        prompt = engine._prompt()
        print(f"\033[92m{prompt}\033[0m{cmd}")
        print()
        
        result = engine.dispatch(cmd)
        if result:
            # Truncate long output
            lines = result.split('\n')
            if len(lines) > 15:
                print('\n'.join(lines[:15]))
                print(f"... ({len(lines) - 15} more lines)")
            else:
                print(result)
        
        print()
    
    print("="*70)
    print(" DEMO COMPLETE")
    print("="*70)
    print()
    print("🎉 The FEPD Forensic OS Terminal is fully operational!")
    print()
    print("📚 Documentation:")
    print("   - Full guide: docs/FEPD_OS_TERMINAL.md")
    print("   - Quick ref:  docs/FEPD_TERMINAL_QUICK_REF.md")
    print("   - Summary:    docs/FEPD_OS_IMPLEMENTATION.md")
    print()
    print("🚀 Launch interactive terminal:")
    print("   python src/fepd_os/cli_entry.py")
    print()
    print("🧪 Run tests:")
    print("   python test_fepd_os.py")
    print()
    print("💾 Demo case:")
    print("   python create_demo_case.py")
    print()


if __name__ == '__main__':
    # Ensure demo case exists
    from src.fepd_os.case_context import CaseContextManager
    import sqlite3
    
    cc = CaseContextManager('.')
    db_path = cc.case_db_path('corp-leak')
    
    if not os.path.exists(db_path):
        print("Creating demo case first...")
        os.system(f"{sys.executable} create_demo_case.py")
        print()
    
    demo_session()

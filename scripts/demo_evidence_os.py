#!/usr/bin/env python3
"""
FEPD Evidence OS Emulation Demo

This demo showcases the Evidence OS feature that makes FEPD's terminal
feel like you're INSIDE the compromised machine's operating system.

When you load a Windows image → Terminal feels like CMD/PowerShell
When you load a Linux image → Terminal feels like Bash
When you load a macOS image → Terminal feels like zsh

🔒 EVERYTHING IS READ-ONLY
Any command that modifies state is intercepted, logged, and blocked.
"""

import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.fepd_os.shell import FEPDShellEngine


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    FEPD Evidence OS Emulation Demo                        ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  The terminal emulates the native OS of the forensic evidence             ║
║  Windows → CMD | Linux → Bash | macOS → zsh                               ║
║  🔒 All operations are READ-ONLY - evidence is protected                  ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")


def demo_windows_case(engine: FEPDShellEngine):
    """Demo Windows evidence OS emulation."""
    print("\n" + "=" * 70)
    print("  DEMO: Windows Evidence (corp-leak case)")
    print("=" * 70)
    
    try:
        result = engine.cmd_use(['case', 'corp-leak'])
        print(result)
        
        if not engine.evidence_shell:
            print("No evidence shell available")
            return
        
        print("\n--- Windows Commands ---\n")
        
        commands = [
            ('dir', 'List directory'),
            ('cd Desktop', 'Change to Desktop'),
            ('dir', 'List Desktop'),
            ('whoami', 'Show current user'),
            ('hostname', 'Show hostname'),
            ('systeminfo', 'Show system info'),
        ]
        
        for cmd, desc in commands:
            print(f"\n>>> {cmd}  # {desc}")
            print("-" * 50)
            output, blocked = engine.evidence_shell.execute(cmd)
            if output:
                print(output[:400] if len(output) > 400 else output)
        
        # Demonstrate blocked command
        print("\n--- Attempting Blocked Command ---\n")
        print(">>> del secret.txt  # SHOULD BE BLOCKED")
        print("-" * 50)
        output, blocked = engine.evidence_shell.execute('del secret.txt')
        print(f"Blocked: {blocked}")
        print(output[:300] if output else "(no output)")
        
    except Exception as e:
        print(f"Could not load Windows case: {e}")


def demo_linux_case(engine: FEPDShellEngine):
    """Demo Linux evidence OS emulation."""
    print("\n" + "=" * 70)
    print("  DEMO: Linux Evidence (linux_test case)")
    print("=" * 70)
    
    try:
        result = engine.cmd_use(['case', 'linux_test'])
        print(result)
        
        if not engine.evidence_shell:
            print("No evidence shell available")
            return
        
        print("\n--- Linux Commands ---\n")
        
        commands = [
            ('ls', 'List directory'),
            ('pwd', 'Print working directory'),
            ('cd /etc', 'Change to /etc'),
            ('ls', 'List /etc'),
            ('whoami', 'Show current user'),
            ('id', 'Show user identity'),
            ('uname -a', 'Show system info'),
        ]
        
        for cmd, desc in commands:
            print(f"\n>>> {cmd}  # {desc}")
            print("-" * 50)
            output, blocked = engine.evidence_shell.execute(cmd)
            if output:
                print(output[:300] if len(output) > 300 else output)
        
        # Demonstrate blocked command
        print("\n--- Attempting Blocked Command ---\n")
        print(">>> rm -rf /  # SHOULD BE BLOCKED")
        print("-" * 50)
        output, blocked = engine.evidence_shell.execute('rm -rf /')
        print(f"Blocked: {blocked}")
        print(output[:300] if output else "(no output)")
        
    except Exception as e:
        print(f"Could not load Linux case: {e}")


def demo_osinfo(engine: FEPDShellEngine):
    """Demo the osinfo command."""
    print("\n" + "=" * 70)
    print("  DEMO: osinfo Command")
    print("=" * 70)
    
    engine.cmd_use(['case', 'corp-leak'])
    
    print("\n>>> osinfo")
    print("-" * 50)
    print(engine.cmd_osinfo([]))
    
    print("\n>>> osinfo --toggle  # Switch to FEPD mode")
    print("-" * 50)
    print(engine.cmd_osinfo(['--toggle']))
    print(f"New prompt: {engine._prompt()}")
    
    print("\n>>> osinfo --toggle  # Back to native OS mode")
    print("-" * 50)
    print(engine.cmd_osinfo(['--toggle']))
    print(f"New prompt: {engine._prompt()}")


def main():
    print_banner()
    
    engine = FEPDShellEngine('.')
    
    # Demo Windows
    demo_windows_case(engine)
    
    # Demo Linux
    demo_linux_case(engine)
    
    # Demo osinfo
    demo_osinfo(engine)
    
    print("\n" + "=" * 70)
    print("  Demo Complete!")
    print("=" * 70)
    print("""
Key Features Demonstrated:
  ✓ Automatic OS detection from evidence (Windows/Linux)
  ✓ Native OS-style prompts (C:\\Users\\> vs user@host:~$)
  ✓ Native commands (dir vs ls, whoami, hostname, etc.)
  ✓ Directory navigation within evidence
  ✓ READ-ONLY enforcement - write commands are BLOCKED
  ✓ Chain of custody logging for blocked commands
  ✓ Toggle between native OS mode and FEPD mode
  
The investigator feels like they're INSIDE the compromised machine,
but the evidence is frozen in time and completely protected.
""")


if __name__ == '__main__':
    main()

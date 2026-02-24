"""
Visual Demo: FEPD OS Clean Terminal Experience
===============================================

This shows exactly what the user sees - nothing more, nothing less.
"""

from src.fepd_os.shell import FEPDShellEngine

def demo_clean_terminal():
    """Simulate the exact terminal output"""
    engine = FEPDShellEngine('.')
    
    # Create a case
    engine.dispatch('create_case LoneWolf_Investigation')
    engine.dispatch('use case LoneWolf_Investigation')
    engine.dispatch('use user root')
    
    print("═" * 70)
    print("FEPD OS Terminal - Clean Native Experience")
    print("═" * 70)
    print()
    
    # Simulate terminal session
    commands = [
        'ls',
        'cd memory',
        'ls',
        'pwd',
        'cat nonexistent.txt',
        'hash',
        'find malware.exe',
        'score suspicious.dll'
    ]
    
    for cmd in commands:
        # Show prompt and command
        print(f"{engine._prompt()}{cmd}")
        
        # Execute and show output (if any)
        try:
            output = engine.dispatch(cmd)
            if output:
                print(output)
        except Exception as e:
            print(str(e))
        
        # No extra spacing - just like a real shell
    
    # Show final prompt
    print(f"{engine._prompt()}", end="")
    print("█")  # Cursor
    
    print()
    print("═" * 70)
    print("Notice:")
    print("  ✓ No banners")
    print("  ✓ No 'READ-ONLY' warnings")
    print("  ✓ No 'Type help...' hints")
    print("  ✓ Errors are inline: 'command: error message'")
    print("  ✓ Silent context switches (prompt changes)")
    print("  ✓ Feels like you're INSIDE the seized evidence")
    print("═" * 70)

if __name__ == '__main__':
    demo_clean_terminal()

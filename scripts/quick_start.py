"""
Quick Start Script - FEPD Artifact Loader
Run this script to set up and test the artifact loader
"""

import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def main():
    """Quick start menu for artifact loader."""
    
    print("\n" + "="*80)
    print("FEPD - Forensic Artifact Loader - Quick Start")
    print("="*80)
    print("\nWhat would you like to do?\n")
    print("1. Create SQLite databases for mobile artifacts")
    print("2. Test artifact loader with current artifacts")
    print("3. View artifact folder structure")
    print("4. Launch FEPD main application")
    print("5. Exit")
    print("\n" + "="*80)
    
    choice = input("\nEnter your choice (1-5): ").strip()
    
    if choice == "1":
        print("\n📦 Creating SQLite databases...\n")
        import create_sqlite_databases
        create_sqlite_databases.main()
        
    elif choice == "2":
        print("\n🔍 Testing artifact loader...\n")
        import test_artifact_loader
        test_artifact_loader.main()
        
    elif choice == "3":
        print("\n📁 Artifact folder structure:\n")
        artifacts_path = Path(__file__).parent / "logggggggggggg"
        
        if not artifacts_path.exists():
            print(f"❌ Artifact folder not found: {artifacts_path}")
            return
        
        def print_tree(path: Path, prefix: str = "", is_last: bool = True):
            """Print directory tree."""
            if path.is_dir():
                # Print directory
                connector = "└── " if is_last else "├── "
                print(f"{prefix}{connector}{path.name}/")
                
                # Get children
                children = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name))
                
                # Print children
                for i, child in enumerate(children):
                    is_last_child = (i == len(children) - 1)
                    extension = "    " if is_last else "│   "
                    print_tree(child, prefix + extension, is_last_child)
            else:
                # Print file
                connector = "└── " if is_last else "├── "
                size = path.stat().st_size
                size_str = f"{size:,} bytes" if size < 1024 else f"{size/1024:.1f} KB"
                print(f"{prefix}{connector}{path.name} ({size_str})")
        
        print(f"\n{artifacts_path.name}/")
        children = sorted(artifacts_path.iterdir(), key=lambda x: (not x.is_dir(), x.name))
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            print_tree(child, "", is_last_child)
        
    elif choice == "4":
        print("\n🚀 Launching FEPD main application...\n")
        print("To use artifact loader:")
        print("  1. Go to Image Ingest tab")
        print("  2. Click 'Browse for Artifact Folder'")
        print("  3. Select the 'logggggggggggg' folder")
        print("  4. Complete the wizard")
        print("  5. View artifacts in Artifacts tab\n")
        
        import main as fepd_main
        fepd_main.main()
        
    elif choice == "5":
        print("\n👋 Goodbye!\n")
        return
    
    else:
        print("\n❌ Invalid choice. Please enter 1-5.\n")
        main()  # Show menu again


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted. Goodbye!\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")
        import traceback
        traceback.print_exc()

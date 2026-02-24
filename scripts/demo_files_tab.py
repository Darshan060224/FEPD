#!/usr/bin/env python3
"""
Demo: FEPD Files Tab - Forensic File Explorer
==============================================

Demonstrates the enhanced Files Tab with:
- Write-blocked filesystem browsing
- Breadcrumb navigation
- User profile detection
- Strings extraction
- Hex/Text view shortcuts
- Terminal path synchronization
"""

import sys
sys.path.insert(0, '.')

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt
from src.core.virtual_fs import VirtualFilesystem, VFSNode, VFSNodeType
from src.ui.files_tab import FilesTab, WRITE_BLOCK_MESSAGE
from pathlib import Path
from datetime import datetime
import tempfile
import os


def create_demo_vfs():
    """Create a demo VFS with sample forensic filesystem structure."""
    # Create temp database
    temp_dir = tempfile.mkdtemp(prefix="fepd_demo_")
    db_path = os.path.join(temp_dir, "demo_vfs.db")
    
    vfs = VirtualFilesystem(db_path)
    
    # Evidence ID
    evidence_id = "CASE-2025-001-DEMO"
    
    # Create realistic forensic filesystem structure
    nodes = [
        # Disk 0 - System Drive
        {
            "path": "/Disk0",
            "name": "Disk0 (500GB Samsung SSD)",
            "node_type": VFSNodeType.DISK,
            "size": 500 * 1024**3,
        },
        {
            "path": "/Disk0/Partition1",
            "name": "Partition1 - NTFS (C:)",
            "node_type": VFSNodeType.PARTITION,
            "size": 450 * 1024**3,
        },
        {
            "path": "/Disk0/Partition1/Windows",
            "name": "Windows",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Windows/System32",
            "name": "System32",
            "node_type": VFSNodeType.SYSTEM,
        },
        {
            "path": "/Disk0/Partition1/Windows/System32/config",
            "name": "config",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Windows/System32/config/SAM",
            "name": "SAM",
            "node_type": VFSNodeType.FILE,
            "size": 65536,
            "sha256": "a1b2c3d4e5f6...",
        },
        {
            "path": "/Disk0/Partition1/Windows/System32/config/SYSTEM",
            "name": "SYSTEM",
            "node_type": VFSNodeType.FILE,
            "size": 12582912,
            "sha256": "f6e5d4c3b2a1...",
        },
        {
            "path": "/Disk0/Partition1/Users",
            "name": "Users",
            "node_type": VFSNodeType.FOLDER,
        },
        # User profiles
        {
            "path": "/Disk0/Partition1/Users/Administrator",
            "name": "Administrator",
            "node_type": VFSNodeType.USER,
        },
        {
            "path": "/Disk0/Partition1/Users/Administrator/Desktop",
            "name": "Desktop",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/Administrator/Desktop/secret_plans.docx",
            "name": "secret_plans.docx",
            "node_type": VFSNodeType.FILE,
            "size": 245760,
            "sha256": "1234567890abcdef...",
        },
        {
            "path": "/Disk0/Partition1/Users/Administrator/Documents",
            "name": "Documents",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe",
            "name": "JohnDoe",
            "node_type": VFSNodeType.USER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/Desktop",
            "name": "Desktop",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/Desktop/evidence.jpg",
            "name": "evidence.jpg",
            "node_type": VFSNodeType.FILE,
            "size": 2457600,
            "sha256": "abcdef1234567890...",
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/AppData",
            "name": "AppData",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/AppData/Local",
            "name": "Local",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/AppData/Local/Google",
            "name": "Google",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/AppData/Local/Google/Chrome",
            "name": "Chrome",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/AppData/Local/Google/Chrome/User Data",
            "name": "User Data",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk0/Partition1/Users/JohnDoe/AppData/Local/Google/Chrome/User Data/History",
            "name": "History",
            "node_type": VFSNodeType.FILE,
            "size": 524288,
            "sha256": "histhash123456...",
        },
        # Disk 1 - External USB
        {
            "path": "/Disk1",
            "name": "Disk1 (32GB SanDisk USB)",
            "node_type": VFSNodeType.DISK,
            "size": 32 * 1024**3,
        },
        {
            "path": "/Disk1/Partition1",
            "name": "Partition1 - FAT32 (D:)",
            "node_type": VFSNodeType.PARTITION,
            "size": 31 * 1024**3,
        },
        {
            "path": "/Disk1/Partition1/DCIM",
            "name": "DCIM",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk1/Partition1/DCIM/Camera",
            "name": "Camera",
            "node_type": VFSNodeType.FOLDER,
        },
        {
            "path": "/Disk1/Partition1/DCIM/Camera/IMG_001.jpg",
            "name": "IMG_001.jpg",
            "node_type": VFSNodeType.FILE,
            "size": 3145728,
        },
        {
            "path": "/Disk1/Partition1/DCIM/Camera/IMG_002.jpg",
            "name": "IMG_002.jpg",
            "node_type": VFSNodeType.FILE,
            "size": 2621440,
        },
        # Deleted file (recovered)
        {
            "path": "/Disk1/Partition1/$Recycle.Bin/deleted_doc.pdf",
            "name": "deleted_doc.pdf (RECOVERED)",
            "node_type": VFSNodeType.DELETED,
            "size": 102400,
            "sha256": "deletedhash...",
        },
    ]
    
    # Add all nodes
    for node_data in nodes:
        parent_path = str(Path(node_data["path"]).parent)
        if parent_path == node_data["path"]:
            parent_path = None
        
        node = VFSNode(
            id=abs(hash(node_data["path"])) % (10**9),
            path=node_data["path"],
            name=node_data["name"],
            parent_path=parent_path if parent_path != "." else None,
            node_type=node_data["node_type"],
            size=node_data.get("size"),
            created=datetime.now(),
            modified=datetime.now(),
            accessed=datetime.now(),
            sha256=node_data.get("sha256"),
            evidence_id=evidence_id,
        )
        vfs.add_node(node)
    
    return vfs, temp_dir


class DemoWindow(QMainWindow):
    """Demo window for Files Tab."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FEPD Files Tab Demo - Forensic File Explorer")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet("background-color: #1e1e1e;")
        
        # Create demo VFS
        self.vfs, self.temp_dir = create_demo_vfs()
        
        # Create central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Info banner
        banner = QLabel("""
            <div style='padding: 10px; background: #0d47a1; color: white;'>
                <b>🔬 FEPD Forensic File Explorer Demo</b><br>
                <small>
                    Try: Right-click for context menu | Ctrl+H: Hex view | Ctrl+T: Text view | 
                    Ctrl+Shift+S: Strings | Delete/Cut/Rename: BLOCKED 🔒
                </small>
            </div>
        """)
        banner.setStyleSheet("background: #0d47a1;")
        layout.addWidget(banner)
        
        # Create Files Tab
        def coc_logger(action, details):
            print(f"[CoC] {action}: {details}")
        
        def read_file_func(path, offset, length):
            # Demo: return sample data
            return b"Sample file content for demo purposes. " * 100
        
        self.files_tab = FilesTab(
            vfs=self.vfs,
            coc_logger=coc_logger,
            read_file_func=read_file_func
        )
        
        # Connect signals
        self.files_tab.path_changed.connect(
            lambda p: print(f"[Signal] Path changed: {p}")
        )
        self.files_tab.user_context_changed.connect(
            lambda u: print(f"[Signal] User context: {u}")
        )
        self.files_tab.write_blocked.connect(
            lambda a: print(f"[Signal] Write BLOCKED: {a}")
        )
        
        layout.addWidget(self.files_tab)
        
        # Footer
        footer = QLabel("""
            <div style='padding: 8px; background: #252525; color: #888; font-size: 11px;'>
                📌 All write operations (Delete, Rename, Cut, Paste) are blocked to preserve evidence integrity.
                All actions logged to Chain of Custody.
            </div>
        """)
        layout.addWidget(footer)
    
    def closeEvent(self, event):
        """Clean up temp files."""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
        super().closeEvent(event)


def main():
    """Run the demo."""
    print("=" * 70)
    print("FEPD Files Tab Demo - Forensic File Explorer")
    print("=" * 70)
    print()
    print("Features demonstrated:")
    print("  ✅ Write-blocked indicator (top right)")
    print("  ✅ Breadcrumb navigation (shows current path)")
    print("  ✅ User profile detection (shows 👤 when in user folder)")
    print("  ✅ Disk/Partition/Folder/File hierarchy")
    print("  ✅ Right-click context menu with forensic actions")
    print("  ✅ Keyboard shortcuts:")
    print("     - Ctrl+H: Hex View")
    print("     - Ctrl+T: Text View")
    print("     - Ctrl+Shift+S: Extract Strings")
    print("     - Ctrl+I: File Details")
    print("     - Ctrl+E: Export File")
    print("     - Delete/Cut/Rename: BLOCKED")
    print()
    print("Starting GUI...")
    print()
    
    app = QApplication(sys.argv)
    window = DemoWindow()
    window.show()
    
    print("[CoC] SESSION_STARTED: Files Tab Demo initialized")
    print("[CoC] KEYBOARD_SHORTCUTS_INITIALIZED: Write operations blocked")
    print()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

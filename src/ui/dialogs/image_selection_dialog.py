"""
Image Selection Dialog - Select disk image for forensic analysis.
Supports E01, RAW, DD, and other image formats.
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                              QPushButton, QFileDialog, QLineEdit, QGroupBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon
from pathlib import Path
import logging


logger = logging.getLogger(__name__)


class ImageSelectionDialog(QDialog):
    """
    Dialog for selecting disk image file.
    
    Features:
    - File picker for image files
    - Format validation
    - Image info display
    - Browse and select interface
    
    Signals:
        image_selected: Emitted when image is selected (str: path)
    
    Example:
        >>> dialog = ImageSelectionDialog()
        >>> if dialog.exec() == QDialog.DialogCode.Accepted:
        ...     image_path = dialog.get_selected_image()
    """
    
    image_selected = pyqtSignal(str)
    
    SUPPORTED_FORMATS = [
        # Forensic Disk Images
        ('Expert Witness Format (EnCase)', '*.E01 *.e01 *.Ex01 *.ex01'),
        ('EnCase Logical Evidence', '*.L01 *.l01 *.Lx01 *.lx01'),
        ('Raw Disk Image', '*.raw *.dd *.img *.bin'),
        ('Split Disk Image', '*.001'),
        
        # Virtual Machine Disks
        ('VMware Virtual Disk', '*.vmdk'),
        ('Hyper-V Virtual Disk', '*.vhd *.vhdx'),
        ('QEMU Disk Image', '*.qcow *.qcow2'),
        ('VirtualBox Disk Image', '*.vdi'),
        
        # Advanced Forensic Formats
        ('Advanced Forensic Format', '*.aff *.aff4'),
        ('AccessData Evidence', '*.ad1'),
        
        # Memory Dumps
        ('Memory Dump', '*.mem *.dmp *.dump *.memory *.vmem *.mddramimage'),
        ('Windows Hibernation', '*.hiberfil'),
        ('Core Dump', '*.core'),
        
        # Mobile Forensics
        ('Android Backup', '*.ab *.tar'),
        ('iOS Backup', '*.backup'),
        ('Cellebrite UFED', '*.ufed *.ufd'),
        
        # Optical/ISO
        ('Optical Disc Image', '*.iso *.dmg'),
        
        # Network Captures
        ('Network Capture', '*.pcap *.pcapng'),
        
        # Archives (Logical Evidence)
        ('Archive Files', '*.zip *.7z *.rar *.tar *.gz *.tgz *.bz2 *.xz'),
        
        # Logs and Events
        ('Windows Event Logs', '*.evtx *.evt *.etl'),
        ('Log Files', '*.log *.txt *.csv'),
        
        # Email
        ('Email Archives', '*.pst *.ost *.mbox *.eml'),
        
        # Database
        ('Database Files', '*.sqlite *.sqlite3 *.db'),
        
        # All Files (fallback)
        ('All Forensic Evidence', '*.*')
    ]
    
    def __init__(self, parent=None):
        """
        Initialize image selection dialog.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        self.selected_image_path = None
        
        self.setWindowTitle("Select Disk Image")
        self.setModal(True)
        self.resize(600, 250)
        
        self._init_ui()
        
        logger.info("ImageSelectionDialog initialized")
    
    def _init_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Select Disk Image for Analysis")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #2c3e50;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel(
            "Choose a disk image file to analyze. Supported formats include "
            "Expert Witness (E01) and raw disk images (RAW, DD, IMG)."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #7f8c8d; padding: 5px;")
        layout.addWidget(desc)
        
        # Image selection group
        image_group = QGroupBox("Disk Image")
        image_layout = QVBoxLayout(image_group)
        
        # File path display
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("No image selected...")
        self.path_edit.setReadOnly(True)
        path_layout.addWidget(self.path_edit)
        
        # Browse button
        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.setFixedWidth(100)
        self.browse_btn.clicked.connect(self._on_browse)
        path_layout.addWidget(self.browse_btn)
        
        image_layout.addLayout(path_layout)
        
        # Image info label
        self.info_label = QLabel("No image selected")
        self.info_label.setStyleSheet("color: #7f8c8d; font-style: italic; padding: 5px;")
        image_layout.addWidget(self.info_label)
        
        layout.addWidget(image_group)
        
        # Spacer
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedWidth(100)
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        self.ok_btn = QPushButton("OK")
        self.ok_btn.setFixedWidth(100)
        self.ok_btn.setEnabled(False)  # Disabled until image selected
        self.ok_btn.clicked.connect(self._on_ok)
        self.ok_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        button_layout.addWidget(self.ok_btn)
        
        layout.addLayout(button_layout)
    
    def _on_browse(self):
        """Handle browse button click."""
        # Build filter string
        filter_str = ";;".join([f"{name} ({pattern})" for name, pattern in self.SUPPORTED_FORMATS])
        
        # Show file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            "",
            filter_str
        )
        
        if file_path:
            self._set_image_path(file_path)
    
    def _set_image_path(self, path: str):
        """
        Set selected image path and update UI.
        
        Args:
            path: Path to image file
        """
        path_obj = Path(path)
        
        # Validate file exists
        if not path_obj.exists():
            self.info_label.setText("❌ Error: File does not exist")
            self.info_label.setStyleSheet("color: #e74c3c; font-style: italic; padding: 5px;")
            self.ok_btn.setEnabled(False)
            return
        
        # Get file info
        file_size = path_obj.stat().st_size
        size_mb = file_size / (1024 * 1024)
        size_gb = size_mb / 1024
        
        if size_gb >= 1:
            size_str = f"{size_gb:.2f} GB"
        else:
            size_str = f"{size_mb:.2f} MB"
        
        # Determine format - comprehensive detection
        ext = path_obj.suffix.lower()
        FORMAT_MAP = {
            '.e01': 'Expert Witness Format (E01)',
            '.ex01': 'Expert Witness Format Extended',
            '.l01': 'Logical Evidence File (L01)',
            '.raw': 'Raw Disk Image',
            '.dd': 'Raw Disk Image (dd)',
            '.img': 'Disk Image',
            '.bin': 'Binary Image',
            '.vmdk': 'VMware Virtual Disk',
            '.vhd': 'Hyper-V Virtual Hard Disk',
            '.vhdx': 'Hyper-V Virtual Hard Disk (Extended)',
            '.qcow2': 'QEMU Copy-On-Write Disk',
            '.qcow': 'QEMU Disk Image',
            '.vdi': 'VirtualBox Disk Image',
            '.aff': 'Advanced Forensic Format',
            '.aff4': 'Advanced Forensic Format 4',
            '.ad1': 'AccessData Evidence File',
            '.mem': 'Memory Dump',
            '.dmp': 'Windows Memory Dump',
            '.dump': 'Memory Dump',
            '.vmem': 'VMware Memory Snapshot',
            '.hiberfil': 'Windows Hibernation File',
            '.core': 'Core Dump',
            '.iso': 'ISO Optical Disc Image',
            '.dmg': 'macOS Disk Image',
            '.pcap': 'Network Packet Capture',
            '.pcapng': 'Network Packet Capture (Next Gen)',
            '.tar': 'TAR Archive',
            '.ab': 'Android Backup',
            '.ufed': 'Cellebrite UFED',
            '.zip': 'ZIP Archive',
            '.7z': '7-Zip Archive',
            '.evtx': 'Windows Event Log',
            '.evt': 'Windows Event Log (Legacy)',
            '.pst': 'Outlook Personal Folders',
            '.ost': 'Outlook Offline Folders',
            '.sqlite': 'SQLite Database',
            '.db': 'Database File',
            '.001': 'Split Image Segment',
        }
        format_str = FORMAT_MAP.get(ext, f"Evidence File ({ext.upper()})")
        
        # Update UI
        self.path_edit.setText(str(path_obj))
        self.info_label.setText(f"✓ {format_str} • Size: {size_str}")
        self.info_label.setStyleSheet("color: #27ae60; font-weight: bold; padding: 5px;")
        
        self.selected_image_path = str(path_obj)
        self.ok_btn.setEnabled(True)
        
        logger.info(f"Image selected: {path_obj.name} ({size_str})")
    
    def _on_ok(self):
        """Handle OK button click."""
        if self.selected_image_path:
            self.image_selected.emit(self.selected_image_path)
            self.accept()
    
    def get_selected_image(self) -> str:
        """
        Get path of selected image.
        
        Returns:
            Image file path, or None
        """
        return self.selected_image_path
    
    def set_initial_directory(self, directory: str):
        """
        Set initial directory for file dialog.
        
        Args:
            directory: Directory path
        """
        # This would be used if we stored last directory
        pass


if __name__ == '__main__':
    """Quick test of ImageSelectionDialog."""
    import sys
    from PyQt6.QtWidgets import QApplication
    
    print("=" * 60)
    print("ImageSelectionDialog Test")
    print("=" * 60)
    print("\nShowing image selection dialog...")
    print("(This is a visual test - select a file or cancel)")
    
    app = QApplication(sys.argv)
    
    dialog = ImageSelectionDialog()
    
    # Connect signal
    def on_image_selected(path):
        print(f"\n✓ Image selected: {path}")
    
    dialog.image_selected.connect(on_image_selected)
    
    result = dialog.exec()
    
    if result == QDialog.DialogCode.Accepted:
        image_path = dialog.get_selected_image()
        print(f"\nDialog accepted")
        print(f"Selected image: {image_path}")
        print("\n✅ ImageSelectionDialog test completed!")
    else:
        print("\nDialog cancelled")
        print("\n⚠ Test cancelled by user")
    
    print("=" * 60)

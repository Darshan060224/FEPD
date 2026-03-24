"""
Quick test to verify Files Tab implementation.
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from PyQt6.QtWidgets import QApplication, QMainWindow
from src.ui.files_tab import FilesTab
from src.core.virtual_fs import VirtualFilesystem

def main():
    """Test the Files Tab."""
    app = QApplication(sys.argv)
    
    # Create a VFS instance
    vfs_db_path = Path("data/workspace/test_vfs.db")
    vfs_db_path.parent.mkdir(parents=True, exist_ok=True)
    
    vfs = VirtualFilesystem(vfs_db_path)
    
    # Initialize VFS with some dummy data
    vfs.add_root("This PC")
    vfs.add_node("/This PC/C:", "C:", "DRIVE")
    vfs.add_node("/This PC/C:/Users", "Users", "FOLDER", parent_path="/This PC/C:")
    vfs.add_node("/This PC/C:/Users/Test", "Test", "FOLDER", parent_path="/This PC/C:/Users")
    
    # Create CoC logger
    def coc_logger(action: str, details: dict):
        print(f"[CoC] {action}: {details}")
    
    # Create read file function
    def read_file_func(path: str, offset: int, length: int):
        return None  # Placeholder
    
    # Create Files Tab
    files_tab = FilesTab(
        vfs=vfs,
        read_file_func=read_file_func,
        coc_logger=coc_logger
    )
    
    # Create main window
    window = QMainWindow()
    window.setWindowTitle("FEPD Files Tab Test")
    window.setCentralWidget(files_tab)
    window.resize(1400, 800)
    window.show()
    
    print("Files Tab loaded successfully!")
    print("You should see a 3-panel interface similar to Windows Explorer.")
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

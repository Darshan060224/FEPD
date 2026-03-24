"""
FEPD - Forensic Evidence Parser Dashboard
Main Application Entry Point

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import sys
import logging
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import Qt

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.ui.main_window import MainWindow
from src.utils.logger import setup_logging
from src.utils.config import Config
from src.utils.chain_of_custody import ChainOfCustody


def main():
    """Main application entry point."""
    
    # Initialize configuration
    config = Config()
    
    # Setup logging
    setup_logging(config)
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 80)
    logger.info("FEPD - Forensic Evidence Parser Dashboard")
    logger.info(f"Version: {config.get('APP_VERSION', '1.0.0')}")
    logger.info(f"Environment: {config.get('APP_ENV', 'production')}")
    logger.info("=" * 80)
    
    # Initialize Chain of Custody
    coc = ChainOfCustody(config)
    coc.log_event("APPLICATION_START", "FEPD application started", severity="INFO")
    
    try:
        # Enable high DPI scaling
        if hasattr(Qt, 'AA_EnableHighDpiScaling'):
            QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
            QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        
        # Create Qt Application
        app = QApplication(sys.argv)
        app.setApplicationName("FEPD")
        app.setApplicationVersion(config.get('APP_VERSION', '1.0.0'))
        app.setOrganizationName("Forensic Analysis Lab")
        
        # Set application icon/logo
        logo_path = Path(__file__).parent / "logo" / "logo.png"
        if logo_path.exists():
            app.setWindowIcon(QIcon(str(logo_path)))
            logger.info(f"Application icon loaded: {logo_path}")
        else:
            logger.warning(f"Logo not found at: {logo_path}")
        
        # Create main window FIRST (in background, disabled)
        logger.info("Initializing main window (disabled)...")
        main_window = MainWindow(config)
        main_window.setEnabled(False)  # Disable interaction until case is loaded
        main_window.showFullScreen()
        
        # Process events to ensure window is visible
        app.processEvents()
        
        # Show case selection dialog ON TOP of main window
        logger.info("Showing case selection dialog on top...")
        from src.ui.dialogs.case_dialog import CaseDialog
        
        case_dialog = CaseDialog(main_window)  # Pass main window as parent
        dialog_result = case_dialog.exec()
        
        # Check if user cancelled or closed dialog
        if dialog_result != QDialog.DialogCode.Accepted:
            logger.info("User cancelled case selection, exiting application")
            coc.log_event("APPLICATION_EXIT", "User cancelled case selection", severity="INFO")
            return 0
        
        # Get selected case metadata and image path
        case_metadata = case_dialog.get_selected_case()
        image_path = case_dialog.get_image_path()
        
        if not case_metadata:
            logger.error("No case metadata available despite dialog acceptance")
            QMessageBox.critical(
                main_window,
                "Error",
                "Failed to load case information. Application will exit."
            )
            return 1
        
        logger.info(f"Case selected: {case_metadata.get('case_id', 'Unknown')}")
        logger.info(f"Image path: {image_path}")
        
        # Get case path from metadata
        case_id = case_metadata.get('case_id')
        if not case_id:
            logger.error("Case ID not found in metadata")
            return 1
        
        case_path = Path("cases") / case_id
        
        logger.info(f"Case path: {case_path}")
        
        # Load case into main window and enable UI
        logger.info("Loading case into main window...")
        success = main_window.load_case(case_metadata, case_path, image_path)
        
        if not success:
            logger.error("Failed to load case into main window")
            QMessageBox.critical(
                main_window,
                "Error",
                "Failed to load case. Application will exit."
            )
            return 1
        
        # Enable main window for interaction
        main_window.setEnabled(True)
        main_window.activateWindow()
        main_window.raise_()
        
        logger.info("Application ready")
        coc.log_event("APPLICATION_READY", "Main window initialized", severity="INFO")
        
        # Start event loop
        exit_code = app.exec()
        
        # Clean shutdown
        logger.info(f"Application exiting with code: {exit_code}")
        coc.log_event("APPLICATION_EXIT", f"Exit code: {exit_code}", severity="INFO")
        
        return exit_code
        
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        coc.log_event("APPLICATION_ERROR", f"Fatal error: {e}", severity="CRITICAL")
        return 1


if __name__ == "__main__":
    sys.exit(main())

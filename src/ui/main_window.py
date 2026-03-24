"""
FEPD - Forensic Evidence Parser Dashboard
Main Window UI

Implements FR-18 to FR-35: Complete tab-based forensic analysis interface

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import pandas as pd
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QStatusBar, QMenuBar, QMenu, QMessageBox, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QInputDialog, QApplication, QDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QBrush, QColor

from ..utils.config import Config
from ..utils.chain_of_custody import ChainOfCustody
from ..modules.pipeline import FEPDPipeline
from ..utils.report_generator import ReportGenerator
from ..utils.session_manager import SessionManager
from ..utils.i18n.translator import Translator
from src.services.unified_forensic_store import UnifiedForensicStore
from src.services.forensic_tab_engine import (
    ForensicTabExtractionEngine,
    TAB_FIELDS,
    route_to_tab,
    validate_or_coerce_response,
)
import threading


class MainWindow(QMainWindow):
    # Signal for thread-safe UI updates after pipeline completion
    pipeline_finished = pyqtSignal(object, object)  # (classified_df, pipeline)
    # Signal for tree population (must run on main thread)
    populate_tree_signal = pyqtSignal(object, object, int)  # (image_path, extracted_dir, total_extracted)
    # Signal for progress updates from background threads
    progress_update_signal = pyqtSignal(int, str)  # (percentage, message)
    """
    Main application window for FEPD.
    
    Features:
    - Tab-based interface (Ingest, Artifacts, Timeline, Report)
    - Menu bar with File, Tools, Help
    - Status bar with progress indicators
    - Chain of Custody integration
    - Dark Indigo theme application
    - Case management integration
    """
    
    def __init__(self, config: Config):
        """
        Initialize Main Window.
        
        Args:
            config: Configuration instance
        """
        super().__init__()
        
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.coc = ChainOfCustody(config)
        
        # Initialize session manager and translator
        self.session_manager = None  # Will be initialized when case is loaded
        self.translator = Translator()
        
        self.current_case = None
        self.case_workspace = None
        
        # Store case metadata (will be loaded later)
        self.case_metadata = None
        self.case_path = None
        self.image_path = None
        self.dynamic_insights_tabs = None
        self._dynamic_renderer = None
        self._last_forensic_hydration_at: Optional[datetime] = None
        self._active_ingest_source_type: Optional[str] = None
        
        # Case cache for quick reopening (enterprise feature)
        self._case_cache = {}  # {case_id: {'data': df, 'timestamp': datetime, 'artifacts': list}}
        self._cache_max_age_seconds = 3600  # Cache valid for 1 hour
        
        self._init_ui()
        self._apply_theme()
        self._setup_menu_bar()
        self._setup_status_bar()
        
        # Connect signal for thread-safe pipeline completion
        self.pipeline_finished.connect(self._on_pipeline_finished)
        # Connect signal for tree population
        self.populate_tree_signal.connect(self._populate_image_tree)
        # Connect signal for progress updates
        self.progress_update_signal.connect(self._on_progress_update)
        
        self.logger.info("Main Window initialized (waiting for case)")
    
    def _init_ui(self):
        """Initialize UI components."""
        # Set window title with case ID if available
        window_title = "FEPD - Forensic Evidence Parser Dashboard v1.0.0"
        if self.case_metadata:
            case_id = self.case_metadata.get('case_id', 'N/A')
            window_title += f" - {case_id}"
        
        self.setWindowTitle(window_title)
        self.setGeometry(100, 100, 1600, 900)
        
        # Set application icon/logo
        logo_path = Path(__file__).parent.parent.parent / "logo" / "logo.png"
        if logo_path.exists():
            self.setWindowIcon(QIcon(str(logo_path)))
            self.logger.info(f"Application logo loaded: {logo_path}")
        else:
            self.logger.warning(f"Logo not found at: {logo_path}")
        
        # Central widget with tab interface
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setMovable(False)
        
        # Tab 0: Case Details (NEW - only if case is loaded)
        if self.case_metadata and self.case_path:
            from .tabs.case_details_tab import CaseDetailsTab
            self.case_details_tab = CaseDetailsTab(self.case_metadata, self.case_path)
            self.tabs.addTab(self.case_details_tab, "📋 Case Details")

        # Tab 1: Image Ingest
        self.ingest_tab = self._create_ingest_tab()
        self.tabs.addTab(self.ingest_tab, "📁 Image Ingest")
        
        # Tab 2: Files (Forensic File Explorer)
        self.files_tab = self._create_files_tab()
        if self.files_tab:
            self.tabs.addTab(self.files_tab, "🗂️ Files")
        
        # Tab 4: Artifacts (Enhanced — Real artifact categories)
        self.artifacts_tab = self._create_artifacts_tab()
        self.tabs.addTab(self.artifacts_tab, "🔍 Artifacts")
        
        # Tab 5: Timeline (Enhanced — Event intelligence)
        self.timeline_tab = self._create_timeline_tab()
        self.tabs.addTab(self.timeline_tab, "📊 Timeline")
        
        # Tab 4: ML Analytics (NEW)
        from .tabs.ml_analytics_tab import MLAnalyticsTab
        self.ml_analytics_tab = MLAnalyticsTab()
        self.tabs.addTab(self.ml_analytics_tab, "🤖 ML Analytics")
        
        # Tab 5: Visualizations (NEW)
        from .tabs.visualizations_tab import VisualizationsTab
        self.visualizations_tab = VisualizationsTab()
        self.tabs.addTab(self.visualizations_tab, "📈 Visualizations")

        # Terminal tab intentionally removed per UX request.
        self.fepd_terminal = None
        
        # Tab 7: Report
        self.report_tab = self._create_report_tab()
        self.tabs.addTab(self.report_tab, "📄 Report")
        
        # Tab 9: Chatbot (RAG-powered forensic assistant)
        from .tabs.chatbot_tab import ChatbotTab
        self.chatbot_tab = ChatbotTab()
        self.tabs.addTab(self.chatbot_tab, "💬 Chatbot")
        
        layout.addWidget(self.tabs)

        # Defensive cleanup: remove legacy Configuration tab if any path injected it.
        self._remove_legacy_configuration_tab()
        
        # Connect tab change signal
        self.tabs.currentChanged.connect(self._on_tab_changed)

    def _remove_legacy_configuration_tab(self) -> None:
        """Remove legacy Configuration tab from UI if present."""
        try:
            for idx in range(self.tabs.count() - 1, -1, -1):
                label = self.tabs.tabText(idx).lower()
                if "configuration" in label:
                    widget = self.tabs.widget(idx)
                    self.tabs.removeTab(idx)
                    if widget is not None:
                        widget.deleteLater()
            if hasattr(self, 'configuration_tab'):
                self.configuration_tab = None
        except Exception as exc:
            self.logger.warning("Could not remove legacy Configuration tab: %s", exc)

    def _create_ingest_tab(self) -> QWidget:
        """Create Image Ingest tab — Enhanced with Evidence Intelligence Dashboard."""
        try:
            from .tabs.image_ingest_tab import ImageIngestTab
            from ..core.case_manager import CaseManager

            case_mgr = CaseManager(base_cases_dir=str(
                Path(self.case_path).parent if self.case_path else "cases"
            ))
            if self.case_metadata and self.case_path:
                case_mgr.current_case = self.case_metadata
                case_mgr.case_path = Path(self.case_path)

            tab = ImageIngestTab(case_manager=case_mgr)
            self._enhanced_ingest_tab = tab
            self.logger.info("Enhanced Image Ingest tab loaded (Evidence Intelligence)")
            return tab
        except Exception as exc:
            self.logger.warning("Enhanced Ingest tab unavailable, using fallback: %s", exc)
            import traceback; traceback.print_exc()

        # ── Fallback: minimal placeholder ──
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        from PyQt6.QtWidgets import QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QSplitter
        
        # Info label
        label = QLabel(
            "📁 Image Ingest Tab\n\n"
            "Create or Open a case first to enable image ingestion.\n\n"
            "Supported formats:\n"
            "• Disk Images: E01, DD, RAW, IMG, VMDK, VHD, QCOW2, AFF\n"
            "• Memory Dumps: MEM, DMP, VMEM, MDDRAMIMAGE, Hibernation\n"
            "• Mobile: Android Backup, iOS, UFED\n"
            "• Archives: ZIP, 7Z, TAR\n"
            "• Network: PCAP, PCAPNG\n"
            "• Logs: EVTX, EVT, ETL"
        )
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        
        # Ingest button (disabled until case is active)
        self.btn_open_image = QPushButton("📂 Ingest Disk Image...")
        self.btn_open_image.clicked.connect(self._open_disk_image)
        self.btn_open_image.setEnabled(False)  # Disabled by default (no active case)
        self.btn_open_image.setMinimumHeight(40)
        layout.addWidget(self.btn_open_image)
        
        # Create 2-pane splitter for filesystem view
        fs_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # LEFT PANE: Folder Tree
        tree_container = QWidget()
        tree_layout = QVBoxLayout(tree_container)
        tree_layout.setContentsMargins(0, 10, 0, 0)
        
        tree_label = QLabel("� Folder Tree")
        tree_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        tree_layout.addWidget(tree_label)
        
        self.image_tree = QTreeWidget()
        self.image_tree.setHeaderLabels(["Folder Structure"])
        self.image_tree.setColumnCount(1)
        self.image_tree.setAlternatingRowColors(True)
        self.image_tree.itemClicked.connect(self._on_tree_item_clicked)
        tree_layout.addWidget(self.image_tree)
        
        fs_splitter.addWidget(tree_container)
        
        # RIGHT PANE: File Metadata Table
        metadata_container = QWidget()
        metadata_layout = QVBoxLayout(metadata_container)
        metadata_layout.setContentsMargins(0, 10, 0, 0)
        
        metadata_label = QLabel("📋 File Metadata (Double-click to view file)")
        metadata_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        metadata_layout.addWidget(metadata_label)
        
        self.file_metadata_table = QTableWidget()
        self.file_metadata_table.setColumnCount(8)
        self.file_metadata_table.setHorizontalHeaderLabels([
            "Name", "Size", "Type", "Modified", "Accessed", "Created", "Path", "SHA-256"
        ])
        self.file_metadata_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.file_metadata_table.setAlternatingRowColors(True)
        self.file_metadata_table.setSortingEnabled(True)
        
        # Enable double-click to open files
        self.file_metadata_table.doubleClicked.connect(self._on_file_double_clicked)
        
        # Set column widths for metadata table
        header = self.file_metadata_table.horizontalHeader()
        header.resizeSection(0, 180)  # Name
        header.resizeSection(1, 80)   # Size
        header.resizeSection(2, 60)   # Type
        header.resizeSection(3, 140)  # Modified
        header.resizeSection(4, 140)  # Accessed
        header.resizeSection(5, 140)  # Created
        header.resizeSection(6, 200)  # Path
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)  # SHA-256
        
        metadata_layout.addWidget(self.file_metadata_table)
        
        fs_splitter.addWidget(metadata_container)
        
        # Set splitter proportions (40% tree | 60% table)
        fs_splitter.setSizes([400, 600])
        
        layout.addWidget(fs_splitter)
        
        return widget
    
    def _create_files_tab(self) -> Optional[QWidget]:
        """
        Create Files tab - Forensic File Explorer v2.
        
        Provides Windows "This PC" style interface for browsing
        evidence filesystems with tree view and file viewers.
        
        v2 Features:
        - Clickable forensic breadcrumb navigation
        - Enhanced status banner with evidence source
        - Evidence Identity Card panel
        - Color-coded file types
        - Terminal sync
        """
        try:
            # Use the original FilesTab that matches application style
            from .files_tab import FilesTab
            from ..core.virtual_fs import VirtualFilesystem
            
            # Get case ID from metadata
            case_id = None
            if self.case_metadata:
                case_id = self.case_metadata.get('case_id')
            
            # Determine VFS database path
            # First try case-specific vfs.db, then fall back to workspace
            if self.case_path:
                vfs_db_path = Path(self.case_path) / "vfs.db"
            else:
                vfs_db_path = Path("data/workspace/vfs.db")
            
            self.vfs = VirtualFilesystem(vfs_db_path)
            
            # If we have a case, try to populate VFS from existing files table
            if case_id:
                case_files_db = Path("data/indexes") / f"{case_id}.db"
                if case_files_db.exists():
                    self._populate_vfs_from_files_db(case_files_db)
            
            # Create CoC logger function
            def coc_logger(action: str, details: dict):
                if hasattr(self, 'chain_of_custody') and self.chain_of_custody:
                    self.chain_of_custody.log_action(action, details)
            
            # Create read file function that reads from physical paths stored in VFS metadata
            def read_file_func(path: str, offset: int, length: int) -> Optional[bytes]:
                try:
                    # Look up the VFS node to find the physical file path
                    node = self.vfs.get_node(path) if self.vfs else None
                    physical_path = None
                    if node and node.metadata:
                        physical_path = node.metadata.get('physical_path')
                    if physical_path and Path(physical_path).exists():
                        with open(physical_path, 'rb') as f:
                            f.seek(offset)
                            return f.read(length)
                except Exception:
                    pass
                return None
            
            # Create Files tab
            files_tab = FilesTab(
                vfs=self.vfs,
                read_file_func=read_file_func,
                coc_logger=coc_logger
            )
            
            self.files_tab_widget = files_tab
            
            # Wire VFS + read_file into the FEPD Terminal
            terminal = getattr(self, 'fepd_terminal', None)
            if terminal and hasattr(terminal, 'set_vfs'):
                terminal.set_vfs(self.vfs)
                terminal.set_read_file_func(read_file_func)
            
            return files_tab
            
        except Exception as e:
            logging.warning(f"Could not create Files tab: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _populate_vfs_from_files_db(self, files_db_path: Path):
        """
        Populate the VFS from an existing files database.
        
        Converts files from the FEPD index database (files table)
        to the VFS format for the Files tab.
        """
        import sqlite3
        from ..core.virtual_fs import VFSNodeType, VFSNode
        from datetime import datetime
        
        try:
            conn = sqlite3.connect(str(files_db_path))
            cur = conn.cursor()
            
            # Check if files table exists
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
            if not cur.fetchone():
                conn.close()
                return
            
            # Read files from the index database
            cur.execute("""
                SELECT path, origin, owner, size, created, modified, hash, ml_score
                FROM files
            """)
            
            nodes_to_add = []
            parent_paths_added = set()
            
            for row in cur.fetchall():
                path, origin, owner, size, created, modified, file_hash, ml_score = row
                if not path:
                    continue
                
                # Normalize path
                norm_path = '/' + path.replace('\\', '/')
                
                # Determine node type
                parts = [p for p in norm_path.split('/') if p]
                name = parts[-1] if parts else ''
                parent_path = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'
                
                # Create parent directories first
                for i in range(1, len(parts)):
                    p_path = '/' + '/'.join(parts[:i])
                    if p_path not in parent_paths_added:
                        p_parent = '/' + '/'.join(parts[:i-1]) if i > 1 else '/'
                        p_name = parts[i-1]
                        
                        # Determine parent node type
                        if p_name.lower() in ('users', 'home'):
                            p_type = VFSNodeType.FOLDER
                        elif p_parent.lower().endswith('/users') or p_parent.lower().endswith('/home'):
                            p_type = VFSNodeType.USER
                        else:
                            p_type = VFSNodeType.FOLDER
                        
                        parent_node = VFSNode(
                            id=0,
                            path=p_path,
                            name=p_name,
                            parent_path=p_parent,
                            node_type=p_type,
                            size=0
                        )
                        nodes_to_add.append(parent_node)
                        parent_paths_added.add(p_path)
                
                # Determine file node type
                node_type = VFSNodeType.FILE
                
                # Parse timestamps
                created_dt = None
                modified_dt = None
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created) if isinstance(created, str) else None
                    except Exception:
                        pass
                if modified:
                    try:
                        modified_dt = datetime.fromisoformat(modified) if isinstance(modified, str) else None
                    except Exception:
                        pass
                
                # Create file node
                file_node = VFSNode(
                    id=0,
                    path=norm_path,
                    name=name,
                    parent_path=parent_path,
                    node_type=node_type,
                    size=size or 0,
                    created=created_dt,
                    modified=modified_dt,
                    sha256=file_hash,
                    evidence_id=origin,
                    metadata={'owner': owner, 'ml_score': ml_score}
                )
                nodes_to_add.append(file_node)
            
            conn.close()
            
            # Add all nodes to VFS
            if nodes_to_add:
                added = self.vfs.add_nodes_batch(nodes_to_add)
                logging.info(f"Populated VFS with {added} nodes from {files_db_path}")
            
        except Exception as e:
            logging.warning(f"Could not populate VFS from files database: {e}")
            import traceback
            traceback.print_exc()
    
    def _populate_files_table_from_artifacts(self, case_id: str, extracted_artifacts: list):
        """
        Populate the files table in the case database from extracted artifacts.
        
        This enables the Files tab to display the extracted artifacts.
        
        Args:
            case_id: Case identifier
            extracted_artifacts: List of ExtractedArtifact objects from pipeline
        """
        import sqlite3
        from datetime import datetime
        import hashlib
        
        if not extracted_artifacts:
            logging.info("No extracted artifacts to populate files table")
            return
        
        case_files_db = Path("data/indexes") / f"{case_id}.db"
        if not case_files_db.exists():
            logging.warning(f"Case database not found: {case_files_db}")
            return
        
        try:
            conn = sqlite3.connect(str(case_files_db))
            cur = conn.cursor()
            
            # Ensure files table exists
            cur.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    path TEXT UNIQUE,
                    origin TEXT,
                    owner TEXT,
                    size INTEGER,
                    created TEXT,
                    modified TEXT,
                    hash TEXT,
                    ml_score REAL,
                    ml_explain TEXT
                )
            """)
            
            inserted_count = 0
            for artifact in extracted_artifacts:
                try:
                    # Build path based on artifact type and source
                    artifact_type = artifact.artifact_type.value if hasattr(artifact.artifact_type, 'value') else str(artifact.artifact_type)
                    
                    # Use original source path if available, else use extracted path
                    original_path = getattr(artifact, 'original_path', None) or getattr(artifact, 'source_path', None)
                    if original_path:
                        # Normalize path
                        norm_path = original_path.replace('\\', '/')
                        if not norm_path.startswith('/'):
                            norm_path = '/' + norm_path
                    else:
                        # Use artifact type as category
                        norm_path = f"/{artifact_type}/{artifact.extracted_path.name if hasattr(artifact.extracted_path, 'name') else Path(str(artifact.extracted_path)).name}"
                    
                    # Get file info
                    extracted_path = Path(str(artifact.extracted_path))
                    size = artifact.size_bytes if hasattr(artifact, 'size_bytes') else (extracted_path.stat().st_size if extracted_path.exists() else 0)
                    hash_val = artifact.sha256_hash if hasattr(artifact, 'sha256_hash') else None
                    modified = datetime.now().isoformat()
                    
                    # Insert into files table
                    cur.execute("""
                        INSERT OR REPLACE INTO files (path, origin, owner, size, created, modified, hash, ml_score)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (norm_path, artifact_type, None, size, modified, modified, hash_val, None))
                    
                    inserted_count += 1
                    
                except Exception as e:
                    logging.debug(f"Could not insert artifact: {e}")
            
            conn.commit()
            conn.close()
            logging.info(f"Populated files table with {inserted_count} artifacts for case {case_id}")
            
        except Exception as e:
            logging.warning(f"Could not populate files table: {e}")
            import traceback
            traceback.print_exc()
    
    def _populate_vfs_from_extracted_artifacts(self, extracted_artifacts: list):
        """
        Populate the VFS directly from extracted artifacts.
        
        This provides immediate display of extracted files in the Files tab
        without requiring the case database files table.
        
        Args:
            extracted_artifacts: List of ExtractedArtifact objects from pipeline
        """
        from ..core.virtual_fs import VFSNodeType, VFSNode
        from datetime import datetime
        
        if not extracted_artifacts or not hasattr(self, 'vfs') or not self.vfs:
            return
        
        try:
            nodes_to_add = []
            parent_paths_added = set()
            
            for artifact in extracted_artifacts:
                try:
                    # Get artifact info
                    artifact_type = artifact.artifact_type.value if hasattr(artifact.artifact_type, 'value') else str(artifact.artifact_type)
                    
                    # Use original source path if available
                    original_path = getattr(artifact, 'original_path', None) or getattr(artifact, 'source_path', None)
                    if original_path:
                        norm_path = original_path.replace('\\', '/')
                        if not norm_path.startswith('/'):
                            norm_path = '/' + norm_path
                    else:
                        # Use artifact type as category
                        file_name = artifact.extracted_path.name if hasattr(artifact.extracted_path, 'name') else Path(str(artifact.extracted_path)).name
                        norm_path = f"/Evidence/{artifact_type}/{file_name}"
                    
                    # Parse path
                    parts = [p for p in norm_path.split('/') if p]
                    name = parts[-1] if parts else ''
                    parent_path = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'
                    
                    # Create parent directories
                    for i in range(1, len(parts)):
                        p_path = '/' + '/'.join(parts[:i])
                        if p_path not in parent_paths_added:
                            p_parent = '/' + '/'.join(parts[:i-1]) if i > 1 else '/'
                            p_name = parts[i-1]
                            
                            parent_node = VFSNode(
                                id=0,
                                path=p_path,
                                name=p_name,
                                parent_path=p_parent,
                                node_type=VFSNodeType.FOLDER,
                                size=0
                            )
                            nodes_to_add.append(parent_node)
                            parent_paths_added.add(p_path)
                    
                    # Create file node
                    extracted_path = Path(str(artifact.extracted_path))
                    size = artifact.size_bytes if hasattr(artifact, 'size_bytes') else (extracted_path.stat().st_size if extracted_path.exists() else 0)
                    hash_val = artifact.sha256_hash if hasattr(artifact, 'sha256_hash') else None
                    
                    file_node = VFSNode(
                        id=0,
                        path=norm_path,
                        name=name,
                        parent_path=parent_path,
                        node_type=VFSNodeType.FILE,
                        size=size,
                        sha256=hash_val,
                        evidence_id=artifact_type,
                        metadata={
                            'artifact_type': artifact_type,
                            'physical_path': str(extracted_path.absolute())
                        }
                    )
                    nodes_to_add.append(file_node)
                    
                except Exception as e:
                    logging.debug(f"Could not create VFS node for artifact: {e}")
            
            # Add all nodes to VFS
            if nodes_to_add:
                added = self.vfs.add_nodes_batch(nodes_to_add)
                logging.info(f"Populated VFS with {added} nodes from extracted artifacts")
                
        except Exception as e:
            logging.warning(f"Could not populate VFS from extracted artifacts: {e}")
            import traceback
            traceback.print_exc()
    
    def _ensure_vfs_parents(self, path: str):
        """Ensure all parent directories exist in VFS."""
        pass  # Handled in _populate_vfs_from_files_db now
    
    def _auto_load_configuration_hives(self, case_path: Path):
        """
        Auto-detect and load registry hives into Configuration tab.
        
        Searches the case's artifacts/registry and extracted_data directories
        for SYSTEM and SOFTWARE hive files.
        """
        try:
            if not hasattr(self, 'configuration_tab') or not self.configuration_tab:
                return

            system_hive = None
            software_hive = None

            # Search paths where hives might be extracted
            search_dirs = [
                Path(case_path) / "artifacts" / "registry",
                Path(case_path) / "extracted_data",
            ]

            # Also search recursively in extracted_data partitions
            extracted_dir = Path(case_path) / "extracted_data"
            if extracted_dir.exists():
                for p_dir in extracted_dir.rglob("*"):
                    if p_dir.is_dir() and p_dir.name.lower() in ('config', 'system32', 'system32/config'):
                        search_dirs.append(p_dir)
                # Also add partition subdirectories
                for part_dir in extracted_dir.iterdir():
                    if part_dir.is_dir():
                        config_dir = part_dir / "Windows" / "System32" / "config"
                        if config_dir.exists():
                            search_dirs.append(config_dir)

            for search_dir in search_dirs:
                if not search_dir.exists():
                    continue
                for f in search_dir.iterdir():
                    if not f.is_file():
                        continue
                    name_lower = f.name.lower()
                    if name_lower == 'system' or name_lower.startswith('system.') and 'log' not in name_lower:
                        if not system_hive:
                            system_hive = f
                    elif name_lower == 'software' or name_lower.startswith('software.') and 'log' not in name_lower:
                        if not software_hive:
                            software_hive = f

            if system_hive or software_hive:
                self.configuration_tab.load_hives(
                    system_hive=system_hive,
                    software_hive=software_hive
                )
                self.logger.info(f"Auto-loaded configuration hives: SYSTEM={system_hive}, SOFTWARE={software_hive}")
            else:
                self.logger.info("No registry hives found for auto-loading into Configuration tab")
        except Exception as e:
            self.logger.warning(f"Could not auto-load configuration hives: {e}")

    def _refresh_artifacts_tab(self, case_path: Path):
        """
        Refresh the enhanced Artifacts tab with artifacts from the case workspace.
        
        Scans the case artifacts directory and feeds found artifacts into the
        enhanced ArtifactsTab via its _on_artifact_found method.
        """
        try:
            enhanced_tab = getattr(self, '_enhanced_artifacts_tab', None)
            if not enhanced_tab:
                return

            case_info = {
                'case_id': self.current_case,
                'path': str(case_path),
            }
            if hasattr(enhanced_tab, 'set_case'):
                enhanced_tab.set_case(case_info)
                return

            artifacts_dir = Path(case_path) / "artifacts"
            if not artifacts_dir.exists():
                return

            from datetime import datetime

            artifact_type_map = {
                'registry': 'Registry',
                'evtx': 'Event Log',
                'prefetch': 'Prefetch',
                'mft': 'File System',
                'browser': 'Browser',
                'lnk': 'Link File',
                'linux_config': 'Linux Config',
                'linux_log': 'Linux Log',
                'script': 'Script',
                'binary': 'Binary',
                'other': 'Other',
            }

            count = 0
            for type_dir in artifacts_dir.iterdir():
                if not type_dir.is_dir():
                    continue

                atype = artifact_type_map.get(type_dir.name, type_dir.name.replace('_', ' ').title())

                for artifact_file in type_dir.iterdir():
                    if not artifact_file.is_file():
                        continue

                    try:
                        stat_info = artifact_file.stat()
                        modified_dt = datetime.fromtimestamp(stat_info.st_mtime)
                        file_size = stat_info.st_size
                    except Exception:
                        modified_dt = None
                        file_size = 0

                    artifact_dict = {
                        'type': atype,
                        'subtype': type_dir.name,
                        'name': artifact_file.name,
                        'path': str(artifact_file),
                        'description': f'{atype} artifact: {artifact_file.name}',
                        'timestamp': modified_dt,
                        'evidence_id': self.current_case or 'evidence',
                        'hash': '',
                        'metadata': {
                            'size': file_size,
                            'physical_path': str(artifact_file.absolute())
                        }
                    }
                    enhanced_tab._on_artifact_found(artifact_dict)
                    count += 1

            if count > 0:
                self.logger.info(f"Loaded {count} artifacts into enhanced Artifacts tab")
        except Exception as e:
            self.logger.warning(f"Could not refresh enhanced Artifacts tab: {e}")

    def _clear_dynamic_insights_tabs(self):
        """Remove previously rendered dynamic sections before fresh hydration."""
        tabs = getattr(self, 'dynamic_insights_tabs', None)
        if tabs is None:
            return
        while tabs.count() > 0:
            widget = tabs.widget(0)
            tabs.removeTab(0)
            if widget is not None:
                widget.deleteLater()

    def _timeline_df_from_section_events(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """Convert routed timeline section events into Timeline/ML-compatible dataframe."""
        normalized = []
        for ev in events:
            if not isinstance(ev, dict):
                continue

            ts = ev.get('time') or ev.get('timestamp') or ""
            src = str(ev.get('event_type') or ev.get('operation') or 'artifact').upper()
            activity = str(ev.get('activity') or ev.get('event_type') or 'event')
            path = str(ev.get('path') or '')

            normalized.append({
                'ts_utc': ts,
                'ts_local': ts,
                'artifact_source': src,
                'event_type': activity,
                'description': f"{activity} | {path}" if path else activity,
                'rule_class': 'NORMAL',
                'severity': 2,
                'user_account': str(ev.get('user') or ''),
                'operation': str(ev.get('operation') or activity),
                'pid': int(ev.get('pid') or 0),
                'ppid': int(ev.get('ppid') or 0),
                'exe_name': str(ev.get('program') or ''),
                'filepath': path,
            })

        if not normalized:
            return pd.DataFrame()

        return pd.DataFrame(normalized)

    def _handle_timeline_section(self, fields: Dict[str, Any]) -> None:
        """Route activity timeline section into timeline/ML/visualization tabs."""
        events = fields.get('events', []) if isinstance(fields, dict) else []
        if not isinstance(events, list):
            events = []
        df = self._timeline_df_from_section_events(events)
        if df.empty:
            return

        if hasattr(self, 'timeline_tab') and hasattr(self.timeline_tab, 'load_events'):
            self.timeline_tab.load_events(df)
        elif hasattr(self, 'timeline_table'):
            self._populate_timeline_table(df)

        if hasattr(self, 'ml_analytics_tab') and hasattr(self.ml_analytics_tab, 'load_events'):
            self.ml_analytics_tab.load_events(df, auto_analyze=False)

        if hasattr(self, 'visualizations_tab') and hasattr(self.visualizations_tab, 'load_events'):
            self.visualizations_tab.load_events(df)

        enhanced_tab = getattr(self, '_enhanced_artifacts_tab', None)
        if enhanced_tab and hasattr(enhanced_tab, 'load_events_for_correlation'):
            enhanced_tab.load_events_for_correlation(df)

    def _handle_top_findings_section(self, fields: Dict[str, Any]) -> None:
        findings = fields.get('findings', []) if isinstance(fields, dict) else []
        if not isinstance(findings, list):
            findings = []
        if hasattr(self, 'ml_analytics_tab') and hasattr(self.ml_analytics_tab, 'apply_top_findings'):
            self.ml_analytics_tab.apply_top_findings(findings)

    def _handle_threat_intel_section(self, fields: Dict[str, Any]) -> None:
        indicators = fields.get('indicators', []) if isinstance(fields, dict) else []
        if not isinstance(indicators, list):
            indicators = []
        if hasattr(self, 'ml_analytics_tab') and hasattr(self.ml_analytics_tab, 'apply_threat_indicators'):
            self.ml_analytics_tab.apply_threat_indicators(indicators)

    def _handle_anomaly_section(self, fields: Dict[str, Any]) -> None:
        anomalies = fields.get('anomalies', []) if isinstance(fields, dict) else []
        if not isinstance(anomalies, list):
            anomalies = []
        if hasattr(self, 'ml_analytics_tab') and hasattr(self.ml_analytics_tab, 'apply_anomaly_findings'):
            self.ml_analytics_tab.apply_anomaly_findings(anomalies)

    def _handle_ueba_section(self, fields: Dict[str, Any]) -> None:
        profiles = fields.get('profiles', []) if isinstance(fields, dict) else []
        if not isinstance(profiles, list):
            profiles = []
        if hasattr(self, 'ml_analytics_tab') and hasattr(self.ml_analytics_tab, 'apply_ueba_profiles'):
            self.ml_analytics_tab.apply_ueba_profiles(profiles)

    def _handle_network_intrusion_section(self, fields: Dict[str, Any]) -> None:
        events = fields.get('events', []) if isinstance(fields, dict) else []
        if not isinstance(events, list):
            events = []
        if hasattr(self, 'ml_analytics_tab') and hasattr(self.ml_analytics_tab, 'apply_network_intrusion_events'):
            self.ml_analytics_tab.apply_network_intrusion_events(events)

    def _handle_config_system_section(self, fields: Dict[str, Any]) -> None:
        if hasattr(self, 'configuration_tab') and hasattr(self.configuration_tab, 'apply_forensic_section'):
            self.configuration_tab.apply_forensic_section('System Information', fields)

    def _handle_config_hardware_section(self, fields: Dict[str, Any]) -> None:
        if hasattr(self, 'configuration_tab') and hasattr(self.configuration_tab, 'apply_forensic_section'):
            self.configuration_tab.apply_forensic_section('Hardware Information', fields)

    def _handle_config_network_section(self, fields: Dict[str, Any]) -> None:
        if hasattr(self, 'configuration_tab') and hasattr(self.configuration_tab, 'apply_forensic_section'):
            self.configuration_tab.apply_forensic_section('Network Configuration', fields)

    def _handle_config_software_section(self, fields: Dict[str, Any]) -> None:
        if hasattr(self, 'configuration_tab') and hasattr(self.configuration_tab, 'apply_forensic_section'):
            self.configuration_tab.apply_forensic_section('Installed Software', fields)

    def _handle_config_services_section(self, fields: Dict[str, Any]) -> None:
        if hasattr(self, 'configuration_tab') and hasattr(self.configuration_tab, 'apply_forensic_section'):
            self.configuration_tab.apply_forensic_section('Services', fields)

    def _handle_config_security_section(self, fields: Dict[str, Any]) -> None:
        if hasattr(self, 'configuration_tab') and hasattr(self.configuration_tab, 'apply_forensic_section'):
            self.configuration_tab.apply_forensic_section('Security Configuration', fields)

    def _sync_files_tab_from_unified_store(self, store: UnifiedForensicStore) -> None:
        """Populate VFS from ui_files to keep Files tab aligned with normalized backend."""
        if not hasattr(self, 'vfs') or not self.vfs:
            return

        from ..core.virtual_fs import VFSNodeType, VFSNode

        rows = store.query_files(limit=200000, offset=0)
        if not rows:
            return

        self.vfs.clear_all()
        nodes_to_add = []
        parent_paths_added = set()

        for row in rows:
            raw_path = str(row.get('path') or '').strip()
            if not raw_path:
                continue

            physical_path = Path(raw_path)
            try:
                rel = physical_path.relative_to(store.case_path)
                vfs_path = "/Evidence/" + str(rel).replace('\\', '/')
            except Exception:
                vfs_path = "/Evidence/" + physical_path.name

            parts = [p for p in vfs_path.split('/') if p]
            if not parts:
                continue

            name = parts[-1]
            parent_path = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'

            for i in range(1, len(parts)):
                p_path = '/' + '/'.join(parts[:i])
                if p_path in parent_paths_added:
                    continue
                p_parent = '/' + '/'.join(parts[:i - 1]) if i > 1 else '/'
                p_name = parts[i - 1]
                nodes_to_add.append(
                    VFSNode(
                        id=0,
                        path=p_path,
                        name=p_name,
                        parent_path=p_parent,
                        node_type=VFSNodeType.FOLDER,
                        size=0,
                    )
                )
                parent_paths_added.add(p_path)

            nodes_to_add.append(
                VFSNode(
                    id=0,
                    path=vfs_path,
                    name=name,
                    parent_path=parent_path,
                    node_type=VFSNodeType.FILE,
                    size=int(row.get('size') or 0),
                    sha256=row.get('sha256') or None,
                    evidence_id=row.get('source') or 'Filesystem',
                    metadata={
                        'owner': row.get('owner') or '',
                        'physical_path': raw_path,
                        'extension': row.get('extension') or '',
                    },
                )
            )

        if nodes_to_add:
            self.vfs.add_nodes_batch(nodes_to_add)
            if hasattr(self, 'files_tab_widget') and self.files_tab_widget and hasattr(self.files_tab_widget, 'refresh'):
                self.files_tab_widget.refresh()

    def _hydrate_tabs_from_unified_store(
        self,
        case_path: Path,
        include_timeline: bool = True,
        rebuild_index: bool = True,
    ) -> None:
        """Hydrate tab payloads from normalized store and strict section routing."""
        try:
            case_path = Path(case_path)
            if not case_path.exists():
                return

            store = UnifiedForensicStore(case_path)
            stats = store.rebuild_case_index() if rebuild_index else {'files': 0, 'artifacts': 0}
            engine = ForensicTabExtractionEngine(store)

            self._sync_files_tab_from_unified_store(store)

            handlers = {
                'Activity Timeline': self._handle_timeline_section,
                'Top Findings': self._handle_top_findings_section,
                'Anomaly Detection': self._handle_anomaly_section,
                'UEBA Profiling': self._handle_ueba_section,
                'Network Intrusion': self._handle_network_intrusion_section,
                'Threat Intelligence': self._handle_threat_intel_section,
                'System Information': self._handle_config_system_section,
                'Hardware Information': self._handle_config_hardware_section,
                'Network Configuration': self._handle_config_network_section,
                'Installed Software': self._handle_config_software_section,
                'Services': self._handle_config_services_section,
                'Security Configuration': self._handle_config_security_section,
            }
            if not include_timeline:
                handlers.pop('Activity Timeline', None)

            sections = list(TAB_FIELDS.keys())
            if not include_timeline:
                sections = [s for s in sections if s != 'Activity Timeline']

            for section in sections:
                payload = validate_or_coerce_response(engine.extract_section(section))
                route_to_tab(payload, handlers)

            self.logger.info(
                "Hydrated forensic sections for %s (%s files, %s artifacts)",
                case_path.name,
                stats.get('files', 0),
                stats.get('artifacts', 0),
            )
        except Exception as exc:
            self.logger.warning("Unified forensic hydration failed: %s", exc)
    
    def _setup_files_terminal_sync(self):
        """
        Set up bidirectional sync between Files Tab and FEPD Terminal.
        
        Files Tab → Terminal: When navigating files, terminal pwd changes
        Terminal → Files Tab: When cd command is used, files tab navigates
        """
        try:
            # Check if both widgets exist
            files_tab = getattr(self, 'files_tab_widget', None)
            terminal = getattr(self, 'fepd_terminal', None)
            
            if not files_tab or not terminal:
                return
            
            # Files Tab → Terminal sync
            # When path changes in Files tab, emit to terminal
            if hasattr(files_tab, 'path_changed'):
                files_tab.path_changed.connect(
                    lambda path: self._on_files_path_changed(path)
                )
            
            # When user context changes, update terminal prompt
            if hasattr(files_tab, 'user_context_changed'):
                files_tab.user_context_changed.connect(
                    lambda user: self._on_user_context_changed(user)
                )
            
            # When Files tab wants to execute a command
            if hasattr(files_tab, 'terminal_command'):
                files_tab.terminal_command.connect(
                    lambda cmd: self._execute_terminal_command(cmd)
                )
            
            # Terminal → Files Tab sync
            # When terminal cd's, sync files tab
            if hasattr(terminal, 'path_changed'):
                terminal.path_changed.connect(
                    lambda path: self._on_terminal_path_changed(path)
                )
            
            logging.info("Files Tab ↔ Terminal sync established")
            
        except Exception as e:
            logging.warning(f"Could not set up files-terminal sync: {e}")

    def _sync_ingest_tab_case(self, case_metadata: Dict[str, Any]) -> None:
        """Bind the active case to Image Ingest tab so persisted evidence repopulates on open."""
        try:
            ingest_tab = getattr(self, '_enhanced_ingest_tab', None)
            if ingest_tab and hasattr(ingest_tab, 'set_case'):
                sync_payload = dict(case_metadata or {})
                if not sync_payload.get('path'):
                    case_path = getattr(self, 'case_path', None) or getattr(self, 'case_workspace', None)
                    if case_path:
                        sync_payload['path'] = str(case_path)
                ingest_tab.set_case(sync_payload)
        except Exception as exc:
            self.logger.warning("Could not sync ingest tab to current case: %s", exc)

    def _sync_all_tabs_case_context(self, case_metadata: Dict[str, Any], case_path: Path) -> None:
        """Push active case context into all user-facing tabs."""
        try:
            # Recreate Case Details tab for the active case to avoid stale metadata.
            if hasattr(self, 'tabs'):
                for i in range(self.tabs.count() - 1, -1, -1):
                    if "case details" in self.tabs.tabText(i).lower():
                        old_widget = self.tabs.widget(i)
                        self.tabs.removeTab(i)
                        if old_widget is not None:
                            old_widget.deleteLater()
                from .tabs.case_details_tab import CaseDetailsTab
                self.case_details_tab = CaseDetailsTab(case_metadata, case_path)
                self.tabs.insertTab(0, self.case_details_tab, "📋 Case Details")

            # Hidden ingest tab still needs case state for backend workflows.
            ingest_case_payload = dict(case_metadata or {})
            ingest_case_payload.setdefault('path', str(case_path))
            self._sync_ingest_tab_case(ingest_case_payload)

            # ML tab context
            if hasattr(self, 'ml_analytics_tab') and self.ml_analytics_tab:
                workspace_root = case_path.parent.parent
                self.ml_analytics_tab.set_case_context(
                    case_path,
                    data_source_path=workspace_root / "dataa",
                    models_dir=workspace_root / "models"
                )

            # Chatbot context
            if hasattr(self, 'chatbot_tab') and self.chatbot_tab:
                self.chatbot_tab.set_case_context(case_path, case_metadata)

            # Report tab context
            if hasattr(self, 'report_tab') and self.report_tab and hasattr(self.report_tab, 'set_case_context'):
                self.report_tab.set_case_context(case_path, case_metadata)
        except Exception as exc:
            self.logger.warning("Could not sync all tabs case context: %s", exc)
    
    def _on_files_path_changed(self, path: str):
        """Handle path change from Files tab."""
        terminal = getattr(self, 'fepd_terminal', None)
        if terminal and hasattr(terminal, 'set_current_path'):
            terminal.set_current_path(path)
    
    def _on_user_context_changed(self, user: str):
        """Handle user context change from Files tab."""
        terminal = getattr(self, 'fepd_terminal', None)
        if terminal and hasattr(terminal, 'set_user_context'):
            terminal.set_user_context(user)
    
    def _execute_terminal_command(self, command: str):
        """Execute command in terminal from Files tab."""
        terminal = getattr(self, 'fepd_terminal', None)
        if terminal and hasattr(terminal, 'execute_command'):
            terminal.execute_command(command)
    
    def _on_terminal_path_changed(self, path: str):
        """Handle path change from Terminal."""
        files_tab = getattr(self, 'files_tab_widget', None)
        if files_tab and hasattr(files_tab, 'sync_from_terminal'):
            files_tab.sync_from_terminal(path)
    
    def _create_artifacts_tab(self) -> QWidget:
        """Create Artifacts Discovery tab — Enhanced with real forensic artifact categories."""
        try:
            from .tabs.artifacts_tab_enhanced import ArtifactsTab
            from ..core.case_manager import CaseManager

            case_mgr = CaseManager(base_cases_dir=str(
                Path(self.case_path).parent if self.case_path else "cases"
            ))
            if self.case_metadata and self.case_path:
                case_mgr.current_case = self.case_metadata
                case_mgr.case_path = Path(self.case_path)

            tab = ArtifactsTab(case_manager=case_mgr)
            self._enhanced_artifacts_tab = tab
            self.logger.info("Enhanced Artifacts tab loaded (8 categories)")
            return tab
        except Exception as exc:
            self.logger.warning("Enhanced Artifacts tab unavailable, using fallback: %s", exc)
            import traceback; traceback.print_exc()

        # ── Fallback ──
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        from PyQt6.QtWidgets import QLabel, QTableWidget
        
        label = QLabel("🔍 Discovered Artifacts")
        layout.addWidget(label)
        
        # Placeholder table
        self.artifacts_table = QTableWidget(0, 5)
        self.artifacts_table.setHorizontalHeaderLabels([
            "Type", "Path", "Size", "Hash (SHA-256)", "Status"
        ])
        layout.addWidget(self.artifacts_table)
        
        return widget
    
    def _create_timeline_tab(self) -> QWidget:
        """Create Timeline Visualization tab — Enhanced with event intelligence."""
        try:
            from .tabs.timeline_tab import TimelineTab

            tab = TimelineTab()
            self._enhanced_timeline_tab = tab
            self.logger.info("Enhanced Timeline tab loaded (event intelligence)")
            return tab
        except Exception as exc:
            self.logger.warning("Enhanced Timeline tab unavailable, using fallback: %s", exc)
            import traceback; traceback.print_exc()

        # ── Fallback ──
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        from PyQt6.QtWidgets import QLabel, QTableWidget
        
        label = QLabel("📊 Forensic Timeline (Vertical View)")
        layout.addWidget(label)
        
        # Create timeline table with columns
        self.timeline_table = QTableWidget(0, 5)
        self.timeline_table.setHorizontalHeaderLabels([
            "Timestamp", "Artifact Type", "Event Type", "Description", "Classification"
        ])
        self.timeline_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.timeline_table)
        
        return widget
    
    def _create_report_tab(self) -> QWidget:
        """Create Report Generation tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        from PyQt6.QtWidgets import QLabel, QPushButton
        
        label = QLabel("📄 Final Report Generation")
        layout.addWidget(label)
        
        btn_generate = QPushButton("Generate PDF Report")
        btn_generate.clicked.connect(self._generate_report)
        layout.addWidget(btn_generate)
        
        layout.addStretch()
        
        return widget
    
    def _apply_theme(self):
        """Apply Dark Indigo theme stylesheet."""
        theme_path = Path(__file__).parent.parent.parent / "resources" / "styles" / "dark_indigo.qss"
        
        if theme_path.exists():
            try:
                with open(theme_path, 'r', encoding='utf-8') as f:
                    stylesheet = f.read()
                self.setStyleSheet(stylesheet)
                self.logger.info("Dark Indigo theme applied")
            except Exception as e:
                self.logger.warning(f"Failed to load theme: {e}")
        else:
            self.logger.warning(f"Theme file not found: {theme_path}")
    
    def _convert_to_evidence_path(self, internal_path: str) -> str:
        """
        Convert internal VFS path to Windows-style evidence display path.
        
        CRITICAL: This ensures the UI NEVER exposes analyzer workspace paths.
        Only evidence-native paths (C:\\Users\\John\\...) should be visible.
        
        Examples:
            /This PC/C:/Users/John/Desktop/file.txt -> C:\\Users\\John\\Desktop\\file.txt
            /This PC/Local Disk (C:)/Users/John -> C:\\Users\\John
            /This PC/D:/Data -> D:\\Data
            /Evidence/EVTX/file.evtx -> [BLOCKED: Workspace path]
            cases/case-122/... -> [BLOCKED: Workspace path]
        """
        if not internal_path:
            return ""
        
        # Block analyzer workspace paths - these should NEVER be shown
        blocked_patterns = [
            'cases/', '/cases/', 'Evidence/', '/Evidence/',
            'extracted_data/', 'temp/', 'workspace/', 'analyzer/',
            'carved_files/'
        ]
        
        path_str = str(internal_path)
        path_lower = path_str.lower()
        
        for pattern in blocked_patterns:
            if pattern.lower() in path_lower:
                # This is a workspace path - convert to evidence-native if possible
                self.logger.warning(f"Blocking workspace path from UI: {path_str[:50]}...")
                return "[Evidence Path]"
        
        # Convert VFS internal path to Windows display path
        parts = path_str.strip('/').split('/')
        
        if parts and parts[0] == 'This PC' and len(parts) > 1:
            # /This PC/C:/Users/John -> C:\\Users\\John
            # /This PC/Local Disk (C:)/Users -> C:\\Users
            drive_part = parts[1]
            
            # Extract drive letter from various formats
            if ':' in drive_part:
                # Direct drive letter: "C:" or "Local Disk (C:)"
                if '(' in drive_part and ')' in drive_part:
                    # "Local Disk (C:)" -> "C:"
                    drive_letter = drive_part[drive_part.index('(')+1:drive_part.index(')')]
                else:
                    drive_letter = drive_part
                
                # Build Windows path
                if len(parts) > 2:
                    return drive_letter + "\\" + "\\".join(parts[2:])
                else:
                    return drive_letter + "\\"
            else:
                # Non-drive partition (Recovery, EFI, etc.) - show as-is
                return "\\".join(parts[1:])
        
        # Check if path looks like a Windows path already
        if len(parts) >= 1 and len(parts[0]) == 2 and parts[0][1] == ':':
            # Already in C:/Users/... format
            return "\\".join(parts)
        
        # Fallback: convert forward slashes to backslashes
        return path_str.replace('/', '\\')
    
    def _get_evidence_path_from_extracted(self, extracted_path) -> str:
        """
        Convert extracted artifact directory path to evidence-native display path.
        
        Takes paths like:
            cases/case-122/extracted_data/partition_0/Windows/System32
            c:\\Users\\darsh\\cases\\csae-122-11\\extracted_data\\partition_1\\Users
        
        Returns:
            C:\\Windows\\System32
            C:\\Users
            
        This reconstructs the original evidence path from the extraction directory.
        """
        path_str = str(extracted_path)
        
        # Normalize path separators
        path_str = path_str.replace('\\', '/')
        
        # Find partition marker and extract path after it
        # Pattern: .../partition_N/actual/path/...
        import re
        
        # Match partition_0, partition_1, etc.
        partition_match = re.search(r'/partition_(\d+)/(.+)$', path_str)
        if partition_match:
            partition_num = int(partition_match.group(1))
            relative_path = partition_match.group(2)
            
            # Map partition number to drive letter (0 -> C:, 1 -> D:, etc.)
            # In most cases, partition 0 is EFI, 1 is Recovery, 2+ is main OS
            # But we'll use a simple mapping for now
            drive_letter = chr(ord('C') + partition_num)
            
            # Build Windows path
            windows_path = f"{drive_letter}:\\{relative_path}".replace('/', '\\')
            return windows_path
        
        # Alternative: extract_data folder patterns
        extract_match = re.search(r'/extracted_data/(.+)$', path_str)
        if extract_match:
            relative_path = extract_match.group(1)
            # Default to C: if no partition info
            windows_path = f"C:\\{relative_path}".replace('/', '\\')
            return windows_path
        
        # If no recognized pattern, return sanitized version
        # Strip common workspace prefixes
        for prefix in ['cases/', 'data/', 'workspace/', 'temp/']:
            if prefix in path_str.lower():
                idx = path_str.lower().find(prefix)
                # Find the case folder end
                after_prefix = path_str[idx + len(prefix):]
                # Skip case name folder
                if '/' in after_prefix:
                    after_case = '/'.join(after_prefix.split('/')[1:])
                    return f"C:\\{after_case}".replace('/', '\\')
        
        # Last resort: just return the folder name
        return Path(path_str).name
    
    def _build_artifact_categories(self, base_path: str, children) -> dict:
        """
        Organize VFS children into forensic artifact categories.
        
        Returns a dictionary of categories with their artifacts:
        {
            'Registry': {'icon': '🔑', 'items': [...]},
            'Event Logs': {'icon': '📋', 'items': [...]},
            ...
        }
        """
        # Define forensic artifact categories with their detection patterns
        ARTIFACT_PATTERNS = {
            'Registry': {
                'icon': '🔑',
                'paths': ['windows/system32/config', 'users/*/ntuser.dat', 'users/*/usrclass.dat'],
                'extensions': ['.dat'],
                'names': ['sam', 'system', 'software', 'security', 'ntuser', 'usrclass', 'default']
            },
            'Event Logs': {
                'icon': '📋',
                'paths': ['windows/system32/winevt/logs'],
                'extensions': ['.evtx', '.evt'],
                'names': []
            },
            'Prefetch': {
                'icon': '⚡',
                'paths': ['windows/prefetch'],
                'extensions': ['.pf'],
                'names': []
            },
            'Browser Data': {
                'icon': '🌐',
                'paths': ['users/*/appdata/local/google/chrome', 'users/*/appdata/local/microsoft/edge',
                          'users/*/appdata/roaming/mozilla/firefox'],
                'extensions': ['.sqlite', '.db'],
                'names': ['history', 'cookies', 'places', 'logins', 'bookmarks']
            },
            'User Documents': {
                'icon': '📄',
                'paths': ['users/*/documents', 'users/*/desktop', 'users/*/downloads'],
                'extensions': ['.docx', '.xlsx', '.pdf', '.txt', '.pptx'],
                'names': []
            },
            'Recent Files': {
                'icon': '🕐',
                'paths': ['users/*/appdata/roaming/microsoft/windows/recent'],
                'extensions': ['.lnk'],
                'names': []
            },
            'Startup Items': {
                'icon': '🚀',
                'paths': ['users/*/appdata/roaming/microsoft/windows/start menu/programs/startup',
                          'programdata/microsoft/windows/start menu/programs/startup'],
                'extensions': ['.lnk', '.exe', '.bat'],
                'names': []
            },
            'Recycle Bin': {
                'icon': '🗑️',
                'paths': ['$recycle.bin'],
                'extensions': [],
                'names': ['$i', '$r']
            },
            'System Files': {
                'icon': '⚙️',
                'paths': ['windows/system32'],
                'extensions': ['.dll', '.exe', '.sys'],
                'names': []
            },
            'MFT & NTFS': {
                'icon': '💾',
                'paths': [],
                'extensions': [],
                'names': ['$mft', '$logfile', '$usnjrnl', '$bitmap']
            },
            'Scheduled Tasks': {
                'icon': '📅',
                'paths': ['windows/system32/tasks', 'windows/tasks'],
                'extensions': ['.job', '.xml'],
                'names': []
            },
            'Email & Outlook': {
                'icon': '📧',
                'paths': ['users/*/appdata/local/microsoft/outlook'],
                'extensions': ['.pst', '.ost', '.eml', '.msg'],
                'names': []
            }
        }
        
        categories = {name: {'icon': data['icon'], 'items': []} for name, data in ARTIFACT_PATTERNS.items()}
        categories['Other Files'] = {'icon': '📁', 'items': []}
        
        def match_artifact(node) -> str:
            """Determine which category a node belongs to."""
            if not node:
                return 'Other Files'
            
            name = (getattr(node, 'name', '') or '').lower()
            path = (getattr(node, 'path', '') or '').lower()
            is_dir = getattr(node, 'is_directory', False)
            
            # Check each category
            for cat_name, patterns in ARTIFACT_PATTERNS.items():
                # Check path patterns
                for pattern in patterns.get('paths', []):
                    pattern_lower = pattern.lower().replace('*', '')
                    if pattern_lower in path:
                        return cat_name
                
                # Check extensions
                for ext in patterns.get('extensions', []):
                    if name.endswith(ext.lower()):
                        return cat_name
                
                # Check names
                for match_name in patterns.get('names', []):
                    if match_name.lower() in name:
                        return cat_name
            
            return 'Other Files'
        
        # Categorize all children
        for child in children or []:
            if not child:
                continue
            
            try:
                category = match_artifact(child)
                
                # Build artifact info
                artifact_info = {
                    'name': getattr(child, 'name', 'Unknown') or 'Unknown',
                    'path': getattr(child, 'path', '') or '',
                    'size': getattr(child, 'size', 0) or 0,
                    'is_dir': getattr(child, 'is_directory', False),
                    'type': 'file',
                    'mtime': None,
                    'atime': None,
                    'ctime': None,
                }
                
                # Get timestamps if available
                if hasattr(child, 'modified') and child.modified:
                    try:
                        artifact_info['mtime'] = child.modified.timestamp()
                    except Exception:
                        pass
                if hasattr(child, 'accessed') and child.accessed:
                    try:
                        artifact_info['atime'] = child.accessed.timestamp()
                    except Exception:
                        pass
                if hasattr(child, 'created') and child.created:
                    try:
                        artifact_info['ctime'] = child.created.timestamp()
                    except Exception:
                        pass
                
                categories[category]['items'].append(artifact_info)
                
            except Exception:
                continue
        
        # Also scan subdirectories for artifacts (1 level deep)
        for child in children or []:
            if not child or not getattr(child, 'is_directory', False):
                continue
            
            child_path = getattr(child, 'path', '')
            if not child_path:
                continue
            
            try:
                subchildren = self.vfs.get_children(child_path) if hasattr(self, 'vfs') and self.vfs else []
                for subchild in (subchildren or [])[:100]:  # Limit per subdirectory
                    if not subchild:
                        continue
                    
                    category = match_artifact(subchild)
                    if category != 'Other Files':  # Only add specific artifacts from subdirs
                        artifact_info = {
                            'name': getattr(subchild, 'name', 'Unknown') or 'Unknown',
                            'path': getattr(subchild, 'path', '') or '',
                            'size': getattr(subchild, 'size', 0) or 0,
                            'is_dir': getattr(subchild, 'is_directory', False),
                            'type': 'file',
                            'mtime': None,
                            'ctime': None,
                        }
                        if hasattr(subchild, 'modified') and subchild.modified:
                            try:
                                artifact_info['mtime'] = subchild.modified.timestamp()
                            except Exception:
                                pass
                        categories[category]['items'].append(artifact_info)
            except Exception:
                continue
        
        # Remove empty categories - keep any that have items
        result = {}
        for name, data in categories.items():
            if data['items']:
                result[name] = data
        
        # Always include "Other Files" if there are any children not categorized elsewhere
        # or if there are children but no specific artifacts found
        if not result and children:
            # All files went to "Other Files" or no categorization worked
            # Create a general "Files" category from all children
            all_files = []
            for child in children or []:
                if not child:
                    continue
                artifact_info = {
                    'name': getattr(child, 'name', 'Unknown') or 'Unknown',
                    'path': getattr(child, 'path', '') or '',
                    'size': getattr(child, 'size', 0) or 0,
                    'is_dir': getattr(child, 'is_directory', False),
                    'type': 'directory' if getattr(child, 'is_directory', False) else 'file',
                    'mtime': None,
                    'ctime': None,
                }
                if hasattr(child, 'modified') and child.modified:
                    try:
                        artifact_info['mtime'] = child.modified.timestamp()
                    except Exception:
                        pass
                all_files.append(artifact_info)
            
            if all_files:
                result['All Files'] = {'icon': '📁', 'items': all_files}
        
        return result
    
    def _setup_menu_bar(self):
        """Setup menu bar."""
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu("&File")
        
        new_case_action = QAction("📁 &New Case", self)
        new_case_action.setShortcut("Ctrl+N")
        new_case_action.triggered.connect(self._new_case)
        file_menu.addAction(new_case_action)
        
        open_case_action = QAction("📂 &Open Case", self)
        open_case_action.setShortcut("Ctrl+O")
        open_case_action.triggered.connect(self._open_case)
        file_menu.addAction(open_case_action)
        
        file_menu.addSeparator()
        
        # Evidence ingestion
        ingest_evidence_action = QAction("💿 &Ingest Evidence...", self)
        ingest_evidence_action.setShortcut("Ctrl+I")
        ingest_evidence_action.triggered.connect(self._open_disk_image)
        file_menu.addAction(ingest_evidence_action)
        
        multi_evidence_action = QAction("📦 &Multi-Evidence Upload...", self)
        multi_evidence_action.setShortcut("Ctrl+M")
        multi_evidence_action.triggered.connect(self._open_multi_evidence)
        multi_evidence_action.setToolTip("Upload multiple related evidence files (disk + memory)")
        file_menu.addAction(multi_evidence_action)
        
        file_menu.addSeparator()
        
        # Session management
        save_session_action = QAction("💾 &Save Session", self)
        save_session_action.setShortcut("Ctrl+S")
        save_session_action.triggered.connect(self._save_session)
        file_menu.addAction(save_session_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools Menu
        tools_menu = menubar.addMenu("&Tools")
        
        settings_action = QAction("&Settings", self)
        settings_action.triggered.connect(self._show_settings)
        tools_menu.addAction(settings_action)
        
        coc_action = QAction("View Chain of &Custody", self)
        coc_action.triggered.connect(self._view_coc)
        tools_menu.addAction(coc_action)
        
        # Help Menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("&About FEPD", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
        docs_action = QAction("&Documentation", self)
        docs_action.triggered.connect(self._show_documentation)
        help_menu.addAction(docs_action)
    
    def _setup_status_bar(self):
        """Setup status bar."""
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        self.statusBar.showMessage("Ready | No case loaded")
        
        # Update status periodically
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(5000)  # Update every 5 seconds
    
    def _update_status(self):
        """Update status bar information."""
        if self.current_case:
            # Get CoC entry count
            try:
                coc_count = len(self.coc.log)
                self.statusBar.showMessage(f"Case: {self.current_case} | CoC Entries: {coc_count}")
            except (AttributeError, TypeError) as e:
                self.logger.debug(f"Could not retrieve CoC count: {e}")
                self.statusBar.showMessage(f"Case: {self.current_case}")
        else:
            self.statusBar.showMessage("Ready | No case loaded")
    
    def _on_tab_changed(self, index: int):
        """Handle tab change event and refresh forensic views with latest parsed outputs."""
        try:
            if not self.case_workspace:
                return

            tab_widget = self.tabs.widget(index)
            tab_name = self.tabs.tabText(index).lower() if hasattr(self, 'tabs') else ""

            if "case details" in tab_name and hasattr(self, 'case_details_tab') and self.case_details_tab:
                if hasattr(self.case_details_tab, 'refresh'):
                    self.case_details_tab.refresh()
                return

            if "report" in tab_name and hasattr(self, 'report_tab') and hasattr(self.report_tab, 'set_case_context'):
                self.report_tab.set_case_context(self.case_workspace, self.case_metadata or {})

            forensic_tab = (
                "artifacts" in tab_name
                or "timeline" in tab_name
                or "ml analytics" in tab_name
                or "visualizations" in tab_name
            )
            if not forensic_tab:
                return

            # Avoid excessive rebuilds while still reflecting newly parsed evidence quickly.
            now = datetime.utcnow()
            if self._last_forensic_hydration_at:
                elapsed = (now - self._last_forensic_hydration_at).total_seconds()
                if elapsed < 3:
                    return

            self._hydrate_tabs_from_unified_store(self.case_workspace, include_timeline=True, rebuild_index=True)
            self._refresh_artifacts_tab(self.case_workspace)
            self._last_forensic_hydration_at = now
            self.statusBar.showMessage("Forensic tabs refreshed from latest parsed evidence", 2500)
        except Exception as exc:
            self.logger.warning("Tab-change forensic refresh failed: %s", exc)
    
    def _new_case(self):
        """
        Create new forensic case using the modern CaseCreationDialog.
        
        Uses the updated dialog that collects:
        - Case ID
        - Case Name
        - Investigator Name
        - Evidence Image Path
        """
        from .dialogs.case_creation_dialog import CaseCreationDialog
        
        dialog = CaseCreationDialog(self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Get case metadata from dialog
            case_metadata = dialog.case_metadata
            
            if case_metadata:
                # Update main window state
                self.case_path = (
                    case_metadata.get('case_path')
                    or case_metadata.get('path')
                    or str(Path('cases') / case_metadata.get('case_id', ''))
                )
                self.case_metadata = case_metadata
                self.case_workspace = Path(self.case_path) if self.case_path else None
                self.current_case = case_metadata.get('case_id')
                
                # Initialize session manager for the new case
                if self.case_path:
                    from src.utils.session_manager import SessionManager
                    self.session_manager = SessionManager(self.case_path)
                
                # Populate Files tab VFS from case database
                case_id = case_metadata.get('case_id')
                if case_id:
                    self._refresh_files_tab(case_id)

                self._sync_all_tabs_case_context(case_metadata, self.case_workspace)
                
                # Auto-load configuration hives and artifacts
                if self.case_workspace:
                    self._auto_load_configuration_hives(self.case_workspace)
                    self._refresh_artifacts_tab(self.case_workspace)
                    self._hydrate_tabs_from_unified_store(self.case_workspace, include_timeline=True, rebuild_index=True)
                
                self.logger.info(f"✅ Case created: {case_metadata.get('case_id')}")
                self.statusBar.showMessage(
                    f"Case '{case_metadata.get('case_name')}' created successfully", 
                    5000
                )
                
                # Show success message
                QMessageBox.information(
                    self,
                    "Case Created",
                    f"✅ Case created successfully!\n\n"
                    f"Case ID: {case_metadata.get('case_id')}\n"
                    f"Case Name: {case_metadata.get('case_name')}\n"
                    f"Investigator: {case_metadata.get('investigator')}\n\n"
                    f"You can now proceed with the forensic analysis."
                )
            else:
                self.logger.warning("Case creation completed but no metadata returned")
        else:
            self.logger.info("Case creation cancelled by user")
    
    def _open_case(self):
        """
        Open existing forensic case using the modern CaseOpenDialog.
        
        Uses the updated dialog that displays:
        - Case ID
        - Case Name
        - Investigator
        - Created Date
        - Case status information
        """
        from .dialogs.case_open_dialog import CaseOpenDialog
        
        dialog = CaseOpenDialog(self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Get case metadata and image path from dialog
            case_metadata = dialog.case_metadata
            image_path = dialog.image_path
            
            if case_metadata:
                # Update main window state
                self.case_path = (
                    case_metadata.get('case_path')
                    or case_metadata.get('path')
                    or str(Path('cases') / case_metadata.get('case_id', ''))
                )
                self.case_metadata = case_metadata
                self.case_workspace = Path(self.case_path) if self.case_path else None
                self.current_case = case_metadata.get('case_id')
                
                # Initialize session manager for the opened case
                if self.case_path:
                    from src.utils.session_manager import SessionManager
                    self.session_manager = SessionManager(self.case_path)
                    
                    # Check for existing session and prompt to restore
                    self._check_and_restore_session()
                
                # Populate Files tab VFS from case database
                case_id = case_metadata.get('case_id')
                if case_id:
                    self._refresh_files_tab(case_id)

                self._sync_all_tabs_case_context(case_metadata, self.case_workspace)
                
                # Auto-load configuration hives and artifacts
                if self.case_workspace:
                    self._auto_load_configuration_hives(self.case_workspace)
                    self._refresh_artifacts_tab(self.case_workspace)
                    self._hydrate_tabs_from_unified_store(self.case_workspace, include_timeline=True, rebuild_index=True)
                
                self.logger.info(f"✅ Case opened: {case_metadata.get('case_id')}")
                self.statusBar.showMessage(
                    f"Case '{case_metadata.get('case_name')}' opened successfully", 
                    5000
                )
                
                # Show success message
                QMessageBox.information(
                    self,
                    "Case Opened",
                    f"✅ Case opened successfully!\n\n"
                    f"Case ID: {case_metadata.get('case_id')}\n"
                    f"Case Name: {case_metadata.get('case_name')}\n"
                    f"Investigator: {case_metadata.get('investigator')}\n\n"
                    f"You can now proceed with the forensic analysis."
                )
            else:
                self.logger.warning("Case opening completed but no metadata returned")
        else:
            self.logger.info("Case opening cancelled by user")
    
    def _refresh_files_tab(self, case_id: str):
        """Refresh the Files tab with data from the case database or artifacts directory."""
        try:
            if not self.vfs:
                return

            # Clear existing VFS data
            self.vfs.clear_all()

            populated = False

            # Strategy 1: Populate from case index database (files table)
            case_files_db = Path("data/indexes") / f"{case_id}.db"
            if case_files_db.exists():
                self._populate_vfs_from_files_db(case_files_db)
                # Check if anything was actually added
                if self.vfs.get_root_nodes():
                    populated = True

            # Strategy 2: Scan case workspace artifacts directory
            if not populated and self.case_workspace:
                artifacts_dir = Path(self.case_workspace) / "artifacts"
                if artifacts_dir.exists():
                    self._populate_vfs_from_case_artifacts(artifacts_dir)
                    if self.vfs.get_root_nodes():
                        populated = True

            # Strategy 3: Scan extracted_data directory
            if not populated and self.case_workspace:
                extracted_dir = Path(self.case_workspace) / "extracted_data"
                if extracted_dir.exists():
                    self._populate_vfs_from_case_artifacts(extracted_dir)

            # Refresh the tree view
            if hasattr(self, 'files_tab_widget') and self.files_tab_widget:
                if hasattr(self.files_tab_widget, 'refresh'):
                    self.files_tab_widget.refresh()
            self.logger.info(f"Files tab refreshed for case: {case_id}")
        except Exception as e:
            self.logger.warning(f"Could not refresh Files tab: {e}")
            import traceback
            traceback.print_exc()

    def _populate_vfs_from_case_artifacts(self, scan_dir: Path):
        """
        Populate VFS by scanning a physical directory tree (artifacts or extracted_data).
        
        This is the fallback when no case index database exists.
        Walks the directory tree and creates VFS nodes for all files/folders found.
        """
        from ..core.virtual_fs import VFSNodeType, VFSNode
        from datetime import datetime

        if not scan_dir.exists() or not self.vfs:
            return

        try:
            nodes_to_add = []
            parent_paths_added = set()
            base_name = scan_dir.name  # e.g. "artifacts" or "extracted_data"

            for root, dirs, files in os.walk(scan_dir):
                rel_root = Path(root).relative_to(scan_dir)
                # Build VFS path: /Evidence/{artifacts_subdir}/...
                if str(rel_root) == '.':
                    vfs_parent = '/'
                else:
                    parts = list(rel_root.parts)
                    vfs_parent = '/Evidence/' + '/'.join(parts)

                # Ensure parent directories exist
                if vfs_parent != '/':
                    dir_parts = vfs_parent.strip('/').split('/')
                    for i in range(1, len(dir_parts) + 1):
                        p_path = '/' + '/'.join(dir_parts[:i])
                        if p_path not in parent_paths_added:
                            p_parent = '/' + '/'.join(dir_parts[:i-1]) if i > 1 else '/'
                            p_name = dir_parts[i-1]
                            parent_node = VFSNode(
                                id=0,
                                path=p_path,
                                name=p_name,
                                parent_path=p_parent,
                                node_type=VFSNodeType.FOLDER,
                                size=0
                            )
                            nodes_to_add.append(parent_node)
                            parent_paths_added.add(p_path)

                # Add files
                for fname in files:
                    file_path = Path(root) / fname
                    if vfs_parent == '/':
                        vfs_file_path = f'/Evidence/{fname}'
                    else:
                        vfs_file_path = f'{vfs_parent}/{fname}'

                    # Ensure /Evidence parent exists
                    if '/Evidence' not in parent_paths_added:
                        nodes_to_add.append(VFSNode(
                            id=0, path='/Evidence', name='Evidence',
                            parent_path='/', node_type=VFSNodeType.FOLDER, size=0
                        ))
                        parent_paths_added.add('/Evidence')

                    try:
                        stat = file_path.stat()
                        size = stat.st_size
                        modified_dt = datetime.fromtimestamp(stat.st_mtime)
                        created_dt = datetime.fromtimestamp(stat.st_ctime)
                    except Exception:
                        size = 0
                        modified_dt = None
                        created_dt = None

                    file_node = VFSNode(
                        id=0,
                        path=vfs_file_path,
                        name=fname,
                        parent_path=vfs_parent if vfs_parent != '/' else '/Evidence',
                        node_type=VFSNodeType.FILE,
                        size=size,
                        created=created_dt,
                        modified=modified_dt,
                        metadata={
                            'physical_path': str(file_path.absolute()),
                            'source': base_name
                        }
                    )
                    nodes_to_add.append(file_node)

            if nodes_to_add:
                added = self.vfs.add_nodes_batch(nodes_to_add)
                logging.info(f"Populated VFS with {added} nodes from {scan_dir}")

        except Exception as e:
            logging.warning(f"Could not populate VFS from {scan_dir}: {e}")
            import traceback
            traceback.print_exc()
    
    def _load_case_data(self, case_id: str, case_path: Path):
        """
        Load complete case data and restore exact forensic workspace state.
        Uses caching for faster reopening of previously loaded cases.
        
        This method restores the entire forensic universe:
        - Step 3: Load normalized_events.csv → restore timeline data
        - Step 4: Load classified_events.csv → restore event classifications
        - Step 5: Load chain_of_custody.log → show all hash entries & validate integrity
        - Step 6: Load case_metadata.json → restore UI state (filters, timezone, theme)
        - Step 7: Rebuild UI using restored data
        
        Args:
            case_id: Case ID to load
            case_path: Path to case folder
        """
        import json
        import pandas as pd
        from datetime import datetime
        
        self.logger.info(f"Loading case: {case_id}")
        
        # Check cache first for faster loading
        if case_id in self._case_cache:
            cache_entry = self._case_cache[case_id]
            cache_age = (datetime.now() - cache_entry['timestamp']).total_seconds()
            if cache_age < self._cache_max_age_seconds:
                self.logger.debug(f"Using cached data for '{case_id}'")
                self.statusBar.showMessage(f"Loading case '{case_id}'...", 0)
                self._restore_from_cache(case_id, case_path)
                return
            else:
                del self._case_cache[case_id]
        
        self.statusBar.showMessage(f"Restoring workspace '{case_id}'...", 0)
        
        # Set current case (activate workspace)
        self.current_case = case_id
        self.case_workspace = case_path
        
        # Load normalized_events.csv
        normalized_file = case_path / "normalized_events.csv"
        if normalized_file.exists() and normalized_file.stat().st_size > 0:
            try:
                df_normalized = pd.read_csv(normalized_file)
                self.normalized_data = df_normalized
                self.logger.debug(f"Loaded {len(df_normalized)} normalized events")
            except Exception as e:
                self.logger.warning(f"Failed to load normalized_events.csv: {e}")
                self.normalized_data = None
        else:
            self.normalized_data = None
        
        # Load classified_events.csv → Timeline
        classified_file = case_path / "classified_events.csv"
        if classified_file.exists() and classified_file.stat().st_size > 0:
            try:
                df_classified = pd.read_csv(classified_file)
                self._populate_timeline_table(df_classified)
                self.logger.debug(f"Loaded {len(df_classified)} timeline events")
            except Exception as e:
                self.logger.error(f"Failed to load classified_events.csv: {e}")
        
        # Load chain_of_custody.log → Validate integrity
        coc_file = case_path / "chain_of_custody.log"
        if coc_file.exists() and coc_file.stat().st_size > 0:
            try:
                if not self._validate_coc_integrity(coc_file):
                    self.logger.warning("CoC integrity check failed")
                    QMessageBox.warning(
                        self, 
                        "Chain of Custody Warning", 
                        "⚠️ Chain of Custody integrity check failed!"
                    )
            except Exception as e:
                self.logger.error(f"Failed to validate CoC: {e}")
        
        # Load case_metadata.json → Restore UI state
        metadata_file = case_path / "case_metadata.json"
        metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                
                # Apply theme/timezone if different from current
                if 'theme' in metadata and hasattr(self, 'apply_theme'):
                    self.apply_theme(metadata['theme'])
                if 'timezone' in metadata and hasattr(self, 'set_timezone'):
                    self.set_timezone(metadata['timezone'])
            except Exception as e:
                self.logger.warning(f"Failed to load case metadata: {e}")
        
        # Load UI filters (if saved)
        filter_file = case_path / "ui_filters.json"
        if filter_file.exists():
            try:
                with open(filter_file, 'r', encoding='utf-8') as f:
                    filters = json.load(f)
                if hasattr(self, 'apply_ui_filters'):
                    self.apply_ui_filters(filters)
                elif hasattr(self.artifacts_tab, 'apply_filters'):
                    self.artifacts_tab.apply_filters(filters)
            except Exception as e:
                self.logger.debug(f"Failed to restore filters: {e}")
        
        # Load artifacts into Artifacts tab
        artifacts_dir = case_path / "artifacts"
        if artifacts_dir.exists():
            artifact_count = len([f for f in artifacts_dir.rglob("*") if f.is_file()])
            if artifact_count > 0:
                self._populate_artifacts_from_disk(artifacts_dir)
        
        # Refresh Files tab with case data
        self._refresh_files_tab(case_id)

        self._sync_ingest_tab_case({
            'case_id': case_id,
            'path': str(case_path),
        })
        
        # Auto-load registry hives into Configuration tab
        self._auto_load_configuration_hives(case_path)
        
        # Refresh Artifacts tab with case artifacts
        self._refresh_artifacts_tab(case_path)

        # Hydrate routed tab payloads from normalized store
        self._hydrate_tabs_from_unified_store(case_path, include_timeline=True, rebuild_index=True)
        
        # Enable workspace mode
        self._set_workspace_active(True)
        
        # Update window title
        self.setWindowTitle(f"FEPD - {case_id}")
        
        # Log case opening in global CoC
        self.coc.log_event(
            event_type="CASE_OPENED",
            description=f"Case '{case_id}' opened",
            metadata={"case_id": case_id}
        )
        
        # Save to cache
        self._save_to_cache(case_id, case_path)
        
        self.logger.info(f"Case '{case_id}' restored")
        self.statusBar.showMessage(f"Case '{case_id}' ready", 3000)
    
    def _save_to_cache(self, case_id: str, case_path: Path):
        """Save case data to cache for quick reopening."""
        from datetime import datetime
        
        self._case_cache[case_id] = {
            'timestamp': datetime.now(),
            'path': case_path,
            'normalized_data': self.normalized_data.copy() if self.normalized_data is not None else None,
            'metadata': self.case_metadata.copy() if self.case_metadata else None
        }
        self.logger.info(f"📦 Cached case '{case_id}' for quick access")
    
    def _restore_from_cache(self, case_id: str, case_path: Path):
        """Restore case from cache (fast path)."""
        cache_entry = self._case_cache[case_id]
        
        # Set current case
        self.current_case = case_id
        self.case_workspace = case_path
        self.normalized_data = cache_entry.get('normalized_data')
        self.case_metadata = cache_entry.get('metadata')
        
        # Restore timeline if data available
        classified_file = case_path / "classified_events.csv"
        if classified_file.exists():
            import pandas as pd
            df_classified = pd.read_csv(classified_file)
            self._populate_timeline_table(df_classified)
        
        # Rebuild artifacts
        artifacts_dir = case_path / "artifacts"
        if artifacts_dir.exists():
            self._populate_artifacts_from_disk(artifacts_dir)
        
        # Refresh Files tab
        self._refresh_files_tab(case_id)

        self._sync_ingest_tab_case({
            'case_id': case_id,
            'path': str(case_path),
        })
        
        # Auto-load configuration hives
        self._auto_load_configuration_hives(case_path)
        
        # Refresh Artifacts tab
        self._refresh_artifacts_tab(case_path)

        # Rehydrate routed tab payloads from normalized store
        self._hydrate_tabs_from_unified_store(case_path, include_timeline=True, rebuild_index=True)
        
        # Enable workspace
        self._set_workspace_active(True)
        self.setWindowTitle(f"FEPD - {case_id}")
        
        self.logger.info(f"⚡ Fast restored case '{case_id}' from cache")
        self.statusBar.showMessage(f"⚡ Case '{case_id}' loaded from cache", 5000)
    
    def _set_workspace_active(self, active: bool):
        """
        Enable or disable workspace mode.
        
        When active (case is open/created):
        - Enable "Ingest Image" button
        - Enable all case-related actions
        - Show active case indicator in status bar
        
        When inactive (no case open):
        - Disable "Ingest Image" button
        - Disable case-related actions
        
        Args:
            active: True to activate workspace, False to deactivate
        """
        # Enable/disable ingest button
        if hasattr(self, 'btn_open_image'):
            self.btn_open_image.setEnabled(active)
        
        # Update status bar indicator
        if active and self.current_case:
            self.statusBar.showMessage(f"📂 Active Case: {self.current_case}", 0)
        else:
            self.statusBar.showMessage("No active case - Create or Open a case to begin", 0)
        
        self.logger.info(f"Workspace mode: {'ACTIVE' if active else 'INACTIVE'}")
    
    def _populate_timeline_table(self, df: 'pd.DataFrame'):
        """
        Populate timeline table with events from classified DataFrame.
        
        Uses batch updates and vectorized operations to prevent UI freeze.
        
        Args:
            df: Pandas DataFrame with classified timeline events
        """
        from PyQt6.QtWidgets import QTableWidgetItem, QApplication
        
        # Limit rows for performance - show first 10000 events
        MAX_DISPLAY_ROWS = 10000
        
        if len(df) > MAX_DISPLAY_ROWS:
            self.logger.warning(f"Large dataset ({len(df)} rows) - displaying first {MAX_DISPLAY_ROWS}")
            df = df.head(MAX_DISPLAY_ROWS)
        
        # Disable updates during batch population to prevent UI freeze
        self.timeline_table.setUpdatesEnabled(False)
        self.timeline_table.blockSignals(True)
        
        try:
            row_count = len(df)
            self.timeline_table.setRowCount(row_count)
            
            # Convert columns to lists for faster iteration (much faster than iterrows)
            ts_col = df.get('ts_local', df.get('ts_utc', pd.Series([''] * row_count))).fillna('').astype(str).tolist()
            src_col = df.get('artifact_source', pd.Series([''] * row_count)).fillna('').astype(str).tolist()
            evt_col = df.get('event_type', pd.Series([''] * row_count)).fillna('').astype(str).tolist()
            desc_col = df.get('description', pd.Series([''] * row_count)).fillna('').astype(str).tolist()
            rule_col = df.get('rule_class', pd.Series(['NORMAL'] * row_count)).fillna('NORMAL').astype(str).tolist()
            
            # Process in batches for large datasets
            BATCH_SIZE = 500
            
            for idx in range(row_count):
                self.timeline_table.setItem(idx, 0, QTableWidgetItem(ts_col[idx]))
                self.timeline_table.setItem(idx, 1, QTableWidgetItem(src_col[idx]))
                self.timeline_table.setItem(idx, 2, QTableWidgetItem(evt_col[idx]))
                self.timeline_table.setItem(idx, 3, QTableWidgetItem(desc_col[idx]))
                self.timeline_table.setItem(idx, 4, QTableWidgetItem(rule_col[idx]))
                
                # Process events every batch to prevent complete freeze
                if idx > 0 and idx % BATCH_SIZE == 0:
                    QApplication.processEvents()
                    
        finally:
            # Re-enable updates
            self.timeline_table.blockSignals(False)
            self.timeline_table.setUpdatesEnabled(True)
    
    def _populate_artifacts_from_disk(self, artifacts_dir: Path):
        """
        Populate artifacts table from extracted artifacts on disk.
        
        Args:
            artifacts_dir: Path to artifacts directory
        """
        from PyQt6.QtWidgets import QTableWidgetItem
        
        self.artifacts_table.setRowCount(0)
        
        # Scan artifact subdirectories (including Linux artifact types)
        artifact_types = ['evtx', 'registry', 'prefetch', 'mft', 'browser', 'lnk', 
                         'linux_config', 'linux_log', 'script', 'binary', 'other']
        
        for artifact_type in artifact_types:
            type_dir = artifacts_dir / artifact_type
            if not type_dir.exists():
                continue
            
            # List all files in this artifact type directory
            for artifact_file in type_dir.iterdir():
                if artifact_file.is_file():
                    row_pos = self.artifacts_table.rowCount()
                    self.artifacts_table.insertRow(row_pos)
                    
                    # Format display name for Linux artifacts
                    display_type = artifact_type.replace('_', ' ').title()
                    
                    # Populate artifact info
                    self.artifacts_table.setItem(row_pos, 0, QTableWidgetItem(display_type))
                    self.artifacts_table.setItem(row_pos, 1, QTableWidgetItem(artifact_file.name))
                    self.artifacts_table.setItem(row_pos, 2, QTableWidgetItem(str(artifact_file.stat().st_size)))
                    self.artifacts_table.setItem(row_pos, 3, QTableWidgetItem(""))  # Hash (compute if needed)
                    self.artifacts_table.setItem(row_pos, 4, QTableWidgetItem("Extracted"))
    
    def _validate_coc_integrity(self, coc_file: Path) -> bool:
        """
        Validate Chain of Custody hash chain integrity.
        
        Args:
            coc_file: Path to chain_of_custody.log
            
        Returns:
            True if integrity verified, False otherwise
        """
        import json
        import hashlib
        
        try:
            with open(coc_file, 'r', encoding='utf-8') as f:
                entries = [json.loads(line) for line in f if line.strip()]
            
            if not entries:
                return True
            
            # Validate hash chain
            for i in range(1, len(entries)):
                current = entries[i]
                previous = entries[i - 1]
                
                # Check if previous_hash matches
                if current.get('previous_hash') != previous.get('entry_hash'):
                    self.logger.error(f"Hash chain broken at entry {i}: {current.get('coc_id')}")
                    return False
            
            self.logger.info("✅ Chain of Custody integrity validated")
            return True
            
        except Exception as e:
            self.logger.error(f"CoC validation failed: {e}")
            return False
    
    def _save_case_state(self):
        """
        Save current case UI state for restoration on reopen.
        
        Saves filters and UI preferences to ui_filters.json
        """
        if not self.current_case or not self.case_workspace:
            return
        
        import json
        from datetime import datetime, timezone
        
        try:
            # Collect current UI state
            ui_state = {
                'case_name': self.current_case,
                'last_saved': datetime.now(timezone.utc).isoformat(),
                'filters': {
                    # Add your filter values here
                    # Example: 'artifact_type': self.artifact_filter.currentText(),
                    # Example: 'date_from': self.date_from.text(),
                    # Example: 'classification': self.classification_filter.currentText(),
                },
                'view_settings': {
                    'timeline_sort_column': 0,  # Could get from table
                    'timeline_sort_order': 'asc',
                }
            }
            
            # Save to case workspace
            filter_file = self.case_workspace / "ui_filters.json"
            with open(filter_file, 'w', encoding='utf-8') as f:
                json.dump(ui_state, f, indent=2)
            
            self.logger.info(f"Case state saved to {filter_file}")
            
        except Exception as e:
            self.logger.warning(f"Failed to save case state: {e}")

    def load_case(self, case_metadata: dict, case_path: Path, image_path: str) -> bool:
        """
        Load a case into the main window and trigger automatic image ingestion.
        
        Args:
            case_metadata: Dictionary containing case metadata
            case_path: Path to the case directory
            image_path: Path to the forensic image file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.logger.info(f"Loading case: {case_metadata.get('case_id', 'Unknown')}")
            
            # Store case information
            self.case_metadata = case_metadata
            self.case_path = case_path
            self.image_path = image_path
            self.current_case = case_metadata.get('case_id')
            self.case_workspace = case_path
            
            # Initialize session manager for this case
            self.session_manager = SessionManager(str(case_path))
            self.logger.info(f"Session manager initialized for case: {case_path}")
            
            # Update window title
            case_id = case_metadata.get('case_id', 'N/A')
            self.setWindowTitle(f"FEPD - Forensic Evidence Parser Dashboard v1.0.0 - {case_id}")
            
            # Ensure all tabs are bound to the selected case context.
            self._sync_all_tabs_case_context(case_metadata, case_path)
            
            # Save config.json with image path
            config_file = case_path / "config.json"
            config_data = {
                "case_id": case_metadata.get('case_id'),
                "case_name": case_metadata.get('case_name'),
                "investigator": case_metadata.get('investigator'),
                "image_path": image_path,
                "created_date": case_metadata.get('created_date'),
                "last_modified": case_metadata.get('last_modified')
            }
            
            import json
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4)
            
            self.logger.info(f"Saved config.json: {config_file}")
            
            self.logger.info("ML Analytics tab case context set")
            
            # Log to chain of custody
            self.coc.log_event(
                "CASE_LOADED",
                f"Case '{case_id}' loaded with image: {Path(image_path).name}",
                severity="INFO"
            )
            
            self.logger.info("Chatbot tab case context set")
            
            # Refresh Files tab with case data (artifacts directory or index DB)
            if case_id:
                self._refresh_files_tab(case_id)
            
            # Auto-load registry hives into Configuration tab
            self._auto_load_configuration_hives(case_path)
            
            # Refresh Artifacts tab with case artifacts
            self._refresh_artifacts_tab(case_path)

            # Hydrate routed tab sections from normalized case index
            self._hydrate_tabs_from_unified_store(case_path, include_timeline=True, rebuild_index=True)
            
            # Automatically start ingestion since user already selected the image
            self.logger.info(f"Starting automatic image ingestion: {image_path}")
            QTimer.singleShot(500, lambda: self._start_automatic_ingestion(image_path))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load case: {e}", exc_info=True)
            return False
    
    def _start_automatic_ingestion(self, image_path: str):
        """
        Automatically start image ingestion after case is loaded.
        Uses the same logic as the manual "Ingest Disk Image" button.
        
        Args:
            image_path: Path to the forensic image file
        """
        self.logger.info(f"=== Automatic Ingestion Started ===")
        self.logger.info(f"Image: {image_path}")
        
        # Call the same method that the "Ingest Disk Image" button uses
        # This already handles E01 extraction, mounting, and full pipeline
        self._process_disk_image(image_path)
    
    def _process_disk_image(self, file_path: str):
        """
        Process a disk image (shared by manual button and automatic ingestion).
        
        Args:
            file_path: Path to the forensic image file
        """
        self.logger.info(f"Processing disk image: {file_path}")

        # Track current ingest source to avoid stale/incorrect completion routing.
        ext = Path(file_path).suffix.lower()
        if ext in {'.mem', '.dmp', '.raw', '.dump', '.memory', '.mddramimage', '.vmem'}:
            self._active_ingest_source_type = 'memory'
        else:
            self._active_ingest_source_type = 'disk'
        
        # Verify case is set
        if not self.current_case:
            QMessageBox.warning(self, "Error", "No case selected. Cannot proceed with image ingestion.")
            return

        # Create progress dialog
        from PyQt6.QtWidgets import QProgressDialog
        from PyQt6.QtCore import Qt, QCoreApplication
        
        self.progress_dialog = QProgressDialog(
            "Initializing forensic analysis...",
            "Cancel",
            0,
            100,
            self
        )
        self.progress_dialog.setWindowTitle("Processing Disk Image")
        self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress_dialog.setMinimumDuration(0)
        self.progress_dialog.setValue(1)  # Start at 1% to show progress immediately
        self.progress_dialog.setLabelText("Starting image analysis...")
        self.progress_dialog.show()
        QCoreApplication.processEvents()  # Force UI update
        
        # Track overall progress with finer granularity
        pipeline_stages = {
            'Initializing': 1,
            'Opening Image': 3,
            'Verifying Hash': 8,
            'Image Mounting': 15,
            'Enumerating Partitions': 20,
            'Artifact Discovery': 40,
            'Artifact Extraction': 60,
            'Artifact Parsing': 80,
            'Data Normalization': 90,
            'Event Classification': 95,
            'Pipeline Complete': 100
        }

        # Start pipeline in background thread
        def progress_cb(stage, current, total, message):
            # For SHA-256 hashing, show real-time percentage
            if 'SHA-256' in message and total > 0:
                percentage = int((current / total) * 20)  # 0-20% for hashing
                self.progress_update_signal.emit(percentage, f"Computing SHA-256 Hash\n{message}")
            elif stage in pipeline_stages and total > 0 and current > 0:
                # Show incremental progress within each stage
                base_percentage = pipeline_stages[stage]
                next_stage_percentage = 100  # Default to 100 for last stage
                
                # Find next stage percentage
                stage_keys = list(pipeline_stages.keys())
                if stage in stage_keys:
                    current_idx = stage_keys.index(stage)
                    if current_idx < len(stage_keys) - 1:
                        next_stage_percentage = pipeline_stages[stage_keys[current_idx + 1]]
                
                # Calculate incremental progress within stage range
                stage_range = next_stage_percentage - base_percentage
                progress_within_stage = int((current / total) * stage_range)
                percentage = base_percentage + progress_within_stage
                
                self.progress_update_signal.emit(percentage, f"{stage} ({current}/{total})\n{message}")
            else:
                # Update progress dialog based on stage
                percentage = pipeline_stages.get(stage, 0)
                self.progress_update_signal.emit(percentage, f"{stage}\n{message}")

        def run_pipeline(image_file_path):
            self.logger.info("=== Starting pipeline thread ===")
            self.logger.info(f"Case: {self.current_case}, Workspace: {self.case_workspace}")
            self.logger.info(f"Image: {image_file_path}")
            
            try:
                from ..modules.image_ingestion import ImageIngestionModule, ImageMetadata, PYEWF_AVAILABLE, PYTSK3_AVAILABLE
                import tempfile
                import shutil
                
                # Configure pipeline for maximum speed
                # Override config with optimized parallel settings
                optimized_config = self.config.copy() if hasattr(self.config, 'copy') else Config()
                optimized_config.set('use_parallel_processing', True)
                optimized_config.set('io_thread_pool_size', 16)  # More I/O threads for faster extraction
                optimized_config.set('max_workers', None)  # Auto-detect CPU cores
                
                pipeline = FEPDPipeline(
                    case_id=self.current_case,
                    workspace_dir=self.case_workspace,
                    config=optimized_config,
                    logger=self.logger
                )
                
                # Create temporary mount directory for E01 extraction
                temp_mount = Path(tempfile.mkdtemp(prefix="fepd_mount_"))
                
                try:
                    # Determine image type
                    image_path = Path(image_file_path)
                    ext = image_path.suffix.lower()
                    if ext in ['.e01', '.001']:
                        image_type = 'E01'
                    elif ext in ['.raw', '.dd', '.img']:
                        image_type = 'RAW'
                    else:
                        image_type = 'RAW'
                    
                    # Open image with DiskImageHandler (handles multi-partition E01 properly)
                    if image_type == 'E01' and PYEWF_AVAILABLE and PYTSK3_AVAILABLE:
                        try:
                            # Use DiskImageHandler for proper multi-partition support
                            from ..modules.image_handler import DiskImageHandler
                            
                            # Update progress: Opening image (3%)
                            self.progress_update_signal.emit(3, "Opening E01 image segments...")
                            
                            handler = DiskImageHandler(str(image_path), verify_hash=True)
                            
                            # Update progress: Verifying hash (8%)
                            self.progress_update_signal.emit(8, "Verifying image hash integrity...")
                            
                            if not handler.open_image():
                                raise Exception("Failed to open E01 image")
                            
                            self.logger.info(f"E01 opened: {handler.image_type}, Hash: {handler.image_hash}")
                            
                            # Update progress: Enumerating partitions (15%)
                            self.progress_update_signal.emit(15, "Enumerating disk partitions...")
                            
                            # Enumerate partitions
                            partitions = handler.enumerate_partitions()
                            self.logger.info(f"Found {len(partitions)} partition(s)")
                            
                            # Update progress: Starting extraction (20%)
                            self.progress_update_signal.emit(20, f"Found {len(partitions)} partition(s) - starting artifact extraction...")
                            
                            total_extracted = 0
                            for i, part in enumerate(partitions):
                                self.logger.info(f"Processing partition {i}: {part['description']}")
                                
                                # Update progress for partition: 20% to 60% range (40% divided among partitions)
                                partition_progress = int(20 + (i * 40 / max(len(partitions), 1)))
                                desc = part.get('description', 'Unknown')
                                self.progress_update_signal.emit(partition_progress, f"Processing partition {i+1}/{len(partitions)}\n{desc}")
                                
                                partition_dir = temp_mount / f"partition_{i}"
                                partition_dir.mkdir(exist_ok=True)
                                
                                try:
                                    fs_info = handler.open_filesystem(i)
                                    if fs_info:
                                        # FAST MODE: Extract only forensic artifacts (not entire filesystem)
                                        extracted = self._extract_artifacts_only(handler, fs_info, partition_dir, partition_idx=i, total_partitions=len(partitions))
                                        self.logger.info(f"Extracted {extracted} artifacts from partition {i}")
                                        
                                        if extracted == 0:
                                            # No known artifacts found - try recursive extraction (Linux/Mac/other FS)
                                            self.logger.info(f"No known artifacts on partition {i} - trying recursive extraction...")
                                            self.progress_update_signal.emit(partition_progress + 3, f"Partition {i+1}: Recursive scan of filesystem...")
                                            extracted = self._extract_partition_recursive(
                                                handler, fs_info, partition_dir, "/",
                                                max_depth=8, partition_idx=i, total_partitions=len(partitions)
                                            )
                                            self.logger.info(f"Recursive extraction got {extracted} files from partition {i}")
                                        
                                        if extracted == 0:
                                            # Still nothing - try file carving as last resort
                                            self.logger.info(f"Recursive extraction found nothing on partition {i} - trying file carving...")
                                            self.progress_update_signal.emit(partition_progress + 4, f"Partition {i+1}: Carving files...")
                                            try:
                                                carved_dir = partition_dir / "carved_files"
                                                carved_count = handler.carve_files_from_partition(i, carved_dir)
                                                extracted += carved_count
                                                self.logger.info(f"Carved {carved_count} files from partition {i}")
                                            except Exception as carve_err:
                                                self.logger.warning(f"File carving failed on partition {i}: {carve_err}")
                                        
                                        total_extracted += extracted
                                        
                                        # Update with extraction count
                                        self.progress_update_signal.emit(partition_progress + 5, f"Partition {i}: Extracted {extracted} artifacts")
                                    else:
                                        # Filesystem couldn't be mounted - try raw extraction and file carving
                                        self.logger.info(f"Filesystem not recognized on partition {i} - attempting raw extraction and file carving")
                                        
                                        # Extract raw partition data
                                        raw_file = partition_dir / "partition_raw.bin"
                                        if handler.extract_raw_partition_data(i, raw_file, max_size=None):
                                            self.logger.info(f"Raw partition data extracted: {raw_file}")
                                            total_extracted += 1
                                        
                                        # Carve files from partition
                                        carved_dir = partition_dir / "carved_files"
                                        carved_count = handler.carve_files_from_partition(i, carved_dir)
                                        total_extracted += carved_count
                                        self.logger.info(f"Carved {carved_count} files from partition {i}")
                                        
                                except Exception as e:
                                    self.logger.warning(f"Could not process partition {i}: {e}")
                                    # Still try file carving as last resort
                                    try:
                                        carved_dir = partition_dir / "carved_files"
                                        carved_count = handler.carve_files_from_partition(i, carved_dir)
                                        total_extracted += carved_count
                                        self.logger.info(f"Recovered {carved_count} files via carving from partition {i}")
                                    except Exception:
                                        self.logger.error(f"All extraction methods failed for partition {i}")
                                        continue
                            
                            handler.close()
                            self.logger.info(f"Total files extracted: {total_extracted} to {temp_mount}")
                            
                            # Copy extracted files to case workspace
                            if total_extracted > 0 and self.case_workspace:
                                extracted_dir = self.case_workspace / "extracted_data"
                                self.logger.info(f"Copying extracted files to case workspace: {extracted_dir}")
                                
                                if extracted_dir.exists():
                                    shutil.rmtree(extracted_dir)
                                shutil.copytree(temp_mount, extracted_dir)
                                self.logger.info(f"✅ Extracted files saved to: {extracted_dir}")
                                
                                # Populate image tree view using signal (thread-safe)
                                self.logger.info("Emitting signal to populate filesystem tree...")
                                self.populate_tree_signal.emit(image_path, extracted_dir, total_extracted)
                                
                                # USE EXTRACTED_DIR for pipeline (has organized categories)
                                temp_mount = extracted_dir
                            else:
                                self.logger.warning("No artifacts extracted from partitions - image may be Android/mobile or unsupported filesystem")
                                self.logger.info(f"Keeping temp mount for raw analysis: {temp_mount}")
                                # Keep temp_mount as-is for pipeline to attempt raw file scanning
                            
                        except Exception as e:
                            self.logger.error(f"E01 extraction error: {e}")
                            self.logger.warning("Image may be Android/mobile or use unsupported filesystem")
                            self.logger.info(f"Keeping temp mount for raw carving attempt: {temp_mount}")
                            # Keep temp_mount for raw file carving - do NOT fall back to parent directory
                        
                    elif PYTSK3_AVAILABLE:
                        import pytsk3
                        
                        try:
                            # Check if this is a memory dump file
                            mem_extensions = {'.mem', '.dmp', '.raw', '.dump', '.memory', '.mddramimage'}
                            if image_path.suffix.lower() in mem_extensions:
                                self.logger.info(f"Detected memory dump file: {image_path.name}")
                                self.logger.info("Routing to memory analyzer instead of disk image handler...")
                                
                                # Import memory analyzer
                                try:
                                    from ..modules.memory_analyzer import MemoryAnalyzer, analyze_memory_dump
                                    
                                    # Analyze full memory dump for forensic completeness.
                                    self.progress_update_signal.emit(30, "Analyzing memory dump (full scan)...")
                                    self.logger.info("Starting full memory dump analysis...")

                                    analyzer = MemoryAnalyzer(str(image_path))
                                    full_results = analyzer.reconstruct_live_state(max_scan_bytes=None)

                                    # Keep backward-compatible structure for existing UI/indexing paths.
                                    process_names = [
                                        str(p.get('name') or '')
                                        for p in full_results.get('processes', [])
                                        if isinstance(p, dict) and p.get('name')
                                    ]
                                    network_ips = [
                                        str(c.get('ip') or '')
                                        for c in full_results.get('network_connections', [])
                                        if isinstance(c, dict) and c.get('ip')
                                    ]
                                    results = {
                                        'file': str(image_path),
                                        'size_gb': round(image_path.stat().st_size / (1024 ** 3), 2),
                                        'scan_time': full_results.get('analysis_time') or datetime.now().isoformat(),
                                        'processes': sorted(set(process_names)),
                                        'network': sorted(set(network_ips)),
                                        'command_history': full_results.get('command_history', []),
                                        'credential_indicators': full_results.get('credential_indicators', []),
                                        'summary': full_results.get('summary', {}),
                                        'scan_mode': 'full',
                                    }
                                    
                                    if results and self.case_workspace:
                                        self.logger.info(f"Memory analysis complete: {len(results.get('processes', []))} processes, "
                                                       f"{len(results.get('network', []))} network connections")
                                        
                                        # Create memory artifacts directory
                                        memory_dir = self.case_workspace / "memory_analysis"
                                        memory_dir.mkdir(exist_ok=True)
                                        
                                        # Save compatibility results JSON
                                        import json
                                        results_file = memory_dir / "quick_scan_results.json"
                                        with open(results_file, 'w') as f:
                                            json.dump(results, f, indent=2)

                                        # Save full-fidelity results JSON
                                        full_results_file = memory_dir / "full_scan_results.json"
                                        with open(full_results_file, 'w') as f:
                                            json.dump(full_results, f, indent=2)
                                        
                                        self.logger.info(f"Memory analysis results saved: {results_file}")
                                        self.logger.info(f"Full memory analysis saved: {full_results_file}")
                                        
                                        # Store in case database for ps/netstat commands
                                        if hasattr(pipeline, 'db_handler'):
                                            # Store memory dump info in database
                                            pipeline.db_handler.add_memory_dump({
                                                'path': str(image_path),
                                                'size_bytes': image_path.stat().st_size,
                                                'processes': results.get('processes', []),
                                                'network': results.get('network', []),
                                                'analysis_time': datetime.now().isoformat()
                                            })
                                        
                                        # Skip normal filesystem processing
                                        self.logger.info("Memory dump processed successfully - skipping filesystem extraction")
                                        raise Exception("MEMORY_DUMP_PROCESSED")  # Signal to skip normal flow
                                    
                                except ImportError as ie:
                                    self.logger.error(f"Memory analyzer not available: {ie}")
                                    self.logger.warning("Falling back to raw filesystem processing...")
                                except Exception as me:
                                    if "MEMORY_DUMP_PROCESSED" in str(me):
                                        # Success signal - re-raise to skip filesystem processing
                                        raise
                                    else:
                                        self.logger.error(f"Memory analysis failed: {me}")
                                        self.logger.warning("Attempting filesystem processing as fallback...")
                            
                            # Open RAW/DD image (for disk images, or fallback for memory dumps)
                            img_info = pytsk3.Img_Info(str(image_path))
                            fs_info = pytsk3.FS_Info(img_info)
                            
                            # Extract filesystem to temp directory
                            self.progress_update_signal.emit(25, "Extracting filesystem...")
                            self._extract_filesystem(fs_info, temp_mount, "/")
                            self.logger.info(f"RAW filesystem extracted to {temp_mount}")
                            
                        except Exception as e:
                            if "MEMORY_DUMP_PROCESSED" in str(e):
                                # Memory dump was successfully analyzed
                                self.logger.info("Memory dump analysis complete - showing results")
                                # Emit completion signal with empty dataframe (memory dumps don't have timeline events)
                                classified_df = pd.DataFrame()
                                self.pipeline_finished.emit(classified_df, pipeline)
                                return  # Exit thread successfully
                            else:
                                self.logger.error(f"RAW extraction error: {e}")
                                self.logger.warning("Image may use unsupported filesystem")
                                self.logger.info(f"Keeping temp mount for raw carving: {temp_mount}")
                                # Keep temp_mount - do NOT fall back to parent directory
                    
                    else:
                        # Fallback: use parent directory (for testing with pre-extracted files)
                        shutil.rmtree(temp_mount)
                        temp_mount = image_path.parent
                        self.logger.warning("pyewf/pytsk3 not available - using parent directory as mount point")
                    
                    # Run pipeline with mounted/extracted filesystem
                    classified_df = pipeline.run(image_path, temp_mount, progress_callback=progress_cb)
                    
                    # Emit signal for UI update
                    self.pipeline_finished.emit(classified_df, pipeline)
                    
                except Exception as e:
                    self.logger.error(f"Pipeline execution failed: {e}", exc_info=True)
                    QTimer.singleShot(0, lambda: self._handle_pipeline_error(str(e)))
                finally:
                    # Cleanup temp directory if it's still a temp dir
                    if "fepd_mount_" in str(temp_mount):
                        try:
                            shutil.rmtree(temp_mount, ignore_errors=True)
                        except Exception:
                            pass
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize pipeline: {e}", exc_info=True)
                QTimer.singleShot(0, lambda: self._handle_pipeline_error(str(e)))
        
        # Start pipeline thread
        import threading
        pipeline_thread = threading.Thread(target=run_pipeline, args=(file_path,), daemon=True)
        pipeline_thread.start()
    
    def _handle_pipeline_error(self, error_message: str):
        """Handle pipeline errors."""
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        
        QMessageBox.critical(
            self,
            "Pipeline Error",
            f"Image ingestion failed:\n\n{error_message}\n\n"
            "Please check logs for details."
        )
    
    def _show_mount_info(self, image_path: str):
        """Show information about mounting the forensic image."""
        from PyQt6.QtWidgets import QMessageBox
        
        image_name = Path(image_path).name
        image_format = Path(image_path).suffix.upper()
        
        info_msg = QMessageBox(self)
        info_msg.setIcon(QMessageBox.Icon.Information)
        info_msg.setWindowTitle("Case Loaded - Next Steps")
        info_msg.setText(f"✅ Case loaded successfully!")
        
        info_msg.setInformativeText(
            f"� Evidence Image: {image_name}\n\n"
            "📋 Next Steps:\n\n"
            "1️⃣ Go to the 'Image Ingest' tab\n\n"
            "2️⃣ Click 'Ingest Disk Image' button\n\n"
            "3️⃣ Select your forensic image file\n\n"
            "4️⃣ Wait for automatic extraction and analysis\n\n"
            "The pipeline will automatically:\n"
            "  • Extract filesystem from E01/RAW images\n"
            "  • Discover all forensic artifacts\n"
            "  • Parse and classify timeline events\n"
            "  • Populate Artifacts and Timeline tabs"
        )
        
        info_msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        info_msg.exec()
    
    def _open_disk_image(self):
        """
        Open forensic disk image using the new Evidence Upload Dialog.
        
        Uses the forensic-grade orchestrator that:
        1. Shows evidence type selection (Disk/Memory)
        2. Validates multi-part E01 sequences
        3. Initializes Chain of Custody
        4. Runs full processing pipeline
        """
        # Ensure a case is selected or created first
        if not self.current_case:
            create = QMessageBox.question(
                self,
                "No Case Selected",
                "No case is currently open. Create a new case first?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if create == QMessageBox.StandardButton.Yes:
                case_name, ok = QInputDialog.getText(self, "New Case", "Enter case name:")
                if ok and case_name:
                    self.current_case = case_name
                    self.case_workspace = Path(self.config.get('CASE_WORKSPACE_DIR', './data/workspace')) / case_name
                    self.case_workspace.mkdir(parents=True, exist_ok=True)
                    self.coc.log_event("CASE_CREATED", f"New case created: {case_name}")
                    self.logger.info(f"Case '{case_name}' created at {self.case_workspace}")
                else:
                    QMessageBox.information(self, "Cancelled", "Image ingestion cancelled (no case name provided)")
                    return
            else:
                QMessageBox.information(self, "Cancelled", "Image ingestion cancelled (no case selected)")
                return
        
        # Show the Evidence Upload Dialog
        try:
            from .dialogs.evidence_upload_dialog import EvidenceUploadDialog, EvidenceProcessingDialog
            from ..core.evidence_orchestrator import EvidenceOrchestrator, EvidenceTypeEnum
            
            # Get operator name
            operator = "SYSTEM"
            if self.case_metadata and self.case_metadata.get('investigator'):
                operator = self.case_metadata.get('investigator')
            
            # Show evidence upload dialog
            upload_dialog = EvidenceUploadDialog(
                self, 
                case_name=self.current_case,
                operator=operator
            )
            
            if upload_dialog.exec() == QDialog.DialogCode.Accepted:
                selection = upload_dialog.get_selection()
                
                if selection and selection.file_paths:
                    self.logger.info(f"Evidence selected: {len(selection.file_paths)} files, type={selection.evidence_type.value}")
                    
                    # Show processing dialog
                    processing_dialog = EvidenceProcessingDialog(self, case_name=self.current_case)
                    
                    # Initialize orchestrator
                    orchestrator = EvidenceOrchestrator(
                        cases_root=str(self.config.get('CASE_WORKSPACE_DIR', './cases'))
                    )
                    
                    # Connect signals
                    def on_phase_started(phase_name, desc):
                        processing_dialog.update_phase(phase_name, "in_progress")
                    
                    def on_phase_completed(phase_name, success, msg):
                        processing_dialog.update_phase(phase_name, "completed" if success else "failed")
                    
                    def on_progress_updated(pct, msg):
                        processing_dialog.update_progress(pct, msg)
                    
                    def on_coc_entry(entry):
                        processing_dialog.add_coc_entry(entry)
                    
                    def on_pipeline_completed(result):
                        processing_dialog.set_complete(result.success, result.error_message or "")
                        if result.success:
                            # Update main window
                            self.case_workspace = result.workspace_path
                            self.image_path = selection.file_paths[0]
                            self.statusBar.showMessage(
                                f"✅ Evidence processed: {result.artifacts_discovered} artifacts, "
                                f"{result.events_parsed} events, {result.anomalies_detected} anomalies"
                            )
                    
                    orchestrator.phase_started.connect(on_phase_started)
                    orchestrator.phase_completed.connect(on_phase_completed)
                    orchestrator.progress_updated.connect(on_progress_updated)
                    orchestrator.coc_entry_added.connect(on_coc_entry)
                    orchestrator.pipeline_completed.connect(on_pipeline_completed)
                    
                    # Cancel handling
                    def on_cancel():
                        orchestrator.cancel()
                    processing_dialog.cancel_requested.connect(on_cancel)
                    
                    # Run pipeline in thread
                    def run_pipeline():
                        evidence_type = (
                            EvidenceTypeEnum.MEMORY_IMAGE 
                            if selection.evidence_type.value == "memory" 
                            else EvidenceTypeEnum.DISK_IMAGE
                        )
                        
                        orchestrator.run_full_pipeline(
                            case_name=self.current_case,
                            file_paths=selection.file_paths,
                            evidence_type=evidence_type,
                            is_multipart=selection.is_multipart,
                            operator=operator
                        )
                    
                    import threading
                    pipeline_thread = threading.Thread(target=run_pipeline, daemon=True)
                    pipeline_thread.start()
                    
                    # Show processing dialog
                    processing_dialog.exec()
                    
                    # If user didn't cancel, process the image with legacy method as fallback
                    if not orchestrator._is_cancelled and selection.file_paths:
                        self._process_disk_image(str(selection.file_paths[0]))
                        
        except ImportError as e:
            self.logger.warning(f"Evidence orchestrator not available: {e}")
            # Fall back to legacy file dialog
            self._open_disk_image_legacy()
    
    def _open_disk_image_legacy(self):
        """Legacy disk image opening method (fallback)."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Forensic Disk Image",
            "",
            "Disk Images (*.E01 *.e01 *.RAW *.raw *.DD *.dd *.IMG *.img);;All Files (*.*)"
        )
        
        if file_path:
            self.logger.info(f"User selected disk image (legacy): {file_path}")
            self._process_disk_image(file_path)
    
    def _open_multi_evidence(self):
        """
        Open multiple related evidence files using the Multi-Evidence Upload Dialog.
        
        Supports:
        - Multiple disk images
        - Disk + Memory combinations
        - Network captures + Disk images
        - Automatic relationship detection
        - Combined data processing for all tabs
        """
        # Ensure a case is selected or created first
        if not self.current_case:
            create = QMessageBox.question(
                self,
                "No Case Selected",
                "No case is currently open. Create a new case first?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if create == QMessageBox.StandardButton.Yes:
                case_name, ok = QInputDialog.getText(self, "New Case", "Enter case name:")
                if ok and case_name:
                    self.current_case = case_name
                    self.case_workspace = Path(self.config.get('CASE_WORKSPACE_DIR', './data/workspace')) / case_name
                    self.case_workspace.mkdir(parents=True, exist_ok=True)
                    self.coc.log_event("CASE_CREATED", f"New case created: {case_name}")
                    self.logger.info(f"Case '{case_name}' created at {self.case_workspace}")
                else:
                    QMessageBox.information(self, "Cancelled", "Multi-evidence upload cancelled (no case name provided)")
                    return
            else:
                QMessageBox.information(self, "Cancelled", "Multi-evidence upload cancelled (no case selected)")
                return
        
        # Show the Multi-Evidence Upload Dialog
        try:
            from .dialogs.multi_evidence_dialog import MultiEvidenceUploadDialog, EvidenceSourceCategory
            from .dialogs.evidence_upload_dialog import EvidenceProcessingDialog
            from ..core.evidence_orchestrator import EvidenceOrchestrator, EvidenceTypeEnum
            
            # Get operator name
            operator = "SYSTEM"
            if self.case_metadata and self.case_metadata.get('investigator'):
                operator = self.case_metadata.get('investigator')
            
            # Show multi-evidence upload dialog
            upload_dialog = MultiEvidenceUploadDialog(
                self,
                case_name=self.current_case,
                operator=operator
            )
            
            if upload_dialog.exec() == QDialog.DialogCode.Accepted:
                selection = upload_dialog.get_selection()
                
                if selection and selection.evidence_items:
                    self.logger.info(
                        f"Multi-evidence selected: {len(selection.evidence_items)} sources, "
                        f"relationships: {len(selection.detected_relationships)}"
                    )
                    
                    # Show processing dialog
                    processing_dialog = EvidenceProcessingDialog(self, case_name=self.current_case)
                    
                    # Initialize orchestrator
                    orchestrator = EvidenceOrchestrator(
                        cases_root=str(self.config.get('CASE_WORKSPACE_DIR', './cases'))
                    )
                    
                    # Connect signals
                    def on_phase_started(phase_name, desc):
                        processing_dialog.update_phase(phase_name, "in_progress")
                    
                    def on_phase_completed(phase_name, success, msg):
                        processing_dialog.update_phase(phase_name, "completed" if success else "failed")
                    
                    def on_progress_updated(pct, msg):
                        processing_dialog.update_progress(pct, msg)
                    
                    def on_coc_entry(entry):
                        processing_dialog.add_coc_entry(entry)
                    
                    def on_pipeline_completed(result):
                        processing_dialog.set_complete(result.success, result.error_message or "")
                        if result.success:
                            # Update main window
                            self.case_workspace = result.workspace_path
                            if selection.evidence_items:
                                self.image_path = selection.evidence_items[0].path
                            self.statusBar.showMessage(
                                f"✅ Multi-evidence processed: {result.artifacts_discovered} artifacts, "
                                f"{result.events_parsed} events, {result.anomalies_detected} anomalies"
                            )
                            # Show summary
                            QMessageBox.information(
                                self,
                                "Processing Complete",
                                f"Multi-evidence processing complete!\n\n"
                                f"• Evidence sources: {len(selection.evidence_items)}\n"
                                f"• Artifacts discovered: {result.artifacts_discovered}\n"
                                f"• Events parsed: {result.events_parsed}\n"
                                f"• Anomalies detected: {result.anomalies_detected}\n\n"
                                f"All tabs now contain combined data from all evidence sources."
                            )
                    
                    orchestrator.phase_started.connect(on_phase_started)
                    orchestrator.phase_completed.connect(on_phase_completed)
                    orchestrator.progress_updated.connect(on_progress_updated)
                    orchestrator.coc_entry_added.connect(on_coc_entry)
                    orchestrator.pipeline_completed.connect(on_pipeline_completed)
                    
                    # Cancel handling
                    def on_cancel():
                        orchestrator.cancel()
                    processing_dialog.cancel_requested.connect(on_cancel)
                    
                    # Build evidence configs from selection
                    evidence_configs = []
                    for item in selection.evidence_items:
                        # Map category to evidence type
                        if item.category == EvidenceSourceCategory.MEMORY:
                            ev_type = EvidenceTypeEnum.MEMORY_IMAGE
                        else:
                            ev_type = EvidenceTypeEnum.DISK_IMAGE
                        
                        # Collect all paths including multipart
                        all_paths = [item.path] + item.related_parts
                        
                        evidence_configs.append({
                            'file_paths': all_paths,
                            'evidence_type': ev_type,
                            'is_multipart': item.is_multipart
                        })
                    
                    # Run multi-evidence pipeline in thread
                    def run_pipeline():
                        orchestrator.run_multi_evidence_pipeline(
                            case_name=self.current_case,
                            evidence_configs=evidence_configs,
                            operator=operator
                        )
                    
                    import threading
                    pipeline_thread = threading.Thread(target=run_pipeline, daemon=True)
                    pipeline_thread.start()
                    
                    # Show processing dialog
                    processing_dialog.exec()
                    
        except ImportError as e:
            self.logger.warning(f"Multi-evidence dialog not available: {e}")
            QMessageBox.warning(
                self,
                "Feature Not Available",
                f"Multi-evidence upload is not available: {str(e)}\n\n"
                "Please use the standard 'Ingest Evidence' option."
            )
        except Exception as e:
            self.logger.error(f"Multi-evidence upload failed: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to open multi-evidence dialog: {str(e)}"
            )
    
    def _extract_filesystem(self, fs_info, output_dir: Path, path: str, max_depth: int = 5, current_depth: int = 0):
        """
        Recursively extract filesystem from pytsk3 FS_Info to directory.
        
        Args:
            fs_info: pytsk3.FS_Info object
            output_dir: Destination directory for extracted files
            path: Current path in filesystem
            max_depth: Maximum recursion depth
            current_depth: Current recursion depth
        """
        import pytsk3
        
        if current_depth >= max_depth:
            return
        
        try:
            directory = fs_info.open_dir(path)
            
            for entry in directory:
                # Skip . and ..
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                try:
                    file_name = entry.info.name.name.decode('utf-8', errors='ignore')
                    file_path = f"{path}/{file_name}" if path != "/" else f"/{file_name}"
                    local_path = output_dir / file_name
                    
                    # Check if directory
                    if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        # Create directory
                        local_path.mkdir(parents=True, exist_ok=True)
                        # Recurse into directory
                        self._extract_filesystem(fs_info, local_path, file_path, max_depth, current_depth + 1)
                    
                    # Check if regular file
                    elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        # Read file content
                        file_obj = fs_info.open_meta(entry.info.meta.addr)
                        file_size = file_obj.info.meta.size
                        
                        # Skip very large files (> 100MB) for performance
                        if file_size > 100 * 1024 * 1024:
                            continue
                        
                        # Write file
                        with open(local_path, 'wb') as f:
                            offset = 0
                            chunk_size = 1024 * 1024  # 1MB chunks
                            while offset < file_size:
                                to_read = min(chunk_size, file_size - offset)
                                data = file_obj.read_random(offset, to_read)
                                if not data:
                                    break
                                f.write(data)
                                offset += len(data)
                
                except Exception as e:
                    # Skip files that can't be read
                    continue
        
        except Exception as e:
            self.logger.warning(f"Error extracting {path}: {e}")
    
    def _populate_image_tree_safe(self, image_path: Path, extracted_dir: Path, total_extracted: int):
        """Thread-safe wrapper for _populate_image_tree - ensures it runs on main thread."""
        self.logger.info("_populate_image_tree_safe called on main thread")
        self._populate_image_tree(image_path, extracted_dir, total_extracted)
    
    def _populate_image_tree(self, image_path: Path, extracted_dir: Path, total_extracted: int):
        """
        Populate the image structure tree view and build VEFS.
        
        After evidence ingestion, this reconstructs the victim's filesystem
        as a Virtual Evidence File System (VEFS), enabling Explorer-like navigation.
        
        The Files tab becomes "that system's Explorer" - not the host PC.
        """
        from PyQt6.QtWidgets import QTreeWidgetItem, QApplication
        from PyQt6.QtCore import QTimer
        from src.modules.image_handler import DiskImageHandler
        
        try:
            self.logger.info("=" * 60)
            self.logger.info("BUILDING VIRTUAL EVIDENCE FILE SYSTEM (VEFS)")
            self.logger.info("Reconstructing victim's filesystem structure...")
            self.logger.info("=" * 60)
            
            self.image_tree.clear()
            self.statusBar.showMessage("Building Virtual Evidence File System...")
            QApplication.processEvents()  # Keep UI responsive
            
            # Process events multiple times to ensure UI stays responsive
            for _ in range(3):
                QApplication.processEvents()
                import time
                time.sleep(0.01)
            
            # Root item - Disk Image
            root_item = QTreeWidgetItem(self.image_tree)
            root_item.setText(0, f"💿 {image_path.name}")
            root_item.setExpanded(True)
            QApplication.processEvents()
            
            # Open image
            self.logger.info(f"Opening forensic image: {image_path}")
            self.statusBar.showMessage("Opening forensic image...")
            QApplication.processEvents()
            
            handler = DiskImageHandler(str(image_path), verify_hash=False)
            
            if not handler.open_image():
                raise Exception("Failed to open forensic image")
            
            QApplication.processEvents()
            
            # Build VEFS using the builder
            try:
                from ..core.vefs_builder import VEFSBuilder, OSType
                
                # Progress callback for UI - with frequent processEvents
                self._vefs_progress_counter = 0
                self._vefs_last_process_time = 0
                
                def vefs_progress(current, total, message):
                    self._vefs_progress_counter += 1
                    import time
                    now = time.time()
                    # Update UI every 20 items or every 100ms, whichever comes first
                    if self._vefs_progress_counter % 20 == 0 or (now - self._vefs_last_process_time) > 0.1:
                        self.statusBar.showMessage(f"VEFS: {message}")
                        QApplication.processEvents()
                        self._vefs_last_process_time = now
                
                # Build complete VEFS
                self.statusBar.showMessage("Building VEFS - this may take a moment...")
                QApplication.processEvents()
                
                vefs_builder = VEFSBuilder(handler, self.vfs, self.logger)
                vefs_success = vefs_builder.build(progress_callback=vefs_progress)
                
                # Process events after heavy operation
                for _ in range(5):
                    QApplication.processEvents()
                    import time
                    time.sleep(0.01)
                
                if vefs_success:
                    self.logger.debug("VEFS built successfully")
                    
                    # Store VEFS builder for file reading
                    self._vefs_builder = vefs_builder
                    
                    # Update Files tab with read function that accesses image directly
                    if hasattr(self, 'files_tab_widget') and self.files_tab_widget:
                        def read_file_from_image(path: str, offset: int = 0, length: int = -1) -> bytes:
                            """Read file from physical disk (carved/extracted) or forensic image."""
                            import os
                            try:
                                # Check if this VFS node has a physical_path (carved/extracted files)
                                if hasattr(self, 'vfs') and self.vfs:
                                    node = self.vfs.get_node(path)
                                    if node and node.metadata and node.metadata.get('physical_path'):
                                        phys = node.metadata['physical_path']
                                        if os.path.isfile(phys):
                                            with open(phys, 'rb') as f:
                                                data = f.read()
                                            if data and offset >= 0:
                                                if length > 0:
                                                    return data[offset:offset + length]
                                                else:
                                                    return data[offset:]
                                            return data or b''
                            except Exception as e:
                                self.logger.debug(f"Physical path read failed for {path}: {e}")
                            # Fallback: read from forensic image via pytsk3
                            try:
                                data = vefs_builder.read_file(path)
                                if data and offset >= 0:
                                    if length > 0:
                                        return data[offset:offset + length]
                                    else:
                                        return data[offset:]
                                return data or b''
                            except Exception:
                                return b''
                        
                        self.files_tab_widget.read_file_func = read_file_from_image
                        self.files_tab_widget.refresh()
                    
                    # Wire updated read_file and VFS into the terminal
                    terminal = getattr(self, 'fepd_terminal', None)
                    if terminal and hasattr(terminal, 'set_read_file_func'):
                        terminal.set_read_file_func(read_file_from_image)
                        if hasattr(self, 'vfs') and self.vfs and hasattr(terminal, 'set_vfs'):
                            terminal.set_vfs(self.vfs)
                    
                    # Build tree view from partitions - simple structure
                    stats = vefs_builder.stats
                    self.statusBar.showMessage(f"Building tree for {len(vefs_builder.partitions)} partitions...")
                    QApplication.processEvents()
                    
                    for part_idx, partition in enumerate(vefs_builder.partitions):
                        # Keep UI responsive between partitions
                        self.statusBar.showMessage(f"Loading partition {part_idx + 1}/{len(vefs_builder.partitions)}...")
                        QApplication.processEvents()
                        
                        # Create partition node with simple naming
                        if partition.drive_letter:
                            icon = "💾"
                            part_name = f"{partition.drive_letter} ({partition.fs_type})"
                        elif partition.is_system:
                            icon = "⚙️"
                            part_name = f"{partition.display_name}"
                        else:
                            icon = "📁"
                            part_name = f"Partition {partition.index}"
                        
                        partition_item = QTreeWidgetItem(root_item)
                        partition_item.setText(0, f"{icon} {part_name}")
                        partition_item.setExpanded(True)
                        
                        # Store partition data for metadata display
                        partition_item.setData(0, Qt.ItemDataRole.UserRole, {
                            'type': 'partition',
                            'partition_index': partition.index,
                            'drive_letter': partition.drive_letter,
                            'fs_type': partition.fs_type,
                            'is_system': partition.is_system
                        })
                        
                        # Get top-level folders from VFS
                        if partition.drive_letter:
                            base_path = f"/This PC/{partition.drive_letter}"
                        elif partition.mount_point:
                            if partition.mount_point == "/":
                                base_path = "/This PC/root"
                            else:
                                base_path = f"/This PC/{partition.mount_point.strip('/')}"
                        elif partition.is_system:
                            base_path = f"/This PC/{partition.display_name.replace(' ', '_')}"
                        else:
                            base_path = f"/This PC/Partition_{partition.index}"
                        
                        # Get file entries directly from image handler (more reliable than VFS)
                        children = []
                        try:
                            fs_info = handler.open_filesystem(partition.index)
                            if fs_info:
                                root_entries = handler.list_directory(fs_info, "/")
                                # Convert to VFS-like objects for compatibility
                                for entry in root_entries[:500]:  # Limit for performance
                                    class FileEntry:
                                        def __init__(self, e, part_path):
                                            self.name = e.get('name', 'Unknown')
                                            self.path = f"{part_path}/{self.name}"
                                            self.is_directory = e.get('is_dir', False)
                                            self.size = e.get('size', 0) or 0
                                            self.modified = e.get('modified')
                                            self.accessed = e.get('accessed')
                                            self.created = e.get('created')
                                            self.is_deleted = e.get('deleted', False)
                                    children.append(FileEntry(entry, base_path))
                        except Exception as e:
                            self.logger.debug(f"Could not list partition {partition.index}: {e}")
                        
                        if not children:
                            # Fallback to VFS
                            children = self.vfs.get_children(base_path) if self.vfs else []
                            if children is None:
                                children = []
                        
                        self.logger.info(f"Partition {partition.index} ({base_path}): {len(children)} children found")
                        
                        # ========================================================
                        # ARTIFACT-FOCUSED TREE: Show forensic artifacts by category
                        # ========================================================
                        artifact_categories = self._build_artifact_categories(base_path, children)
                        
                        if artifact_categories:
                            # Add artifact category nodes
                            for category_name, category_data in artifact_categories.items():
                                if category_data['items']:
                                    cat_item = QTreeWidgetItem(partition_item)
                                    cat_item.setText(0, f"{category_data['icon']} {category_name} ({len(category_data['items'])})")
                                    cat_item.setExpanded(True)
                                    
                                    # Store artifact files for metadata display
                                    cat_item.setData(0, Qt.ItemDataRole.UserRole, {
                                        'type': 'artifact_category',
                                        'category': category_name,
                                        'path': base_path
                                    })
                                    cat_item.setData(0, Qt.ItemDataRole.UserRole + 1, {
                                        'files': category_data['items'],
                                        'path': base_path,
                                        'total_files': len(category_data['items'])
                                    })
                                    
                                    # Add individual artifacts as children (limited to 50 per category)
                                    for artifact in category_data['items'][:50]:
                                        art_item = QTreeWidgetItem(cat_item)
                                        art_name = artifact.get('name', 'Unknown')
                                        art_icon = "📄" if not artifact.get('is_dir') else "📁"
                                        art_item.setText(0, f"{art_icon} {art_name}")
                                        art_item.setData(0, Qt.ItemDataRole.UserRole, {
                                            'type': 'artifact',
                                            'category': category_name,
                                            'path': artifact.get('path', ''),
                                            'artifact_data': artifact
                                        })
                                QApplication.processEvents()
                        else:
                            # Fallback to regular tree if no artifacts detected
                            displayed = 0
                            for child in sorted(children[:100], key=lambda x: (not x.is_directory, x.name.lower())):
                                self._add_vfs_node_to_tree(partition_item, child, max_depth=3)
                                displayed += 1
                                if displayed % 10 == 0:
                                    QApplication.processEvents()
                        
                        QApplication.processEvents()
                    
                    # ========================================================
                    # 🚀 AUTOMATIC FILESYSTEM DETECTION
                    # Detect and display complete Windows/Linux filesystem structure
                    # with Desktop, Downloads, Documents, Pictures, Music, Videos, etc.
                    # ========================================================
                    try:
                        from ..utils.auto_filesystem_detector import auto_detect_filesystem
                        
                        self.logger.info("🚀 Running automatic filesystem detection...")
                        self.statusBar.showMessage("Detecting user profiles and special folders...")
                        QApplication.processEvents()
                        
                        # Run automatic detection on extracted data
                        if extracted_dir and extracted_dir.exists():
                            filesystem_structure = auto_detect_filesystem(extracted_dir)
                            
                            # Add detected structure to tree
                            if filesystem_structure and 'root' in filesystem_structure:
                                self._add_detected_filesystem_to_tree(root_item, filesystem_structure)
                                self.logger.info("✅ Automatic filesystem detection complete")
                        
                    except Exception as e:
                        self.logger.warning(f"Automatic filesystem detection failed: {e}")
                    
                    # Add summary info
                    summary_item = QTreeWidgetItem(root_item)
                    summary_item.setText(0, f"📊 {stats['total_files']:,} files, {stats['total_folders']:,} folders")
                    
                    if stats['user_profiles']:
                        users_item = QTreeWidgetItem(root_item)
                        users_item.setText(0, f"👤 Users: {', '.join(stats['user_profiles'])}")
                    
                else:
                    self.logger.warning("VEFS build failed - using extracted data")
                    if extracted_dir and extracted_dir.exists():
                        self._build_extracted_tree(root_item, extracted_dir)
                    
            except ImportError as ie:
                self.logger.warning(f"VEFS builder not available: {ie}")
                self._build_legacy_tree(handler, root_item, extracted_dir)
            except Exception as vefs_error:
                self.logger.error(f"VEFS build error: {vefs_error}")
                self._build_legacy_tree(handler, root_item, extracted_dir)
            
            handler.close()
            self.statusBar.showMessage("VEFS ready", 3000)
            QApplication.processEvents()
            
        except Exception as tree_error:
            self.logger.error(f"Error building VEFS: {tree_error}")
            self.statusBar.showMessage("VEFS build failed", 3000)
    
    def _add_vfs_node_to_tree(self, parent_item, node, current_depth: int = 0, max_depth: int = 3):
        """Add a VFS node and its children to the tree view with proper metadata storage."""
        from PyQt6.QtWidgets import QTreeWidgetItem, QApplication
        
        try:
            # Safety check for node
            if node is None or parent_item is None:
                return
            
            # Import VFSNodeType safely
            try:
                from ..core.virtual_fs import VFSNodeType
            except ImportError:
                VFSNodeType = None
            
            # Choose icon based on node type
            icon = "📁"  # Default
            if VFSNodeType is not None and hasattr(node, 'node_type'):
                icon_map = {
                    VFSNodeType.DRIVE: "💾",
                    VFSNodeType.FOLDER: "📁",
                    VFSNodeType.SYSTEM: "⚙️",
                    VFSNodeType.USER: "👤",
                    VFSNodeType.FILE: "📄",
                    VFSNodeType.DELETED: "🗑️",
                    VFSNodeType.PARTITION: "💿",
                    VFSNodeType.ROOT: "💻",
                }
                icon = icon_map.get(node.node_type, "📄" if not getattr(node, 'is_directory', True) else "📁")
            elif hasattr(node, 'is_directory'):
                icon = "📁" if node.is_directory else "📄"
            
            # Get node name safely
            node_name = getattr(node, 'name', 'Unknown') or 'Unknown'
            node_path = getattr(node, 'path', '') or ''
            is_directory = getattr(node, 'is_directory', False)
            
            # Create tree item
            item = QTreeWidgetItem(parent_item)
            item.setText(0, f"{icon} {node_name}")
            item.setData(0, Qt.ItemDataRole.UserRole, {
                'type': 'dir' if is_directory else 'file',
                'path': node_path,
                'vfs_node': True
            })
            
            # For directories, get children and store files for metadata display
            if is_directory and hasattr(self, 'vfs') and self.vfs:
                try:
                    children = self.vfs.get_children(node_path) or []
                    
                    # Separate files and directories safely
                    files = [c for c in children if c and not getattr(c, 'is_directory', False)]
                    dirs = [c for c in children if c and getattr(c, 'is_directory', False)]
                    
                    # Store files data in UserRole+1 for metadata table display when clicked
                    if files:
                        files_data = []
                        for f in files[:200]:  # Store up to 200 files
                            try:
                                # Safely get timestamps
                                mtime = None
                                ctime = None
                                if hasattr(f, 'modified') and f.modified:
                                    try:
                                        mtime = f.modified.timestamp()
                                    except (AttributeError, OSError, ValueError):
                                        pass
                                if hasattr(f, 'created') and f.created:
                                    try:
                                        ctime = f.created.timestamp()
                                    except (AttributeError, OSError, ValueError):
                                        pass
                                
                                files_data.append({
                                    'name': getattr(f, 'name', 'Unknown') or 'Unknown',
                                    'size': getattr(f, 'size', 0) or 0,
                                    'type': 'file',
                                    'mtime': mtime,
                                    'ctime': ctime,
                                    'deleted': getattr(f, 'is_deleted', False),
                                    'sha256': getattr(f, 'sha256', None),
                                })
                            except Exception:
                                continue  # Skip problematic files
                        
                        if files_data:
                            item.setData(0, Qt.ItemDataRole.UserRole + 1, {
                                'files': files_data,
                                'path': node_path,
                                'total_files': len(files)
                            })
                    
                    # Expand important directories
                    important_dirs = {'windows', 'users', 'program files', 'documents and settings', 'home', 'system32'}
                    if node_name.lower() in important_dirs:
                        item.setExpanded(True)
                    
                    # Add children if within depth limit
                    if current_depth < max_depth:
                        displayed = 0
                        # Sort: directories first, then alphabetically (with safe key)
                        try:
                            sorted_dirs = sorted(dirs, key=lambda x: (getattr(x, 'name', '') or '').lower())
                        except Exception:
                            sorted_dirs = dirs
                        
                        for child in sorted_dirs:
                            if displayed >= 50:  # Show up to 50 subdirectories
                                break
                            try:
                                self._add_vfs_node_to_tree(item, child, current_depth + 1, max_depth)
                                displayed += 1
                            except Exception as child_error:
                                self.logger.debug(f"Error adding child node: {child_error}")
                                continue
                            
                            # Keep UI responsive during tree building
                            if displayed % 10 == 0:
                                QApplication.processEvents()
                        
                        # Add placeholder if there are more
                        if len(dirs) > 50:
                            more_item = QTreeWidgetItem(item)
                            more_item.setText(0, f"📋 ... and {len(dirs) - 50} more folders")
                            more_item.setData(0, Qt.ItemDataRole.UserRole, {'type': 'placeholder', 'path': node_path})
                    else:
                        # Add placeholder for lazy loading beyond max depth
                        if dirs:
                            placeholder = QTreeWidgetItem(item)
                            placeholder.setText(0, f"📂 {len(dirs)} subfolders (click to expand)")
                            placeholder.setData(0, Qt.ItemDataRole.UserRole, {
                                'type': 'lazy_placeholder',
                                'parent_path': node_path,
                                'child_count': len(dirs)
                            })
                            
                except Exception as children_error:
                    self.logger.debug(f"Error processing children: {children_error}")
        
        except Exception as e:
            self.logger.debug(f"Error adding VFS node to tree: {e}")
    
    def _add_detected_filesystem_to_tree(self, root_item, filesystem_structure):
        """
        Add automatically detected filesystem structure to tree.
        Shows Desktop, Downloads, Documents, Pictures, Music, Videos, etc.
        
        Args:
            root_item: Root tree widget item
            filesystem_structure: Dict[str, Any] - Detected structure from auto_filesystem_detector
        """
        from PyQt6.QtWidgets import QTreeWidgetItem, QApplication
        from PyQt6.QtCore import Qt
        
        try:
            if not filesystem_structure or 'root' not in filesystem_structure:
                return
            
            root_data = filesystem_structure['root']
            
            # Create "User Profiles" section
            if 'children' in root_data and root_data['children']:
                profiles_section = QTreeWidgetItem(root_item)
                profiles_section.setText(0, "👥 User Profiles & Special Folders")
                profiles_section.setExpanded(True)
                
                # Add each drive with user profiles
                for drive_node in root_data['children']:
                    if 'children' in drive_node:
                        for child in drive_node['children']:
                            # Look for Users folder
                            if child.get('type') == 'folder' and 'Users' in child.get('name', ''):
                                users_item = QTreeWidgetItem(profiles_section)
                                users_item.setText(0, child['name'])
                                users_item.setExpanded(True)
                                
                                # Add each user profile
                                if 'children' in child:
                                    for profile in child['children']:
                                        if profile.get('type') == 'user_profile':
                                            profile_item = QTreeWidgetItem(users_item)
                                            profile_item.setText(0, profile['name'])
                                            profile_item.setExpanded(True)
                                            
                                            # Add special folders
                                            if 'children' in profile:
                                                for folder in profile['children']:
                                                    folder_item = QTreeWidgetItem(profile_item)
                                                    folder_item.setText(0, folder['name'])
                                                    
                                                    # Store folder stats for metadata display
                                                    if 'stats' in folder:
                                                        stats = folder['stats']
                                                        folder_item.setData(0, Qt.ItemDataRole.UserRole, {
                                                            'type': 'special_folder',
                                                            'folder_name': stats.name,
                                                            'path': str(stats.path),
                                                            'file_count': stats.file_count,
                                                            'total_size': stats.total_size,
                                                            'suspicious_count': stats.suspicious_count,
                                                            'last_modified': stats.last_modified
                                                        })
                                            
                                            QApplication.processEvents()
                
                self.logger.info("✅ User profiles and special folders added to tree")
        
        except Exception as e:
            self.logger.error(f"Error adding detected filesystem to tree: {e}")
    
    def _build_legacy_tree(self, handler, root_item, extracted_dir):
        """Fall back to legacy tree building method."""
        from PyQt6.QtWidgets import QTreeWidgetItem
        
        try:
            if not handler or not root_item:
                return
                
            partitions = handler.enumerate_partitions() or []
            self.logger.info(f"Found {len(partitions)} partition(s) - building legacy tree...")
            
            for i, part_info in enumerate(partitions):
                try:
                    partition_item = QTreeWidgetItem(root_item)
                    desc = part_info.get('description', 'Unknown') if isinstance(part_info, dict) else str(part_info)
                    partition_item.setText(0, f"💾 Partition {i} - {desc}")
                    partition_item.setExpanded(True)
                    
                    try:
                        fs_info = handler.open_filesystem(i)
                        if fs_info:
                            self._build_filesystem_tree(handler, fs_info, partition_item, "/", max_depth=3)
                        else:
                            partition_dir = extracted_dir / f"partition_{i}" if extracted_dir else None
                            if partition_dir and partition_dir.exists():
                                self._build_extracted_tree(partition_item, partition_dir)
                            else:
                                error_item = QTreeWidgetItem(partition_item)
                                error_item.setText(0, "⚠ Cannot read filesystem")
                    except Exception as e:
                        self.logger.warning(f"Could not read partition {i}: {e}")
                        partition_dir = extracted_dir / f"partition_{i}" if extracted_dir else None
                        if partition_dir and partition_dir.exists():
                            self._build_extracted_tree(partition_item, partition_dir)
                        else:
                            error_item = QTreeWidgetItem(partition_item)
                            error_item.setText(0, "⚠ Cannot read filesystem")
                except Exception as part_error:
                    self.logger.warning(f"Error building partition {i}: {part_error}")
        except Exception as e:
            self.logger.error(f"Error building legacy tree: {e}")
    
    def _build_extracted_tree(self, parent_item, directory: Path, max_depth: int = 4, current_depth: int = 0):
        """Build tree from extracted/carved artifacts directory."""
        from PyQt6.QtWidgets import QTreeWidgetItem, QApplication
        
        if current_depth >= max_depth or not directory.exists():
            return
        
        try:
            items = list(directory.iterdir())
            
            # Separate directories and files
            dirs = [item for item in items if item.is_dir()]
            files = [item for item in items if item.is_file()]
            
            # Sort
            dirs.sort(key=lambda x: x.name.lower())
            files.sort(key=lambda x: x.name.lower())
            
            # Keep UI responsive for large directories
            if current_depth == 0 or len(items) > 50:
                QApplication.processEvents()
            
            # Add files to parent item data for metadata display
            if files:
                files_data = []
                for i, file_path in enumerate(files[:200]):  # Limit to 200 files
                    try:
                        stat = file_path.stat()
                        files_data.append({
                            'name': file_path.name,
                            'size': stat.st_size,
                            'type': 'file',
                            'mtime': stat.st_mtime,
                            'ctime': stat.st_ctime,
                        })
                    except Exception:
                        continue
                    # Keep UI responsive during file stat operations
                    if i > 0 and i % 50 == 0:
                        QApplication.processEvents()
                
                parent_item.setData(0, Qt.ItemDataRole.UserRole + 1, {
                    'files': files_data,
                    'path': self._get_evidence_path_from_extracted(directory),
                    'total_files': len(files)
                })
                self.logger.debug(f"Stored {len(files_data)} files for: {directory.name}")
            
            # Add directory items
            for dir_idx, dir_path in enumerate(dirs):
                # Use emoji based on directory name
                if 'carved' in dir_path.name.lower():
                    icon = "🔍"
                elif 'partition' in dir_path.name.lower():
                    icon = "💾"
                elif any(x in dir_path.name.lower() for x in ['android', 'db', 'database']):
                    icon = "📱"
                elif dir_path.name.lower() in ['registry', 'prefetch', 'evtx', 'mft']:
                    icon = "📁"
                else:
                    icon = "📂"
                
                # Convert to Windows-style evidence path for display
                evidence_path = self._get_evidence_path_from_extracted(dir_path)
                
                dir_item = QTreeWidgetItem(parent_item)
                dir_item.setText(0, f"{icon} {dir_path.name}")
                dir_item.setData(0, Qt.ItemDataRole.UserRole, {
                    'type': 'dir',
                    'path': evidence_path,  # Evidence-native path, NOT workspace path
                    '_internal_path': str(dir_path)  # Keep internal path for file ops only
                })
                dir_item.setExpanded(current_depth < 2)  # Auto-expand first 2 levels
                
                # Keep UI responsive
                if dir_idx % 20 == 0:
                    QApplication.processEvents()
                
                # Recurse into subdirectory
                self._build_extracted_tree(dir_item, dir_path, max_depth, current_depth + 1)
        
        except Exception as e:
            self.logger.error(f"Error building extracted tree for {directory}: {e}")
    
    def _build_filesystem_tree(self, handler, fs_info, parent_item, path: str, current_depth: int = 0, max_depth: int = 3):
        """
        Recursively build filesystem tree from E01 image.
        
        Args:
            handler: DiskImageHandler instance
            fs_info: Filesystem info object
            parent_item: Parent QTreeWidgetItem
            path: Current path in filesystem (e.g., "/", "/Windows", etc.)
            current_depth: Current recursion depth
            max_depth: Maximum depth to traverse
        """
        from PyQt6.QtWidgets import QTreeWidgetItem, QApplication
        
        if current_depth >= max_depth:
            return
        
        try:
            entries = handler.list_directory(fs_info, path)
            
            # Separate directories and files
            directories = []
            files = []
            
            for entry in entries:
                if entry['name'] in ['.', '..']:
                    continue
                
                if entry['type'] == 'dir':
                    directories.append(entry)
                else:
                    files.append(entry)
            
            # Keep UI responsive
            if current_depth == 0 or len(entries) > 50:
                QApplication.processEvents()
            
            # Sort directories and files
            directories.sort(key=lambda x: x['name'].lower())
            files.sort(key=lambda x: x['name'].lower())
            
            # Store files in parent item for display when clicked
            # This stores the files that exist IN this directory
            if files:
                parent_item.setData(0, Qt.ItemDataRole.UserRole + 1, {
                    'files': files[:200],  # Store up to 200 files
                    'path': path,
                    'total_files': len(files)
                })
                self.logger.debug(f"Stored {len(files)} files for path: {path}")
            
            # Add directories first
            for dir_idx, dir_entry in enumerate(directories):
                dir_item = QTreeWidgetItem(parent_item)
                dir_item.setText(0, f"📁 {dir_entry['name']}")
                dir_item.setData(0, Qt.ItemDataRole.UserRole, {
                    'type': 'dir',
                    'path': f"{path}/{dir_entry['name']}" if path != "/" else f"/{dir_entry['name']}",
                    'entry': dir_entry
                })
                
                # Keep UI responsive
                if dir_idx % 20 == 0:
                    QApplication.processEvents()
                
                # Build full path
                full_path = f"{path}/{dir_entry['name']}" if path != "/" else f"/{dir_entry['name']}"
                
                # Recursively add subdirectories (only for important ones to avoid slowness)
                important_dirs = ['Windows', 'WINDOWS', 'Program Files', 'Users', 'Documents and Settings', 
                                 'System32', 'system32', 'config', 'Prefetch', 'winevt']
                
                if current_depth < 2 or dir_entry['name'] in important_dirs:
                    self._build_filesystem_tree(handler, fs_info, dir_item, full_path, current_depth + 1, max_depth)
                else:
                    # Add placeholder for unexpanded directories
                    placeholder = QTreeWidgetItem(dir_item)
                    placeholder.setText(0, "...")
        
        except Exception as e:
            self.logger.debug(f"Error reading directory {path}: {e}")
    
    def _on_tree_item_clicked(self, item, column):
        """Handle tree item click to populate metadata table and lazy load children."""
        from PyQt6.QtWidgets import QTableWidgetItem, QApplication
        from PyQt6.QtGui import QBrush, QColor
        
        try:
            # Safety check
            if item is None:
                return
            
            # Log the click for debugging
            try:
                item_text = item.text(0) if item else 'None'
                self.logger.info(f"Tree item clicked: {item_text}")
            except Exception:
                self.logger.info("Tree item clicked")
            
            # Get item data safely
            try:
                item_data = item.data(0, Qt.ItemDataRole.UserRole)
                files_data = item.data(0, Qt.ItemDataRole.UserRole + 1)
            except Exception:
                item_data = None
                files_data = None
            
            # Handle lazy loading placeholder
            if item_data and isinstance(item_data, dict) and item_data.get('type') == 'lazy_placeholder':
                self._expand_lazy_node(item, item_data)
                return
            
            # Handle partition click - show all artifacts in this partition
            if item_data and isinstance(item_data, dict) and item_data.get('type') == 'partition':
                drive_letter = item_data.get('drive_letter', '')
                partition_idx = item_data.get('partition_index', 0)
                
                # Collect all artifacts from child categories
                all_artifacts = []
                for i in range(item.childCount()):
                    child = item.child(i)
                    if child:
                        child_files = child.data(0, Qt.ItemDataRole.UserRole + 1)
                        if child_files and isinstance(child_files, dict) and 'files' in child_files:
                            all_artifacts.extend(child_files['files'])
                
                if all_artifacts:
                    files_data = {
                        'files': all_artifacts[:200],  # Limit for performance
                        'path': f"{drive_letter or f'Partition {partition_idx}'}" ,
                        'total_files': len(all_artifacts)
                    }
                    self.logger.info(f"Partition clicked: {len(all_artifacts)} artifacts found")
            
            # Handle individual artifact click - show single artifact details
            if item_data and isinstance(item_data, dict) and item_data.get('type') == 'artifact':
                artifact_data = item_data.get('artifact_data', {})
                if artifact_data:
                    # Create a single-item files_data for the metadata table
                    files_data = {
                        'files': [artifact_data],
                        'path': artifact_data.get('path', ''),
                        'total_files': 1
                    }
                    # Continue to populate table with this single artifact
            
            # Handle artifact category click - show all artifacts in category
            if item_data and isinstance(item_data, dict) and item_data.get('type') == 'artifact_category':
                # files_data should already be set from UserRole+1
                category_name = item_data.get('category', 'Unknown')
                self.logger.info(f"Artifact category clicked: {category_name}")
            
            # Handle VFS nodes - try to get files from VFS if no cached data
            if item_data and isinstance(item_data, dict) and item_data.get('vfs_node') and not files_data:
                path = item_data.get('path', '')
                if path and hasattr(self, 'vfs') and self.vfs:
                    try:
                        children = self.vfs.get_children(path) or []
                        files = [c for c in children if c and not getattr(c, 'is_directory', False)]
                        if files:
                            files_list = []
                            for f in files[:200]:
                                try:
                                    mtime = None
                                    ctime = None
                                    if hasattr(f, 'modified') and f.modified:
                                        try:
                                            mtime = f.modified.timestamp()
                                        except (AttributeError, OSError, ValueError):
                                            pass
                                    if hasattr(f, 'created') and f.created:
                                        try:
                                            ctime = f.created.timestamp()
                                        except (AttributeError, OSError, ValueError):
                                            pass
                                    
                                    files_list.append({
                                        'name': getattr(f, 'name', 'Unknown') or 'Unknown',
                                        'size': getattr(f, 'size', 0) or 0,
                                        'type': 'file',
                                        'mtime': mtime,
                                        'ctime': ctime,
                                        'deleted': getattr(f, 'is_deleted', False),
                                        'sha256': getattr(f, 'sha256', None),
                                    })
                                except Exception:
                                    continue
                            
                            if files_list:
                                files_data = {
                                    'files': files_list,
                                    'path': path,
                                    'total_files': len(files)
                                }
                                # Cache it for next time
                                item.setData(0, Qt.ItemDataRole.UserRole + 1, files_data)
                                self.logger.info(f"Loaded {len(files_list)} files from VFS for: {path}")
                    except Exception as e:
                        self.logger.warning(f"Could not load VFS files: {e}")
        
            # Debug: Check what data exists
            self.logger.info(f"Item data (UserRole): {item_data}")
            self.logger.info(f"Files data (UserRole+1): {files_data is not None}")
            
            if not files_data or not isinstance(files_data, dict) or 'files' not in files_data:
                self.logger.info("No files data found in clicked item")
                if hasattr(self, 'file_metadata_table') and self.file_metadata_table:
                    self.file_metadata_table.setRowCount(1)
                    self.file_metadata_table.setItem(0, 0, QTableWidgetItem("📂 Click on an artifact category to see files"))
                    for col in range(1, 8):
                        self.file_metadata_table.setItem(0, col, QTableWidgetItem("-"))
                return
            
            files = files_data.get('files', [])
            if not files or not isinstance(files, list):
                if hasattr(self, 'file_metadata_table') and self.file_metadata_table:
                    self.file_metadata_table.setRowCount(1)
                    self.file_metadata_table.setItem(0, 0, QTableWidgetItem("📂 No files in this folder"))
                    for col in range(1, 8):
                        self.file_metadata_table.setItem(0, col, QTableWidgetItem("-"))
                return
            
            path = files_data.get('path', '')
            total_files = files_data.get('total_files', len(files))
        
            self.logger.info(f"Found {len(files)} files in path: {path} (total: {total_files})")
            
            # Safety check for table
            if not hasattr(self, 'file_metadata_table') or not self.file_metadata_table:
                return
            
            # Optimize table population for large file lists
            self.file_metadata_table.setRowCount(0)  # Clear first
            self.file_metadata_table.setSortingEnabled(False)
            self.file_metadata_table.setRowCount(len(files))
            
            for i, file_entry in enumerate(files):
                if not file_entry or not isinstance(file_entry, dict):
                    continue
                    
                # Keep UI responsive for large lists
                if i > 0 and i % 50 == 0:
                    QApplication.processEvents()
                
                # Name with icon
                name = file_entry.get('name', 'Unknown')
                deleted = file_entry.get('deleted', False)
                icon = "🗑️" if deleted else "📄"
                name_item = QTableWidgetItem(f"{icon} {name}")
                self.file_metadata_table.setItem(i, 0, name_item)
                
                # Size
                size = file_entry.get('size', 0)
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024**2:
                    size_str = f"{size/1024:.1f} KB"
                elif size < 1024**3:
                    size_str = f"{size/(1024**2):.1f} MB"
                else:
                    size_str = f"{size/(1024**3):.2f} GB"
                self.file_metadata_table.setItem(i, 1, QTableWidgetItem(size_str))
                
                # Type (from extension)
                ext = Path(name).suffix.upper()[1:] if '.' in name else 'File'
                self.file_metadata_table.setItem(i, 2, QTableWidgetItem(ext))
                
                # Modified
                mtime_val = file_entry.get('mtime', None)
                if mtime_val:
                    try:
                        from datetime import datetime
                        mtime_str = datetime.fromtimestamp(mtime_val).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        mtime_str = str(mtime_val)
                else:
                    mtime_str = '-'
                self.file_metadata_table.setItem(i, 3, QTableWidgetItem(mtime_str))
                
                # Accessed (atime)
                atime_val = file_entry.get('atime', None)
                if atime_val:
                    try:
                        from datetime import datetime
                        atime_str = datetime.fromtimestamp(atime_val).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        atime_str = str(atime_val)
                else:
                    atime_str = '-'
                self.file_metadata_table.setItem(i, 4, QTableWidgetItem(atime_str))
                
                # Created
                ctime_val = file_entry.get('ctime', None)
                if ctime_val:
                    try:
                        from datetime import datetime
                        ctime_str = datetime.fromtimestamp(ctime_val).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        ctime_str = str(ctime_val)
                else:
                    ctime_str = '-'
                self.file_metadata_table.setItem(i, 5, QTableWidgetItem(ctime_str))
                
                # Path - CRITICAL: Convert to Windows-style evidence path, never show analyzer paths
                raw_path = f"{path}/{name}" if path and not path.endswith("/") else f"{path}{name}"
                display_path = self._convert_to_evidence_path(raw_path)
                path_item = QTableWidgetItem(display_path)
                # Store the actual VFS path for file viewing
                path_item.setData(Qt.ItemDataRole.UserRole, file_entry.get('path', raw_path))
                self.file_metadata_table.setItem(i, 6, path_item)
                
                # SHA-256
                sha256 = file_entry.get('sha256', '-') or '-'
                self.file_metadata_table.setItem(i, 7, QTableWidgetItem(sha256))
                
                # Color deleted files red
                if deleted:
                    for col in range(8):
                        try:
                            cell = self.file_metadata_table.item(i, col)
                            if cell:
                                cell.setForeground(QBrush(QColor(231, 76, 60)))  # Red
                        except Exception:
                            pass
            
            self.file_metadata_table.setSortingEnabled(True)
            
            # Update status bar
            if hasattr(self, 'statusBar') and self.statusBar:
                if total_files > len(files):
                    self.statusBar.showMessage(f"Showing {len(files)} of {total_files} files in {path}", 3000)
                else:
                    self.statusBar.showMessage(f"{len(files)} files in {path}", 3000)
            
            self.logger.info(f"Populated metadata table with {len(files)} files from {path}")
        
        except Exception as e:
            self.logger.error(f"Error in tree item click handler: {e}")
            import traceback
            traceback.print_exc()
    
    def _on_file_double_clicked(self, index):
        """Handle double-click on file in metadata table to open file viewer."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel, QPushButton, QTabWidget, QWidget
        from PyQt6.QtGui import QFont
        
        try:
            row = index.row()
            if row < 0:
                return
            
            # Get file name and path from the table
            name_item = self.file_metadata_table.item(row, 0)
            path_item = self.file_metadata_table.item(row, 6)  # Path column
            
            if not name_item or not path_item:
                return
            
            file_name = name_item.text().replace("📄 ", "").replace("🗑️ ", "")
            display_path = path_item.text()
            vfs_path = path_item.data(Qt.ItemDataRole.UserRole) or display_path
            
            # Try to read file content
            file_content = None
            file_hex = None
            
            # Try reading from VEFS builder if available
            if hasattr(self, '_vefs_builder') and self._vefs_builder:
                try:
                    file_content = self._vefs_builder.read_file(vfs_path)
                except Exception as e:
                    self.logger.debug(f"Could not read file via VEFS: {e}")
            
            # Create file viewer dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"📄 File Viewer - {file_name}")
            dialog.setMinimumSize(800, 600)
            dialog.setModal(False)  # Allow interaction with main window
            
            layout = QVBoxLayout(dialog)
            
            # File info header
            info_label = QLabel(f"<b>File:</b> {file_name}<br><b>Path:</b> {display_path}")
            info_label.setStyleSheet("padding: 10px; background: #2d2d30; border-radius: 5px;")
            layout.addWidget(info_label)
            
            # Tab widget for different views
            tabs = QTabWidget()
            
            # Text View Tab
            text_tab = QWidget()
            text_layout = QVBoxLayout(text_tab)
            text_view = QTextEdit()
            text_view.setReadOnly(True)
            text_view.setFont(QFont("Consolas", 10))
            
            if file_content:
                try:
                    # Try to decode as text
                    text_str = file_content.decode('utf-8', errors='replace')
                    text_view.setPlainText(text_str[:100000])  # Limit to 100KB
                    if len(file_content) > 100000:
                        text_view.append(f"\n\n[... Truncated - showing first 100KB of {len(file_content):,} bytes ...]")
                except Exception:
                    text_view.setPlainText("[Could not decode file as text]")
            else:
                text_view.setPlainText("[File content not available - evidence image may need to be mounted]")
            
            text_layout.addWidget(text_view)
            tabs.addTab(text_tab, "📝 Text")
            
            # Hex View Tab
            hex_tab = QWidget()
            hex_layout = QVBoxLayout(hex_tab)
            hex_view = QTextEdit()
            hex_view.setReadOnly(True)
            hex_view.setFont(QFont("Consolas", 10))
            
            if file_content:
                # Create hex dump (first 4KB)
                hex_lines = []
                chunk = file_content[:4096]
                for i in range(0, len(chunk), 16):
                    row_bytes = chunk[i:i+16]
                    hex_part = ' '.join(f'{b:02X}' for b in row_bytes)
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row_bytes)
                    hex_lines.append(f"{i:08X}  {hex_part:<48}  {ascii_part}")
                
                hex_view.setPlainText('\n'.join(hex_lines))
                if len(file_content) > 4096:
                    hex_view.append(f"\n[... Showing first 4KB of {len(file_content):,} bytes ...]")
            else:
                hex_view.setPlainText("[File content not available]")
            
            hex_layout.addWidget(hex_view)
            tabs.addTab(hex_tab, "🔢 Hex")
            
            # Metadata Tab
            meta_tab = QWidget()
            meta_layout = QVBoxLayout(meta_tab)
            meta_view = QTextEdit()
            meta_view.setReadOnly(True)
            meta_view.setFont(QFont("Consolas", 10))
            
            # Gather metadata from table row
            meta_lines = [
                f"File Name:    {file_name}",
                f"Path:         {display_path}",
                f"Size:         {self.file_metadata_table.item(row, 1).text() if self.file_metadata_table.item(row, 1) else '-'}",
                f"Type:         {self.file_metadata_table.item(row, 2).text() if self.file_metadata_table.item(row, 2) else '-'}",
                f"Modified:     {self.file_metadata_table.item(row, 3).text() if self.file_metadata_table.item(row, 3) else '-'}",
                f"Accessed:     {self.file_metadata_table.item(row, 4).text() if self.file_metadata_table.item(row, 4) else '-'}",
                f"Created:      {self.file_metadata_table.item(row, 5).text() if self.file_metadata_table.item(row, 5) else '-'}",
                f"SHA-256:      {self.file_metadata_table.item(row, 7).text() if self.file_metadata_table.item(row, 7) else '-'}",
            ]
            
            if file_content:
                meta_lines.extend([
                    "",
                    f"Content Size: {len(file_content):,} bytes",
                    f"Magic Bytes:  {file_content[:8].hex().upper() if len(file_content) >= 8 else file_content.hex().upper()}",
                ])
            
            meta_view.setPlainText('\n'.join(meta_lines))
            meta_layout.addWidget(meta_view)
            tabs.addTab(meta_tab, "ℹ️ Metadata")
            
            layout.addWidget(tabs)
            
            # Button row
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            btn_layout.addWidget(close_btn)
            
            layout.addLayout(btn_layout)
            
            # Log file access in chain of custody
            if hasattr(self, 'chain_of_custody') and self.chain_of_custody:
                self.chain_of_custody.log_action("FILE_VIEWED", {
                    'file_name': file_name,
                    'path': display_path,
                    'vfs_path': vfs_path,
                })
            
            dialog.show()
            
        except Exception as e:
            self.logger.error(f"Error opening file viewer: {e}")
            import traceback
            traceback.print_exc()

    def _expand_lazy_node(self, placeholder_item, item_data):
        """Expand a lazy-loaded placeholder by loading its children."""
        from PyQt6.QtWidgets import QTreeWidgetItem, QApplication
        
        try:
            # Safety checks
            if not placeholder_item or not item_data or not isinstance(item_data, dict):
                return
            
            parent_path = item_data.get('parent_path', '')
            if not parent_path or not hasattr(self, 'vfs') or not self.vfs:
                return
            
            # Convert to evidence path for status bar display
            display_path = self._convert_to_evidence_path(parent_path)
            if hasattr(self, 'statusBar') and self.statusBar:
                self.statusBar.showMessage(f"Loading children of {display_path}...")
            QApplication.processEvents()
            
            # Get parent item
            parent_item = placeholder_item.parent()
            if not parent_item:
                return
            
            # Remove placeholder safely
            try:
                parent_item.removeChild(placeholder_item)
            except Exception:
                pass
            
            # Load children from VFS
            children = self.vfs.get_children(parent_path) or []
            dirs = [c for c in children if c and getattr(c, 'is_directory', False)]
            
            # Sort safely
            try:
                sorted_dirs = sorted(dirs, key=lambda x: (getattr(x, 'name', '') or '').lower())[:100]
            except Exception:
                sorted_dirs = dirs[:100]
            
            # Add child nodes
            for i, child in enumerate(sorted_dirs):
                try:
                    self._add_vfs_node_to_tree(parent_item, child, current_depth=0, max_depth=2)
                except Exception:
                    continue
                if i % 20 == 0:
                    QApplication.processEvents()
            
            if hasattr(self, 'statusBar') and self.statusBar:
                self.statusBar.showMessage(f"Loaded {len(dirs)} folders", 2000)
            
        except Exception as e:
            self.logger.error(f"Error expanding lazy node: {e}")
            if hasattr(self, 'statusBar') and self.statusBar:
                self.statusBar.showMessage("Error loading folders", 2000)
    
    def _expand_artifact_pattern(self, handler, fs_info, pattern: str, max_file_size: int = 100 * 1024 * 1024) -> list:
        """
        Expand wildcard patterns in artifact paths to actual filesystem paths.
        Robust error handling to prevent crashes.
        
        tsk3's open_dir doesn't support wildcards, so we need to:
        1. Split the path at each wildcard segment
        2. Enumerate directories to find matches
        3. Build full paths for each match
        
        Args:
            handler: DiskImageHandler instance
            fs_info: Filesystem info object
            pattern: Pattern like "Users/*/AppData/Local/..." or "Windows/Prefetch/*.pf"
            max_file_size: Maximum file size to include (default 100MB)
            
        Returns:
            List of tuples (full_path, filename) for files matching the pattern
        """
        import fnmatch
        results = []
        max_results = 200  # Limit results to prevent memory issues
        
        try:
            parts = pattern.split('/')
        except Exception:
            return []
        
        def expand_recursive(current_path: str, remaining_parts: list, depth: int = 0) -> list:
            """Recursively expand wildcard segments."""
            # Prevent infinite recursion and limit depth
            if depth > 10 or len(results) >= max_results:
                return []
            
            if not remaining_parts:
                return [(current_path, current_path.rsplit('/', 1)[-1] if '/' in current_path else current_path)]
            
            segment = remaining_parts[0]
            rest = remaining_parts[1:]
            
            if '*' in segment:
                # This segment has a wildcard - enumerate and filter
                try:
                    entries = handler.list_directory(fs_info, current_path if current_path else '/')
                    if not entries:
                        return []
                    
                    matches = []
                    
                    for entry in entries[:100]:  # Limit entries per directory
                        try:
                            entry_name = entry.get('name', '')
                            if not entry_name or entry_name in ['.', '..']:
                                continue
                            
                            # Use fnmatch for proper wildcard matching
                            if fnmatch.fnmatch(entry_name, segment):
                                next_path = f"{current_path}/{entry_name}" if current_path else f"/{entry_name}"
                                
                                if rest:  # More path segments to process
                                    if entry.get('type') == 'directory':
                                        matches.extend(expand_recursive(next_path, rest, depth + 1))
                                else:  # This is the final segment - must be a file with valid size
                                    entry_size = entry.get('size', 0)
                                    if entry.get('type') == 'file' and 0 < entry_size < max_file_size:
                                        matches.append((next_path, entry_name))
                                
                                # Stop if we have enough results
                                if len(matches) >= max_results:
                                    break
                        except Exception:
                            continue
                    
                    return matches
                except Exception:
                    return []
            else:
                # No wildcard in this segment - just append to path
                next_path = f"{current_path}/{segment}" if current_path else f"/{segment}"
                return expand_recursive(next_path, rest, depth + 1)
        
        try:
            results = expand_recursive("", parts, 0)
        except Exception:
            pass  # Return empty list on error
        
        return results[:max_results]  # Ensure limit

    def _extract_artifacts_only(self, handler, fs_info, output_dir: Path, partition_idx: int = 0, total_partitions: int = 1):
        """
        FAST MODE: Extract only known forensic artifacts (not entire filesystem).
        Uses batch extraction for 10-100x faster processing.
        Robust error handling to prevent crashes.
        
        Args:
            handler: DiskImageHandler instance
            fs_info: Filesystem info object
            output_dir: Output directory for extracted files
            partition_idx: Current partition index (for progress)
            total_partitions: Total number of partitions (for progress)
            
        Returns:
            Number of artifacts extracted
        """
        extracted_count = 0
        
        # Known forensic artifact paths (from discovery module)
        ARTIFACT_PATHS = {
            # Windows artifacts - most important first
            'registry': [
                'Windows/System32/config/SYSTEM',
                'Windows/System32/config/SOFTWARE',
                'Windows/System32/config/SAM',
                'Windows/System32/config/SECURITY',
                'Windows/System32/config/DEFAULT',
            ],
            'evtx': [
                'Windows/System32/winevt/Logs/*.evtx',
            ],
            'prefetch': [
                'Windows/Prefetch/*.pf',
            ],
            'mft': [
                '$MFT',
            ],
            'user_registry': [
                'Users/*/NTUSER.DAT',
                'Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat',
            ],
            # Linux artifacts
            'linux_system': [
                'etc/passwd',
                'etc/shadow',
                'etc/group',
                'etc/hostname',
                'etc/hosts',
                'etc/fstab',
                'etc/crontab',
                'etc/sudoers',
                'etc/os-release',
            ],
            'linux_logs': [
                'var/log/syslog',
                'var/log/auth.log',
                'var/log/messages',
                'var/log/kern.log',
                'var/log/dmesg',
                'var/log/wtmp',
                'var/log/btmp',
                'var/log/lastlog',
                'var/log/secure',
                'var/log/faillog',
                'var/log/apache2/*.log',
                'var/log/nginx/*.log',
            ],
            'linux_user': [
                'home/*/.bash_history',
                'home/*/.bashrc',
                'home/*/.profile',
                'home/*/.ssh/authorized_keys',
                'home/*/.ssh/known_hosts',
                'root/.bash_history',
                'root/.bashrc',
            ],
            # macOS artifacts
            'macos_system': [
                'private/var/log/system.log',
                'private/var/log/install.log',
                'private/var/db/dslocal/nodes/Default/users/*.plist',
            ],
        }
        
        # Collect all files to extract first (fast discovery phase)
        files_to_extract = []  # List of (source_path, output_path, category)
        
        try:
            self.progress_update_signal.emit(
                int(10 + (partition_idx * 40 / total_partitions)), 
                f"Partition {partition_idx + 1}: Discovering artifacts..."
            )
        except Exception:
            pass  # Don't crash on signal error
        
        for category, paths in ARTIFACT_PATHS.items():
            category_dir = output_dir / category
            
            for pattern in paths:
                try:
                    # Handle wildcard patterns - need to expand wildcards in directory paths
                    if '*' in pattern:
                        # Get all expanded paths for this pattern
                        try:
                            expanded_paths = self._expand_artifact_pattern(handler, fs_info, pattern)
                        except Exception:
                            expanded_paths = []
                        
                        for expanded_path, file_name in expanded_paths:
                            try:
                                # Generate unique local path including parent dirs for user artifacts
                                path_parts = expanded_path.strip('/').split('/')
                                if len(path_parts) >= 2 and path_parts[0] == 'Users':
                                    unique_name = f"{path_parts[1]}_{file_name}"
                                else:
                                    unique_name = file_name
                                local_path = category_dir / unique_name
                                files_to_extract.append((expanded_path, str(local_path), category))
                            except Exception:
                                continue
                    else:
                        # Direct file path
                        file_path = f"/{pattern}"
                        local_path = category_dir / pattern.split('/')[-1]
                        files_to_extract.append((file_path, str(local_path), category))
                except Exception:
                    continue  # Skip problematic patterns
        
        # Now extract all files in batch (fast extraction phase)
        total_files = len(files_to_extract)
        self.logger.debug(f"Partition {partition_idx}: Found {total_files} artifacts to extract")
        
        if total_files == 0:
            return 0
        
        # Create all category directories upfront
        for _, output_path, category in files_to_extract:
            try:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
        
        # Extract files with progress updates - robust error handling
        for i, (source_path, output_path, category) in enumerate(files_to_extract):
            # Update progress every 20 files for less UI overhead
            if i % 20 == 0:
                try:
                    progress_pct = int(15 + (partition_idx * 40 / total_partitions) + 
                                      (i / max(total_files, 1)) * (35 / total_partitions))
                    self.progress_update_signal.emit(
                        progress_pct, 
                        f"Partition {partition_idx + 1}: {i}/{total_files} ({category})"
                    )
                except Exception:
                    pass  # Don't crash on signal error
            
            # Use fast extraction (no hash calculation, no logging per file)
            try:
                metadata = handler.extract_file_fast(fs_info, source_path, Path(output_path), calculate_hash=False)
                if metadata:
                    extracted_count += 1
            except Exception:
                continue  # Skip failed files, don't crash
        
        # Final progress update
        try:
            self.progress_update_signal.emit(
                int(50 + (partition_idx * 10 / total_partitions)),
                f"Partition {partition_idx + 1}: {extracted_count} artifacts extracted"
            )
        except Exception:
            pass
        
        return extracted_count
    
    def _extract_partition_recursive(self, handler, fs_info, output_dir: Path, path: str, max_depth: int = 8, current_depth: int = 0, partition_idx: int = 0, total_partitions: int = 1):
        """
        Recursively extract files from a partition using DiskImageHandler.
        Robust error handling to prevent crashes.
        
        Args:
            handler: DiskImageHandler instance
            fs_info: Filesystem info object
            output_dir: Output directory for extracted files
            path: Current path in filesystem
            max_depth: Maximum recursion depth
            current_depth: Current recursion depth
            partition_idx: Current partition index (for progress)
            total_partitions: Total number of partitions (for progress)
            
        Returns:
            Number of files extracted
        """
        if current_depth >= max_depth:
            return 0
        
        extracted_count = 0
        max_files_per_dir = 20000  # High ceiling for deep forensic extraction
        
        try:
            entries = handler.list_directory(fs_info, path)
            if not entries:
                return 0
            
            total_entries = min(len(entries), max_files_per_dir)
            
            for idx, entry in enumerate(entries[:max_files_per_dir]):
                if entry.get('name') in ['.', '..', None]:
                    continue
                
                # Update progress every 50 files for less UI overhead
                if idx % 50 == 0 and current_depth <= 1:
                    try:
                        base_progress = 10 + (partition_idx * 40 / max(total_partitions, 1))
                        entry_progress = (idx / max(total_entries, 1)) * (40 / max(total_partitions, 1))
                        overall_progress = int(base_progress + entry_progress)
                        self.progress_update_signal.emit(overall_progress, f"Scanning: {entry.get('name', '?')}...")
                    except Exception:
                        pass  # Don't crash on signal error
                
                try:
                    entry_name = entry.get('name', '')
                    if not entry_name:
                        continue
                        
                    entry_path = f"{path}/{entry_name}" if path != "/" else f"/{entry_name}"
                    local_path = output_dir / entry_name
                    
                    if entry.get('type') == 'dir':
                        # Create directory and recurse
                        try:
                            local_path.mkdir(exist_ok=True)
                        except Exception:
                            continue
                        subcount = self._extract_partition_recursive(
                            handler, fs_info, local_path, entry_path, 
                            max_depth, current_depth + 1, partition_idx, total_partitions
                        )
                        extracted_count += subcount
                    
                    elif entry.get('type') == 'file':
                        file_size = entry.get('size', 0)
                        # Extract full file; handler streams in chunks for memory safety.
                        if file_size > 0:
                            try:
                                success = handler.extract_file(fs_info, entry_path, local_path)
                                if success:
                                    extracted_count += 1
                            except Exception:
                                continue  # Skip failed files
                
                except Exception:
                    continue  # Skip problematic entries
        
        except Exception:
            pass  # Directory read failed - skip
        
        return extracted_count
    
    def _generate_report(self):
        """Generate final PDF report with comprehensive forensic analysis."""
        if not self.current_case:
            QMessageBox.warning(self, "No Case", "Please create or open a case first")
            return
        
        try:
            from ..utils.report_generator import ReportGenerator, REPORTLAB_AVAILABLE
            
            if not REPORTLAB_AVAILABLE:
                QMessageBox.critical(
                    self,
                    "Missing Dependency",
                    "ReportLab library is required for PDF generation.\n\n"
                    "Install with: pip install reportlab"
                )
                return
            
            # Show language selection dialog
            from .dialogs.language_selector_dialog import LanguageSelectorDialog
            lang_dialog = LanguageSelectorDialog(self)
            if lang_dialog.exec() != lang_dialog.DialogCode.Accepted:
                return  # User cancelled
            
            # Set selected language
            selected_language = lang_dialog.get_selected_language()
            self.translator.set_language(selected_language)
            self.logger.info(f"Report language set to: {selected_language}")
            
            # Show progress dialog
            from PyQt6.QtWidgets import QProgressDialog
            progress = QProgressDialog(
                "Generating comprehensive forensic report...\n\n"
                "This may take a few moments depending on the amount of data.",
                "Cancel",
                0,
                100,
                self
            )
            progress.setWindowTitle("Generating Report")
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.setMinimumDuration(0)
            progress.setValue(10)
            progress.show()
            
            # Collect data for report
            progress.setLabelText("Collecting case data...")
            progress.setValue(20)
            QApplication.processEvents()
            
            # Get classified events if available
            classified_df = None
            if self.case_workspace:
                classified_file = self.case_workspace / "classified_events.csv"
                if classified_file.exists():
                    try:
                        classified_df = pd.read_csv(classified_file)
                    except Exception as e:
                        self.logger.warning(f"Failed to load classified events: {e}")
            
            progress.setValue(40)
            QApplication.processEvents()
            
            # Get artifacts data
            artifacts_data = []
            if self.case_workspace:
                artifacts_dir = self.case_workspace / "artifacts"
                if artifacts_dir.exists():
                    for artifact_type in ['evtx', 'registry', 'prefetch', 'mft', 'browser', 'lnk',
                                         'linux_config', 'linux_log', 'script', 'binary', 'other']:
                        type_dir = artifacts_dir / artifact_type
                        if type_dir.exists():
                            for artifact_file in type_dir.rglob("*"):
                                if artifact_file.is_file():
                                    artifacts_data.append({
                                        'type': artifact_type,
                                        'name': artifact_file.name,
                                    'path': str(artifact_file.relative_to(artifacts_dir)),
                                    'size': artifact_file.stat().st_size,
                                    'modified': datetime.fromtimestamp(
                                        artifact_file.stat().st_mtime
                                    ).isoformat()
                                })
            
            progress.setValue(60)
            progress.setLabelText("Generating PDF report...")
            QApplication.processEvents()
            
            # Get CoC log path
            coc_log_path = None
            if self.case_workspace:
                coc_log_path = self.case_workspace / "chain_of_custody.log"
                if not coc_log_path.exists():
                    coc_log_path = None
            
            # Initialize report generator
            report_gen = ReportGenerator(
                case_metadata=self.case_metadata,
                case_path=self.case_workspace,
                classified_df=classified_df,
                artifacts_data=artifacts_data,
                coc_log_path=coc_log_path,
                logger=self.logger
            )
            
            progress.setValue(80)
            QApplication.processEvents()
            
            # Generate report
            report_path = report_gen.generate_report()
            
            progress.setValue(100)
            progress.close()
            
            self.logger.info(f"Report generated successfully: {report_path}")
            
            # Log to CoC
            self.coc.log_event(
                "REPORT_GENERATED",
                f"Forensic report generated: {report_path.name}",
                severity="INFO"
            )
            
            # Show success message with option to open
            result = QMessageBox.question(
                self,
                "Report Generated",
                f"✅ Forensic report generated successfully!\n\n"
                f"Report: {report_path.name}\n"
                f"Location: {report_path.parent}\n\n"
                f"Would you like to open the report folder?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if result == QMessageBox.StandardButton.Yes:
                import os
                import subprocess
                
                # Open report folder in file explorer
                if os.name == 'nt':  # Windows
                    os.startfile(report_path.parent)
                elif os.name == 'posix':  # macOS/Linux
                    subprocess.run(['open' if sys.platform == 'darwin' else 'xdg-open', str(report_path.parent)])
        
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "Report Generation Failed",
                f"Failed to generate report:\n\n{str(e)}\n\n"
                f"Check logs for details."
            )
    
    def _show_settings(self):
        """Show settings dialog."""
        QMessageBox.information(self, "Settings", "Settings dialog - To be implemented")
    
    def _view_coc(self):
        """View Chain of Custody log."""
        try:
            coc_entries = len(self.coc.log)
            QMessageBox.information(
                self, 
                "Chain of Custody", 
                f"Total CoC Entries: {coc_entries}\n\nFull CoC viewer - To be implemented (FR-25)"
            )
        except (AttributeError, TypeError, IOError) as e:
            self.logger.warning(f"Failed to display CoC: {e}")
            QMessageBox.warning(self, "CoC", "No Chain of Custody entries found")
    
    def _show_about(self):
        """Show about dialog."""
        about_text = """
        <h2>FEPD - Forensic Evidence Parser Dashboard</h2>
        <p><b>Version:</b> 1.0.0</p>
        <p><b>Purpose:</b> Offline forensic analysis for Windows disk images</p>
        <p><b>Compliance:</b> NIST SP 800-86, ISO/IEC 27037, ACPO Principles</p>
        <br>
        <p>Copyright © 2025 FEPD Development Team</p>
        <p>Proprietary - For Forensic Use Only</p>
        """
        QMessageBox.about(self, "About FEPD", about_text)
    
    def _show_documentation(self):
        """Show documentation."""
        QMessageBox.information(
            self,
            "Documentation",
            "Documentation files located in:\n\n"
            "- docs/\n"
            "- INSTALL.md\n"
            "- PROJECT_INDEX.md\n"
            "- QUICK_REFERENCE.md"
        )
    
    def _on_progress_update(self, percentage: int, message: str):
        """
        Slot called for progress updates (thread-safe via Qt signal).
        Updates the progress dialog from the main thread.
        
        Args:
            percentage: Progress percentage (0-100)
            message: Status message to display
        """
        try:
            if hasattr(self, 'progress_dialog') and self.progress_dialog:
                self.progress_dialog.setValue(percentage)
                self.progress_dialog.setLabelText(message)
            self.statusBar.showMessage(message)
        except Exception as e:
            self.logger.warning(f"Progress update error: {e}")
    
    def _on_pipeline_finished(self, classified_df, pipeline):
        """
        Slot called when pipeline finishes (thread-safe via Qt signal).
        Updates UI with pipeline results.
        
        Args:
            classified_df: DataFrame with classified events
            pipeline: Pipeline instance with extracted artifacts
        """
        try:
            self._on_pipeline_finished_impl(classified_df, pipeline)
        except Exception as e:
            self.logger.error(f"Critical error in pipeline finished handler: {e}")
            import traceback
            traceback.print_exc()
            QMessageBox.critical(
                self,
                "Pipeline Error",
                f"An error occurred while updating the UI after pipeline completion:\n\n{str(e)}\n\n"
                f"Your analysis results have been saved. Try reloading the case."
            )
            self.statusBar.showMessage(f"Error: {str(e)}", 10000)
    
    def _on_pipeline_finished_impl(self, classified_df, pipeline):
        """Implementation of pipeline finished handler (separated for error handling)."""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication
        
        self.logger.info("Pipeline processing completed")
        
        # Close progress dialog
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        
        # Check if this run was a memory dump analysis.
        # Do not infer from directory existence alone, because mixed cases can contain both outputs.
        memory_analysis_dir: Optional[Path] = (
            self.case_workspace.joinpath("memory_analysis")
            if self.case_workspace is not None
            else None
        )
        is_memory_dump = self._active_ingest_source_type == 'memory'
        
        if is_memory_dump and memory_analysis_dir:
            # Handle memory dump results
            self.logger.info("Displaying memory dump analysis results")
            
            # Load memory analysis results
            results_file = memory_analysis_dir / "quick_scan_results.json"
            if results_file.exists():
                import json
                with open(results_file, 'r') as f:
                    results = json.load(f)
                
                processes = results.get('processes', [])
                network_ips = results.get('network', [])
                
                # Show success message
                msg = (
                    f"✅ Memory Dump Analysis Complete!\n\n"
                    f"File: {self.case_metadata.get('image_path', 'Unknown')}\n"
                    f"Size: {results.get('size_gb', 0):.2f} GB\n\n"
                    f"Artifacts Extracted:\n"
                    f"• Processes: {len(processes)}\n"
                    f"• Network IPs: {len(network_ips)}\n\n"
                    f"Results saved to: memory_analysis/\n\n"
                    f"Use FEPD Terminal commands:\n"
                    f"  • 'ps' - View processes\n"
                    f"  • 'netstat' - View network connections\n"
                    f"  • 'memscan --full' - Run full analysis"
                )
                
                # Show malware indicators if found
                malware_indicators = []
                for proc in processes[:50]:  # Check first 50 processes
                    proc_lower = proc.lower()
                    if any(mal in proc_lower for mal in ['zyklon', 'keylog', 'rat', 'backdoor', 'trojan']):
                        malware_indicators.append(proc)
                
                if malware_indicators:
                    msg += f"\n\n⚠️ POTENTIAL MALWARE DETECTED:\n" + "\n".join(f"  • {m}" for m in malware_indicators[:5])
                
                QMessageBox.information(
                    self,
                    "Memory Analysis Complete",
                    msg
                )
                
                self.statusBar.showMessage(f"Memory analysis complete - {len(processes)} processes, {len(network_ips)} IPs")

            # Ensure UI tabs consume latest normalized outputs even for memory-only runs.
            if self.case_workspace:
                self._hydrate_tabs_from_unified_store(self.case_workspace, include_timeline=True, rebuild_index=True)
                self._refresh_artifacts_tab(self.case_workspace)
                self._last_forensic_hydration_at = datetime.utcnow()

            self._active_ingest_source_type = None
            
            # No timeline events for memory dumps - they're displayed via terminal commands
            return
        
        # Handle normal disk image results - USE DEFERRED LOADING TO PREVENT UI FREEZE
        event_count = len(classified_df) if classified_df is not None else 0
        self.statusBar.showMessage(f"Loading {event_count} events... Please wait", 0)
        QApplication.processEvents()
        
        # Store data for deferred loading
        self._pending_classified_df = classified_df
        self._pending_pipeline = pipeline
        self._pending_event_count = event_count
        
        # Start the deferred loading chain - each step processes events to keep UI responsive
        # Use 100ms delay between steps to allow UI to fully update
        QTimer.singleShot(100, self._deferred_load_step1_timeline)
    
    def _deferred_load_step1_timeline(self):
        """Step 1: Load timeline table (deferred to prevent UI freeze)."""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication
        import time
        
        try:
            classified_df = self._pending_classified_df
            if classified_df is not None and not classified_df.empty:
                self.statusBar.showMessage(f"Loading timeline ({len(classified_df)} events)...", 0)
                QApplication.processEvents()
                time.sleep(0.01)  # Small delay for UI
                self._populate_timeline_table(classified_df)
                QApplication.processEvents()  # Let UI catch up after heavy operation
                self.logger.info(f"Updated timeline table with {len(classified_df)} events")
            else:
                self.timeline_table.setRowCount(0)
                self.logger.warning("No timeline events to display")
        except Exception as e:
            self.logger.error(f"Error loading timeline: {e}")
        
        # Continue to next step with longer delay
        QApplication.processEvents()
        QTimer.singleShot(100, self._deferred_load_step2_tabs)
    
    def _deferred_load_step2_tabs(self):
        """Step 2: Load analysis tabs (deferred to prevent UI freeze)."""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication
        import time
        
        try:
            classified_df = self._pending_classified_df
            if classified_df is not None and not classified_df.empty:
                # Load into ML Analytics tab
                self.statusBar.showMessage("Loading ML Analytics...", 0)
                QApplication.processEvents()
                time.sleep(0.01)
                if hasattr(self, 'ml_analytics_tab'):
                    self.ml_analytics_tab.load_events(classified_df)
                    self.logger.info(f"Loaded events into ML Analytics tab")
                QApplication.processEvents()
                
                # Load into visualizations tab
                self.statusBar.showMessage("Loading Visualizations...", 0)
                QApplication.processEvents()
                time.sleep(0.01)
                if hasattr(self, 'visualizations_tab'):
                    self.visualizations_tab.load_events(classified_df)
                    self.logger.info(f"Loaded events into Visualizations tab")
                QApplication.processEvents()
                
                QApplication.processEvents()
        except Exception as e:
            self.logger.error(f"Error loading tabs: {e}")
        
        # Continue to next step with longer delay
        QApplication.processEvents()
        QTimer.singleShot(100, self._deferred_load_step3_terminal)
    
    def _deferred_load_step3_terminal(self):
        """Step 3: Load terminal (deferred to prevent UI freeze)."""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication
        import time
        
        try:
            self.statusBar.showMessage("Loading Terminal...", 0)
            QApplication.processEvents()
            time.sleep(0.01)
            if hasattr(self, 'fepd_terminal') and self.current_case:
                self.fepd_terminal.load_case(self.current_case)
                self.logger.info(f"Loaded case into FEPD Terminal")
            QApplication.processEvents()
        except Exception as e:
            self.logger.error(f"Error loading terminal: {e}")
        
        # Continue to next step with longer delay
        QApplication.processEvents()
        QTimer.singleShot(100, self._deferred_load_step4_files)
    
    def _deferred_load_step4_files(self):
        """Step 4: Load files and artifacts (deferred to prevent UI freeze)."""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication
        import time
        
        try:
            pipeline = self._pending_pipeline
            
            # Populate files table from extracted artifacts
            if self.current_case:
                self.statusBar.showMessage("Loading Files...", 0)
                QApplication.processEvents()
                time.sleep(0.01)
                
                extracts = getattr(pipeline, 'extracted_artifacts', [])
                if extracts:
                    self._populate_files_table_from_artifacts(self.current_case, extracts)
                    self.logger.info(f"Populated files table with {len(extracts)} extracted artifacts")
                    QApplication.processEvents()
                    time.sleep(0.01)
                    
                    # Also populate VFS directly for immediate display
                    if hasattr(self, 'vfs') and self.vfs:
                        self.vfs.clear_all()
                        self._populate_vfs_from_extracted_artifacts(extracts)
                        self.logger.info("Populated VFS directly from extracted artifacts")
                    QApplication.processEvents()
        except Exception as e:
            self.logger.error(f"Error loading files: {e}")
        
        # Continue to next step with longer delay
        QApplication.processEvents()
        QTimer.singleShot(100, self._deferred_load_step5_refresh)
    
    def _deferred_load_step5_refresh(self):
        """Step 5: Refresh Files tab (deferred to prevent UI freeze)."""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication
        import time
        
        try:
            if self.current_case:
                self.statusBar.showMessage("Refreshing Files Tab...", 0)
                QApplication.processEvents()
                time.sleep(0.01)
                self._refresh_files_tab(self.current_case)
                self.logger.info("Files tab refreshed after pipeline completion")
                QApplication.processEvents()
                
                # Inject VFS into terminal NOW that it's fully populated
                if hasattr(self, 'fepd_terminal') and hasattr(self, 'vfs') and self.vfs:
                    try:
                        # Try the VEOS-style terminal API first
                        if hasattr(self.fepd_terminal, 'set_veos'):
                            self.fepd_terminal.set_veos(self.vfs)
                        elif hasattr(self.fepd_terminal, 'terminal') and hasattr(self.fepd_terminal.terminal, 'get_engine'):
                            engine = self.fepd_terminal.terminal.get_engine()
                            engine.vfs = self.vfs
                            if hasattr(self.fepd_terminal.terminal, 'win_engine'):
                                self.fepd_terminal.terminal.win_engine.shell.vfs = self.vfs
                        
                        # Trigger a refresh message in terminal
                        if hasattr(self.fepd_terminal, '_append_output'):
                            self.fepd_terminal._append_output(
                                "\n✅ Evidence filesystem loaded - Commands now operational\n",
                                color="#50c878"
                            )
                        elif hasattr(self.fepd_terminal, 'terminal') and hasattr(self.fepd_terminal.terminal, 'print_message'):
                            self.fepd_terminal.terminal.print_message(
                                "✅ Evidence filesystem loaded - Commands now operational",
                                'success'
                            )
                        
                        self.logger.info("✅ VFS injected into terminal - commands now operational")
                    except Exception as ve:
                        self.logger.error(f"Failed to inject VFS into terminal: {ve}")
        except Exception as e:
            self.logger.error(f"Error refreshing files tab: {e}")
        
        # Continue to final step with longer delay
        QApplication.processEvents()
        QTimer.singleShot(100, self._deferred_load_step6_artifacts)
    
    def _deferred_load_step6_artifacts(self):
        """Step 6: Populate artifacts table and show completion (deferred)."""
        from PyQt6.QtWidgets import QApplication
        
        try:
            pipeline = self._pending_pipeline
            event_count = self._pending_event_count
            
            self.statusBar.showMessage("Loading Artifacts Table...", 0)
            QApplication.processEvents()
            
            extracts = getattr(pipeline, 'extracted_artifacts', []) if pipeline else []
            if extracts:
                # Import path sanitizer for forensic integrity
                try:
                    from ..core.path_sanitizer import safe_path
                except ImportError:
                    def safe_path(path, component="unknown", evidence_mapping=None):
                        return Path(path).name if path else "[Protected]"
                
                self.artifacts_table.setUpdatesEnabled(False)
                self.artifacts_table.blockSignals(True)
                try:
                    self.artifacts_table.setRowCount(len(extracts))
                    for row, a in enumerate(extracts):
                        from PyQt6.QtWidgets import QTableWidgetItem
                        
                        # FORENSIC INTEGRITY: Display original evidence path, NOT analyzer path
                        original_path = getattr(a, 'original_path', None) or getattr(a, 'source_path', None)
                        if original_path:
                            display_path = str(original_path)
                        else:
                            display_path = Path(str(a.extracted_path)).name if a.extracted_path else "[Artifact]"
                        
                        self.artifacts_table.setItem(row, 0, QTableWidgetItem(a.artifact_type.value))
                        self.artifacts_table.setItem(row, 1, QTableWidgetItem(display_path))
                        self.artifacts_table.setItem(row, 2, QTableWidgetItem(str(a.size_bytes)))
                        self.artifacts_table.setItem(row, 3, QTableWidgetItem(a.sha256_hash))
                        self.artifacts_table.setItem(row, 4, QTableWidgetItem("Extracted"))
                        
                        # Process events every 100 rows to keep UI responsive
                        if row > 0 and row % 100 == 0:
                            QApplication.processEvents()
                finally:
                    self.artifacts_table.blockSignals(False)
                    self.artifacts_table.setUpdatesEnabled(True)
                
                self.logger.info(f"Updated artifacts table with {len(extracts)} artifacts")
                QApplication.processEvents()

                # Refresh non-timeline routed sections from latest normalized index.
                if self.case_workspace:
                    self._hydrate_tabs_from_unified_store(
                        self.case_workspace,
                        include_timeline=True,
                        rebuild_index=True,
                    )
                    self._refresh_artifacts_tab(self.case_workspace)
                    self._last_forensic_hydration_at = datetime.utcnow()
                    QApplication.processEvents()
                
                # Show success message
                self.statusBar.showMessage(f"✅ Analysis complete - {len(extracts)} artifacts, {event_count} events", 0)
                QApplication.processEvents()
                
                QMessageBox.information(
                    self,
                    "Analysis Complete",
                    f"Forensic analysis completed successfully!\n\n"
                    f"Artifacts found: {len(extracts)}\n"
                    f"Timeline events: {event_count}\n\n"
                    f"Results saved to case workspace."
                )
            else:
                self.logger.warning("No artifacts extracted to display")
                self._show_no_artifacts_message(event_count)
        except Exception as e:
            self.logger.error(f"Error in final step: {e}")
            self.statusBar.showMessage(f"Completed with errors: {e}", 10000)
        finally:
            # Clean up pending data
            self._pending_classified_df = None
            self._pending_pipeline = None
            self._pending_event_count = 0
            self._active_ingest_source_type = None
        
        # Check and restore session
        self._check_and_restore_session()
    
    def _show_no_artifacts_message(self, event_count):
        """Show diagnostic message when no artifacts found."""
        diagnostic_msg = (
            "The pipeline completed but no artifacts were discovered in the image.\n\n"
            "⚠ POSSIBLE CAUSES:\n\n"
            "1. MEMORY DUMP FILE (NOT A DISK IMAGE)\n"
            "   → Use FEPD Terminal → 'memscan <path>'\n\n"
            "2. NOT A WINDOWS FILESYSTEM\n"
            "   → FEPD focuses on Windows artifacts\n\n"
            "3. FILESYSTEM EXTRACTION FAILED\n"
            "   → Try opening in FTK Imager first\n\n"
            "4. IMAGE IS EMPTY OR CORRUPTED\n"
            "   → Verify image integrity\n\n"
            "🔍 Check Console/Logs for details"
        )
        QMessageBox.warning(self, "No Artifacts Found", diagnostic_msg)
    
    def _check_and_restore_session(self):
        """Check for existing session and prompt to restore."""
        if not self.session_manager or not self.session_manager.has_snapshot():
            return
        
        try:
            from .dialogs.restore_session_dialog import RestoreSessionDialog
            dialog = RestoreSessionDialog(str(self.case_path), self)
            if dialog.exec() == dialog.DialogCode.Accepted:
                # Restore session
                state = self.session_manager.load_session()
                self._apply_session_state(state)
                self.logger.info("Session restored")
                self.statusBar.showMessage("Session restored", 5000)
            else:
                # Delete snapshot if user chose fresh start
                self.session_manager.delete_snapshot()
                self.logger.info("Starting fresh - snapshot deleted")
        except Exception as e:
            self.logger.error(f"Failed to restore session: {e}", exc_info=True)
    
    def _apply_session_state(self, state: dict):
        """Apply restored session state to UI."""
        try:
            # Restore active tab
            if 'active_tab' in state and state['active_tab'] < self.tabs.count():
                self.tabs.setCurrentIndex(state['active_tab'])
                self.logger.info(f"Restored tab: {state['active_tab']}")
            
            # Restore scroll positions
            scroll_positions = state.get('scroll_positions', {})
            
            # Timeline scroll
            if 'timeline' in scroll_positions and hasattr(self, 'timeline_table'):
                scroll_value = scroll_positions['timeline']
                self.timeline_table.verticalScrollBar().setValue(scroll_value)
            
            # Artifacts scroll
            if 'artifacts' in scroll_positions and hasattr(self, 'artifacts_table'):
                scroll_value = scroll_positions['artifacts']
                self.artifacts_table.verticalScrollBar().setValue(scroll_value)
            
            # Files scroll
            if 'files' in scroll_positions and hasattr(self, 'file_metadata_table'):
                scroll_value = scroll_positions['files']
                self.file_metadata_table.verticalScrollBar().setValue(scroll_value)
            
            self.logger.info("Session state applied successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to apply session state: {e}", exc_info=True)
    
    def _get_current_state(self) -> dict:
        """Get current application state for session saving."""
        state = {
            'active_tab': self.tabs.currentIndex(),
            'scroll_positions': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Get scroll positions
        if hasattr(self, 'timeline_table'):
            state['scroll_positions']['timeline'] = self.timeline_table.verticalScrollBar().value()
        
        if hasattr(self, 'artifacts_table'):
            state['scroll_positions']['artifacts'] = self.artifacts_table.verticalScrollBar().value()
        
        if hasattr(self, 'file_metadata_table'):
            state['scroll_positions']['files'] = self.file_metadata_table.verticalScrollBar().value()
        
        return state
    
    def _save_session(self):
        """Save current session (toolbar action)."""
        if not self.session_manager:
            self.statusBar.showMessage("No active case", 3000)
            return
        
        state = self._get_current_state()
        if self.session_manager.save_session(state_dict=state):
            self.statusBar.showMessage("Session saved", 3000)
            self.logger.info("Session saved manually")
        else:
            self.statusBar.showMessage("Failed to save session", 3000)
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Auto-save session before closing
        if self.session_manager:
            state = self._get_current_state()
            self.session_manager.auto_save(state_dict=state)
            self.logger.info("Session auto-saved on close")
        
        # Save case state before closing
        if self.current_case:
            self._save_case_state()
        
        self.logger.info("Application closing")
        self.coc.log_event("APPLICATION_CLOSED", "FEPD application closed", severity="INFO")
        event.accept()

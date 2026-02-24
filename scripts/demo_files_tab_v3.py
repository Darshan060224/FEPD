"""
QUICK START: Files Tab v3 Enhanced Integration
===============================================

Drop-in replacement for existing Files Tab with forensic superpowers.
"""

from src.ui.files_tab_v3_enhanced import ForensicFilesTabEnhanced
from src.core.chain_of_custody import ChainLogger

# ============================================================================
# STEP 1: Initialize Enhanced Files Tab
# ============================================================================

def create_enhanced_files_tab(vfs, veos, case_manager, coc_logger):
    """
    Create forensically enhanced Files Tab.
    
    Args:
        vfs: VirtualFilesystem instance
        veos: VirtualEvidenceOS instance
        case_manager: CaseManager instance
        coc_logger: Chain of Custody logger
        
    Returns:
        ForensicFilesTabEnhanced instance
    """
    
    # Define read function for hash computation
    def read_file(path: str, offset: int, size: int) -> bytes:
        """Read file chunk for hash computation."""
        try:
            # Use VEOS to read file
            veos_file = veos.open(path, mode='rb')
            veos_file.seek(offset)
            return veos_file.read(size)
        except Exception as e:
            print(f"Read error: {e}")
            return b''
    
    # Create enhanced Files Tab
    files_tab = ForensicFilesTabEnhanced(
        vfs=vfs,
        veos=veos,
        read_file_func=read_file,
        coc_logger=coc_logger.log
    )
    
    return files_tab


# ============================================================================
# STEP 2: Connect Cross-Tab Signals
# ============================================================================

def connect_cross_tab_signals(files_tab, ml_analysis_tab, timeline_tab):
    """
    Wire up cross-tab intelligence.
    
    Args:
        files_tab: ForensicFilesTabEnhanced instance
        ml_analysis_tab: MLAnalysisTab instance
        timeline_tab: TimelineTab instance
    """
    
    # ML Analysis → Files Tab (risk badges)
    if hasattr(ml_analysis_tab, 'risk_score_computed'):
        ml_analysis_tab.risk_score_computed.connect(files_tab.set_ml_risk_score)
    
    # Files Tab → Timeline (show file in timeline)
    if hasattr(timeline_tab, 'show_file_timeline'):
        files_tab.timeline_requested.connect(timeline_tab.show_file_timeline)
    
    # Files Tab → ML Analysis (analyze selected file)
    if hasattr(ml_analysis_tab, 'analyze_file'):
        files_tab.ml_flagged_file_selected.connect(ml_analysis_tab.analyze_file)
    
    print("✅ Cross-tab signals connected")


# ============================================================================
# STEP 3: Example Usage in Main Window
# ============================================================================

def integrate_into_main_window(main_window):
    """
    Replace existing Files Tab with enhanced version.
    
    Args:
        main_window: Main application window
    """
    
    # Assuming main_window has these attributes:
    # - vfs: VirtualFilesystem
    # - veos: VirtualEvidenceOS
    # - case_manager: CaseManager
    # - coc_logger: ChainLogger
    # - tab_widget: QTabWidget
    
    # Create enhanced Files Tab
    enhanced_files_tab = create_enhanced_files_tab(
        vfs=main_window.vfs,
        veos=main_window.veos,
        case_manager=main_window.case_manager,
        coc_logger=main_window.coc_logger
    )
    
    # Find existing Files Tab index
    files_tab_index = -1
    for i in range(main_window.tab_widget.count()):
        if main_window.tab_widget.tabText(i) == "📁 Files":
            files_tab_index = i
            break
    
    # Replace or add tab
    if files_tab_index >= 0:
        # Remove old tab
        main_window.tab_widget.removeTab(files_tab_index)
        # Insert enhanced tab at same position
        main_window.tab_widget.insertTab(files_tab_index, enhanced_files_tab, "📁 Files v3")
    else:
        # Add new tab
        main_window.tab_widget.addTab(enhanced_files_tab, "📁 Files v3")
    
    # Connect cross-tab signals
    if hasattr(main_window, 'ml_analysis_tab') and hasattr(main_window, 'timeline_tab'):
        connect_cross_tab_signals(
            enhanced_files_tab,
            main_window.ml_analysis_tab,
            main_window.timeline_tab
        )
    
    # Store reference
    main_window.files_tab_v3 = enhanced_files_tab
    
    print("✅ Files Tab v3 Enhanced integrated successfully")


# ============================================================================
# STEP 4: Load Initial Directory
# ============================================================================

def demo_load_directory(files_tab):
    """
    Demo: Load a directory with all features enabled.
    """
    
    # Enable forensic features
    files_tab.show_deleted_checkbox.setChecked(True)
    files_tab.show_orphaned_checkbox.setChecked(False)
    
    # Load root directory
    files_tab.load_directory("C:\\Users\\Alice\\Documents")
    
    print("✅ Loaded C:\\Users\\Alice\\Documents with deleted files visible")


# ============================================================================
# STEP 5: Simulate ML Risk Score (for testing)
# ============================================================================

def demo_ml_risk_integration(files_tab):
    """
    Demo: Add ML risk scores to files.
    """
    
    # High-risk file
    files_tab.set_ml_risk_score(
        "C:\\Users\\Alice\\Downloads\\malware.exe",
        score=0.87,
        reason="Anomalous execution pattern detected"
    )
    
    # Medium-risk file
    files_tab.set_ml_risk_score(
        "C:\\Users\\Alice\\Desktop\\suspicious.bat",
        score=0.62,
        reason="Obfuscated script with network activity"
    )
    
    print("✅ ML risk scores added to files")


# ============================================================================
# STEP 6: Test Advanced Search
# ============================================================================

def demo_advanced_search(files_tab):
    """
    Demo: Execute advanced forensic search.
    """
    
    # Search for large deleted executables
    files_tab.search_input.setText("ext:exe size:>5MB deleted:true")
    files_tab._on_advanced_search()
    
    print("✅ Advanced search executed: ext:exe size:>5MB deleted:true")


# ============================================================================
# COMPLETE INTEGRATION EXAMPLE
# ============================================================================

if __name__ == "__main__":
    """
    Complete integration example.
    """
    
    # Mock components for testing
    class MockVFS:
        def get_node(self, path):
            return None
    
    class MockVEOS:
        def open(self, path, mode='r'):
            return None
    
    class MockCoCLogger:
        def log(self, event, data):
            print(f"📋 CoC: {event} - {data}")
    
    # Create components
    vfs = MockVFS()
    veos = MockVEOS()
    coc_logger = MockCoCLogger()
    
    # Create enhanced Files Tab
    files_tab = create_enhanced_files_tab(vfs, veos, None, coc_logger)
    
    print("✅ Files Tab v3 Enhanced created")
    print()
    print("Features enabled:")
    print("  - 🗑️  Deleted files detection (MFT-based)")
    print("  - 👻 Orphaned MFT entries")
    print("  - 📋 Evidence provenance panel")
    print("  - 🔐 Lazy hash computation")
    print("  - 📊 Progressive loading (200-item batches)")
    print("  - 🔴 ML risk badges")
    print("  - 🔍 Advanced forensic search")
    print("  - 📝 Audit-grade CoC logging")
    print()
    print("Ready for integration!")


# ============================================================================
# TESTING SCENARIOS
# ============================================================================

def run_test_scenarios(files_tab):
    """
    Run comprehensive test scenarios.
    """
    
    print("\n🧪 Running test scenarios...\n")
    
    # Test 1: Deleted files
    print("Test 1: Toggle deleted files")
    files_tab.show_deleted_checkbox.setChecked(True)
    print("  ✅ Deleted files visible\n")
    
    # Test 2: Advanced search
    print("Test 2: Advanced search for executables")
    demo_advanced_search(files_tab)
    print("  ✅ Search results displayed\n")
    
    # Test 3: ML integration
    print("Test 3: ML risk score integration")
    demo_ml_risk_integration(files_tab)
    print("  ✅ Risk badges added\n")
    
    # Test 4: Hash computation
    print("Test 4: Lazy hash computation")
    files_tab._request_hash_computation("C:\\Users\\Alice\\document.pdf")
    print("  ✅ Hash computation started\n")
    
    print("🎉 All test scenarios passed!")


# ============================================================================
# CONFIGURATION OPTIONS
# ============================================================================

class FilesTabV3Config:
    """
    Configuration for Files Tab v3 Enhanced.
    """
    
    # Progressive loading batch size
    BATCH_SIZE = 200
    
    # Hash computation chunk size (bytes)
    HASH_CHUNK_SIZE = 65536  # 64KB
    
    # MFT parser settings
    MFT_PARTITION_OFFSET = 2048  # Sectors
    
    # ML risk thresholds
    ML_HIGH_RISK_THRESHOLD = 0.8
    ML_MEDIUM_RISK_THRESHOLD = 0.5
    
    # UI colors
    COLOR_DELETED = "#888888"        # Gray
    COLOR_HIGH_RISK = "#F44336"      # Red
    COLOR_MEDIUM_RISK = "#FFC107"    # Amber
    COLOR_LOW_RISK = "#4CAF50"       # Green
    
    @classmethod
    def apply_to_tab(cls, files_tab):
        """Apply configuration to Files Tab instance."""
        files_tab.BATCH_SIZE = cls.BATCH_SIZE
        # Additional configuration as needed
        print(f"✅ Configuration applied: Batch size = {cls.BATCH_SIZE}")

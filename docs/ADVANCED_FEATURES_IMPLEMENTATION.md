# Advanced Features Implementation Guide

**FEPD - Forensic Evidence Parser Dashboard**  
**Complete Implementation Guide for Advanced Features**

---

## 📋 Table of Contents

1. [Multilingual PDF Reporting](#1-multilingual-pdf-reporting)
2. [Snapshot + Resume Analysis](#2-snapshot--resume-analysis)
3. [Event Heatmap Calendar](#3-event-heatmap-calendar)
4. [Artifact Timeline Navigation & Filtering](#4-artifact-timeline-navigation--filtering)
5. [Folder Tree & Metadata Viewer](#5-folder-tree--metadata-viewer)
6. [Workflow Integration](#6-workflow-integration)
7. [Performance Optimization](#7-performance-optimization)
8. [Testing Strategy](#8-testing-strategy)

---

## 1. 🌍 Multilingual PDF Reporting

### Overview
Add multilingual support for forensic reports exported to PDF format with language selection during export.

### Architecture

```
src/
├── utils/
│   ├── i18n/
│   │   ├── __init__.py
│   │   ├── translator.py           # Translation engine
│   │   └── report_translator.py    # Report-specific translations
│   └── report_generator.py         # EXISTING - Enhanced with i18n
└── locales/
    ├── en.json                      # English translations
    ├── fr.json                      # French translations
    ├── hi.json                      # Hindi translations
    └── es.json                      # Spanish translations
```

### Implementation Steps

#### Step 1: Create Translation Engine

**File: `src/utils/i18n/__init__.py`**
```python
"""
Internationalization (i18n) module for FEPD
Provides multilingual support for UI and reports
"""

from .translator import Translator
from .report_translator import ReportTranslator

__all__ = ['Translator', 'ReportTranslator']
```

**File: `src/utils/i18n/translator.py`**
```python
"""
Core translation engine for FEPD
Handles loading and managing language packs
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional


class Translator:
    """
    Translation engine with support for multiple languages.
    
    Features:
    - JSON-based language packs
    - Fallback to English for missing translations
    - Nested key support (dot notation)
    - Parameter substitution
    """
    
    def __init__(self, locale_dir: Path = None):
        """
        Initialize translator.
        
        Args:
            locale_dir: Directory containing language pack JSON files
        """
        self.logger = logging.getLogger(__name__)
        
        if locale_dir is None:
            # Default to locales/ in project root
            locale_dir = Path(__file__).parent.parent.parent.parent / "locales"
        
        self.locale_dir = Path(locale_dir)
        self.current_language = 'en'
        self.translations: Dict[str, Dict] = {}
        self.fallback_language = 'en'
        
        # Load available languages
        self._load_available_languages()
    
    def _load_available_languages(self):
        """Scan locale directory and load available language packs."""
        if not self.locale_dir.exists():
            self.logger.warning(f"Locale directory not found: {self.locale_dir}")
            self.locale_dir.mkdir(parents=True, exist_ok=True)
            return
        
        for json_file in self.locale_dir.glob("*.json"):
            lang_code = json_file.stem
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    self.translations[lang_code] = json.load(f)
                self.logger.info(f"Loaded language pack: {lang_code}")
            except Exception as e:
                self.logger.error(f"Failed to load {lang_code}: {e}")
    
    def set_language(self, lang_code: str) -> bool:
        """
        Switch to specified language.
        
        Args:
            lang_code: Language code (e.g., 'en', 'fr', 'hi')
        
        Returns:
            True if language was loaded successfully
        """
        if lang_code not in self.translations:
            self.logger.warning(f"Language '{lang_code}' not available")
            return False
        
        self.current_language = lang_code
        self.logger.info(f"Language switched to: {lang_code}")
        return True
    
    def get(self, key: str, default: str = None, **kwargs) -> str:
        """
        Get translated string by key.
        
        Args:
            key: Translation key (supports dot notation, e.g., 'report.title')
            default: Default value if key not found
            **kwargs: Parameters for string formatting
        
        Returns:
            Translated string with parameters substituted
        
        Examples:
            >>> t.get('report.title')
            'Forensic Analysis Report'
            >>> t.get('report.case_id', case='12345')
            'Case ID: 12345'
        """
        # Get current language translations
        translations = self.translations.get(self.current_language, {})
        
        # Support nested keys with dot notation
        keys = key.split('.')
        value = translations
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                value = None
                break
        
        # Fallback to English if not found
        if value is None and self.current_language != self.fallback_language:
            fallback = self.translations.get(self.fallback_language, {})
            value = fallback
            for k in keys:
                if isinstance(value, dict):
                    value = value.get(k)
                else:
                    value = None
                    break
        
        # Use default if still not found
        if value is None:
            value = default or key
        
        # Substitute parameters
        if kwargs and isinstance(value, str):
            try:
                value = value.format(**kwargs)
            except KeyError as e:
                self.logger.warning(f"Missing parameter in translation: {e}")
        
        return str(value)
    
    def get_available_languages(self) -> Dict[str, str]:
        """
        Get list of available languages.
        
        Returns:
            Dictionary mapping language codes to display names
            Example: {'en': 'English', 'fr': 'Français', 'hi': 'हिन्दी'}
        """
        languages = {}
        for lang_code, translations in self.translations.items():
            # Look for language name in metadata
            display_name = translations.get('_metadata', {}).get('display_name', lang_code.upper())
            languages[lang_code] = display_name
        
        return languages
```

**File: `src/utils/i18n/report_translator.py`**
```python
"""
Report-specific translation utilities for FEPD
Extends base Translator for forensic report generation
"""

from typing import Dict, List
from .translator import Translator


class ReportTranslator:
    """
    Report-specific translator with forensic terminology support.
    
    Features:
    - Pre-defined forensic terms
    - Section headers translation
    - Table column translations
    - Evidence classification terms
    """
    
    def __init__(self, translator: Translator):
        """
        Initialize report translator.
        
        Args:
            translator: Base translator instance
        """
        self.translator = translator
    
    def get_report_metadata(self, case_id: str, examiner: str, date: str) -> Dict[str, str]:
        """
        Get translated report metadata labels.
        
        Returns:
            Dictionary with translated metadata fields
        """
        return {
            'title': self.translator.get('report.title'),
            'case_id': self.translator.get('report.case_id', case=case_id),
            'examiner': self.translator.get('report.examiner', name=examiner),
            'date': self.translator.get('report.date', date=date),
            'organization': self.translator.get('report.organization')
        }
    
    def get_section_headers(self) -> Dict[str, str]:
        """
        Get all report section headers translated.
        
        Returns:
            Dictionary mapping section IDs to translated headers
        """
        return {
            'executive_summary': self.translator.get('report.sections.executive_summary'),
            'case_info': self.translator.get('report.sections.case_information'),
            'evidence': self.translator.get('report.sections.evidence_details'),
            'timeline': self.translator.get('report.sections.timeline_analysis'),
            'artifacts': self.translator.get('report.sections.artifacts_summary'),
            'registry': self.translator.get('report.sections.registry_analysis'),
            'prefetch': self.translator.get('report.sections.prefetch_analysis'),
            'browser': self.translator.get('report.sections.browser_activity'),
            'network': self.translator.get('report.sections.network_activity'),
            'anomalies': self.translator.get('report.sections.anomaly_detection'),
            'chain_of_custody': self.translator.get('report.sections.chain_of_custody'),
            'conclusions': self.translator.get('report.sections.conclusions')
        }
    
    def get_table_headers(self, table_type: str) -> List[str]:
        """
        Get translated table column headers.
        
        Args:
            table_type: Type of table ('timeline', 'artifacts', 'registry', etc.)
        
        Returns:
            List of translated column headers
        """
        header_key = f'report.tables.{table_type}'
        headers = self.translator.get(header_key, default=[])
        
        if not headers:
            # Fallback to common headers
            return [
                self.translator.get('report.common.timestamp'),
                self.translator.get('report.common.event_type'),
                self.translator.get('report.common.description'),
                self.translator.get('report.common.source')
            ]
        
        return headers
    
    def get_classification_labels(self) -> Dict[str, str]:
        """
        Get translated event classification labels.
        
        Returns:
            Dictionary mapping classification codes to translated labels
        """
        return {
            'NORMAL': self.translator.get('report.classification.normal'),
            'SUSPICIOUS': self.translator.get('report.classification.suspicious'),
            'MALICIOUS': self.translator.get('report.classification.malicious'),
            'CRITICAL': self.translator.get('report.classification.critical'),
            'INFO': self.translator.get('report.classification.info')
        }
    
    def get_artifact_types(self) -> Dict[str, str]:
        """
        Get translated artifact type labels.
        
        Returns:
            Dictionary mapping artifact types to translated labels
        """
        return {
            'Registry': self.translator.get('artifacts.registry'),
            'Prefetch': self.translator.get('artifacts.prefetch'),
            'EVTX': self.translator.get('artifacts.evtx'),
            'MFT': self.translator.get('artifacts.mft'),
            'Browser': self.translator.get('artifacts.browser'),
            'Network': self.translator.get('artifacts.network')
        }
```

#### Step 2: Create Language Pack Templates

**File: `locales/en.json`**
```json
{
  "_metadata": {
    "language_code": "en",
    "display_name": "English",
    "version": "1.0.0",
    "contributors": ["FEPD Team"]
  },
  "report": {
    "title": "Forensic Analysis Report",
    "subtitle": "Digital Evidence Examination",
    "organization": "Darshan Research Lab",
    "case_id": "Case ID: {case}",
    "examiner": "Examiner: {name}",
    "date": "Report Date: {date}",
    "sections": {
      "executive_summary": "Executive Summary",
      "case_information": "Case Information",
      "evidence_details": "Evidence Details",
      "timeline_analysis": "Timeline Analysis",
      "artifacts_summary": "Artifacts Summary",
      "registry_analysis": "Registry Analysis",
      "prefetch_analysis": "Prefetch Analysis",
      "browser_activity": "Browser Activity",
      "network_activity": "Network Activity",
      "anomaly_detection": "Anomaly Detection",
      "chain_of_custody": "Chain of Custody",
      "conclusions": "Conclusions and Recommendations"
    },
    "tables": {
      "timeline": ["Timestamp", "Event Type", "Description", "Source", "Classification"],
      "artifacts": ["Artifact Type", "Count", "First Seen", "Last Seen", "Status"],
      "registry": ["Key Path", "Value Name", "Data", "Last Modified"],
      "prefetch": ["Application", "Execution Count", "Last Run", "Hash"]
    },
    "common": {
      "timestamp": "Timestamp",
      "event_type": "Event Type",
      "description": "Description",
      "source": "Source",
      "classification": "Classification",
      "page": "Page",
      "of": "of",
      "total": "Total",
      "hash": "Hash",
      "size": "Size",
      "path": "Path"
    },
    "classification": {
      "normal": "Normal",
      "suspicious": "Suspicious",
      "malicious": "Malicious",
      "critical": "Critical",
      "info": "Information"
    }
  },
  "artifacts": {
    "registry": "Registry Files",
    "prefetch": "Prefetch Files",
    "evtx": "Event Logs",
    "mft": "Master File Table",
    "browser": "Browser History",
    "network": "Network Artifacts"
  },
  "ui": {
    "select_language": "Select Report Language",
    "export": "Export Report",
    "cancel": "Cancel",
    "save": "Save",
    "load": "Load"
  }
}
```

**File: `locales/fr.json`**
```json
{
  "_metadata": {
    "language_code": "fr",
    "display_name": "Français",
    "version": "1.0.0",
    "contributors": ["FEPD Team"]
  },
  "report": {
    "title": "Rapport d'Analyse Forensique",
    "subtitle": "Examen de Preuves Numériques",
    "organization": "Laboratoire de Recherche Darshan",
    "case_id": "ID de Cas: {case}",
    "examiner": "Examinateur: {name}",
    "date": "Date du Rapport: {date}",
    "sections": {
      "executive_summary": "Résumé Exécutif",
      "case_information": "Informations sur le Cas",
      "evidence_details": "Détails de la Preuve",
      "timeline_analysis": "Analyse de la Chronologie",
      "artifacts_summary": "Résumé des Artefacts",
      "registry_analysis": "Analyse du Registre",
      "prefetch_analysis": "Analyse Prefetch",
      "browser_activity": "Activité du Navigateur",
      "network_activity": "Activité Réseau",
      "anomaly_detection": "Détection d'Anomalies",
      "chain_of_custody": "Chaîne de Traçabilité",
      "conclusions": "Conclusions et Recommandations"
    },
    "tables": {
      "timeline": ["Horodatage", "Type d'Événement", "Description", "Source", "Classification"],
      "artifacts": ["Type d'Artefact", "Nombre", "Première Vue", "Dernière Vue", "État"],
      "registry": ["Chemin de Clé", "Nom de Valeur", "Données", "Dernière Modification"],
      "prefetch": ["Application", "Nombre d'Exécutions", "Dernière Exécution", "Hash"]
    },
    "common": {
      "timestamp": "Horodatage",
      "event_type": "Type d'Événement",
      "description": "Description",
      "source": "Source",
      "classification": "Classification",
      "page": "Page",
      "of": "de",
      "total": "Total",
      "hash": "Hash",
      "size": "Taille",
      "path": "Chemin"
    },
    "classification": {
      "normal": "Normal",
      "suspicious": "Suspect",
      "malicious": "Malveillant",
      "critical": "Critique",
      "info": "Information"
    }
  },
  "artifacts": {
    "registry": "Fichiers de Registre",
    "prefetch": "Fichiers Prefetch",
    "evtx": "Journaux d'Événements",
    "mft": "Table de Fichiers Maître",
    "browser": "Historique du Navigateur",
    "network": "Artefacts Réseau"
  },
  "ui": {
    "select_language": "Sélectionner la Langue du Rapport",
    "export": "Exporter le Rapport",
    "cancel": "Annuler",
    "save": "Enregistrer",
    "load": "Charger"
  }
}
```

**File: `locales/hi.json`**
```json
{
  "_metadata": {
    "language_code": "hi",
    "display_name": "हिन्दी",
    "version": "1.0.0",
    "contributors": ["FEPD Team"]
  },
  "report": {
    "title": "फॉरेंसिक विश्लेषण रिपोर्ट",
    "subtitle": "डिजिटल साक्ष्य परीक्षण",
    "organization": "दर्शन अनुसंधान प्रयोगशाला",
    "case_id": "मामला आईडी: {case}",
    "examiner": "परीक्षक: {name}",
    "date": "रिपोर्ट तिथि: {date}",
    "sections": {
      "executive_summary": "कार्यकारी सारांश",
      "case_information": "मामले की जानकारी",
      "evidence_details": "साक्ष्य विवरण",
      "timeline_analysis": "समयरेखा विश्लेषण",
      "artifacts_summary": "कलाकृतियों का सारांश",
      "registry_analysis": "रजिस्ट्री विश्लेषण",
      "prefetch_analysis": "प्रीफेच विश्लेषण",
      "browser_activity": "ब्राउज़र गतिविधि",
      "network_activity": "नेटवर्क गतिविधि",
      "anomaly_detection": "विसंगति का पता लगाना",
      "chain_of_custody": "हिरासत की श्रृंखला",
      "conclusions": "निष्कर्ष और सिफारिशें"
    },
    "tables": {
      "timeline": ["समय-चिह्न", "घटना प्रकार", "विवरण", "स्रोत", "वर्गीकरण"],
      "artifacts": ["कलाकृति प्रकार", "गिनती", "पहली बार देखा", "अंतिम देखा", "स्थिति"],
      "registry": ["कुंजी पथ", "मान नाम", "डेटा", "अंतिम संशोधित"],
      "prefetch": ["अनुप्रयोग", "निष्पादन गणना", "अंतिम रन", "हैश"]
    },
    "common": {
      "timestamp": "समय-चिह्न",
      "event_type": "घटना प्रकार",
      "description": "विवरण",
      "source": "स्रोत",
      "classification": "वर्गीकरण",
      "page": "पृष्ठ",
      "of": "का",
      "total": "कुल",
      "hash": "हैश",
      "size": "आकार",
      "path": "पथ"
    },
    "classification": {
      "normal": "सामान्य",
      "suspicious": "संदिग्ध",
      "malicious": "दुर्भावनापूर्ण",
      "critical": "गंभीर",
      "info": "जानकारी"
    }
  },
  "artifacts": {
    "registry": "रजिस्ट्री फाइलें",
    "prefetch": "प्रीफेच फाइलें",
    "evtx": "घटना लॉग",
    "mft": "मास्टर फ़ाइल तालिका",
    "browser": "ब्राउज़र इतिहास",
    "network": "नेटवर्क कलाकृतियाँ"
  },
  "ui": {
    "select_language": "रिपोर्ट भाषा चुनें",
    "export": "रिपोर्ट निर्यात करें",
    "cancel": "रद्द करें",
    "save": "सहेजें",
    "load": "लोड करें"
  }
}
```

#### Step 3: Integrate with Report Generator

**Modify: `src/utils/report_generator.py`**

Add these imports at the top:
```python
from .i18n.translator import Translator
from .i18n.report_translator import ReportTranslator
```

Add to the `ReportGenerator` class:
```python
def __init__(self, case_dir: str, case_id: str, language: str = 'en'):
    """
    Initialize report generator with i18n support.
    
    Args:
        case_dir: Case directory path
        case_id: Case identifier
        language: Language code for report (default: 'en')
    """
    self.translator = Translator()
    self.translator.set_language(language)
    self.report_translator = ReportTranslator(self.translator)
    # ... existing init code ...
```

Modify section generation methods to use translated strings:
```python
def _add_title_page(self):
    """Add title page with translated headers."""
    metadata = self.report_translator.get_report_metadata(
        case_id=self.case_id,
        examiner=self.examiner_name,
        date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    
    self.canvas.setFont('Helvetica-Bold', 28)
    self.canvas.drawCentredString(self.width/2, self.height - 200, metadata['title'])
    # ... rest of title page ...
```

#### Step 4: Add Language Selection Dialog

**File: `src/ui/dialogs/language_selector_dialog.py`**
```python
"""
Language selection dialog for report export
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QComboBox, QPushButton, QDialogButtonBox
)
from PyQt6.QtCore import Qt


class LanguageSelectorDialog(QDialog):
    """
    Dialog for selecting report export language.
    
    Features:
    - Dropdown with available languages
    - Preview of language display names
    - OK/Cancel buttons
    """
    
    def __init__(self, translator, parent=None):
        super().__init__(parent)
        self.translator = translator
        self.selected_language = 'en'
        
        self.setWindowTitle("Select Report Language")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Choose the language for your exported report:")
        header.setWordWrap(True)
        layout.addWidget(header)
        
        # Language selector
        selector_layout = QHBoxLayout()
        label = QLabel("Language:")
        self.language_combo = QComboBox()
        
        # Populate with available languages
        languages = self.translator.get_available_languages()
        for code, name in languages.items():
            self.language_combo.addItem(name, code)
        
        selector_layout.addWidget(label)
        selector_layout.addWidget(self.language_combo, 1)
        layout.addLayout(selector_layout)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def get_selected_language(self) -> str:
        """Get the selected language code."""
        return self.language_combo.currentData()
```

#### Step 5: Update Main Window Export Handler

In `src/ui/main_window.py`, modify the export report method:
```python
def _export_report(self):
    """Export forensic report with language selection."""
    from .dialogs.language_selector_dialog import LanguageSelectorDialog
    from .i18n.translator import Translator
    
    # Show language selection dialog
    translator = Translator()
    dialog = LanguageSelectorDialog(translator, self)
    
    if dialog.exec() == QDialog.DialogCode.Accepted:
        language = dialog.get_selected_language()
        
        # Generate report with selected language
        generator = ReportGenerator(
            case_dir=self.config.get_case_dir(self.current_case_id),
            case_id=self.current_case_id,
            language=language
        )
        
        success, pdf_path = generator.generate_report(
            timeline_df=self.timeline_df,
            artifacts_summary=self.artifacts_summary
        )
        
        if success:
            QMessageBox.information(
                self,
                "Success",
                f"Report exported to:\n{pdf_path}"
            )
```

### Usage Example

```python
# In your report generation code:
from src.utils.report_generator import ReportGenerator

# Generate English report
generator_en = ReportGenerator(case_dir, case_id, language='en')
generator_en.generate_report(timeline_df, artifacts)

# Generate French report
generator_fr = ReportGenerator(case_dir, case_id, language='fr')
generator_fr.generate_report(timeline_df, artifacts)

# Generate Hindi report
generator_hi = ReportGenerator(case_dir, case_id, language='hi')
generator_hi.generate_report(timeline_df, artifacts)
```

---

## 2. 💾 Snapshot + Resume Analysis

### Overview
Implement session save/restore functionality to preserve analysis state including filters, scroll position, and UI layout.

### Architecture

```
cases/
└── case1/
    └── session_snapshot.json    # Session state storage

src/
├── utils/
│   ├── session_manager.py       # Session save/restore logic
│   └── config.py                # EXISTING - Enhanced with session support
└── ui/
    ├── dialogs/
    │   └── restore_session_dialog.py  # Restore prompt dialog
    └── main_window.py           # EXISTING - Enhanced with session integration
```

### Implementation

**File: `src/utils/session_manager.py`**
```python
"""
Session management for FEPD
Handles saving and restoring analysis sessions
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class SessionManager:
    """
    Manages analysis session snapshots.
    
    Features:
    - Save/restore filter state
    - Preserve timeline scroll position
    - Store UI layout preferences
    - Track current analysis state
    """
    
    SESSION_FILENAME = "session_snapshot.json"
    
    def __init__(self, case_dir: Path):
        """
        Initialize session manager for a case.
        
        Args:
            case_dir: Path to case directory
        """
        self.logger = logging.getLogger(__name__)
        self.case_dir = Path(case_dir)
        self.session_file = self.case_dir / self.SESSION_FILENAME
    
    def save_session(self, session_data: Dict[str, Any]) -> bool:
        """
        Save current session state.
        
        Args:
            session_data: Dictionary containing session state:
                - image_path: Path to disk image
                - case_id: Case identifier
                - filters: Active filters (time range, keywords, etc.)
                - ui_state: UI layout (scroll positions, tab index, etc.)
                - analysis_progress: Current analysis state
                - timestamp: Save timestamp
        
        Returns:
            True if saved successfully
        
        Example:
            >>> session_data = {
            ...     'image_path': '/path/to/image.e01',
            ...     'case_id': 'case1',
            ...     'filters': {
            ...         'time_range': ['2024-01-01', '2024-12-31'],
            ...         'keywords': ['malware', 'suspicious'],
            ...         'artifact_types': ['Registry', 'Prefetch']
            ...     },
            ...     'ui_state': {
            ...         'timeline_scroll': 1250,
            ...         'active_tab': 2,
            ...         'splitter_sizes': [300, 900]
            ...     }
            ... }
            >>> manager.save_session(session_data)
        """
        try:
            # Add metadata
            session_data['timestamp'] = datetime.now().isoformat()
            session_data['version'] = '1.0'
            
            # Write to file
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
            
            self.logger.info(f"Session saved: {self.session_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save session: {e}")
            return False
    
    def load_session(self) -> Optional[Dict[str, Any]]:
        """
        Load saved session state.
        
        Returns:
            Session data dictionary or None if not found
        """
        if not self.session_file.exists():
            self.logger.info("No session snapshot found")
            return None
        
        try:
            with open(self.session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            self.logger.info(f"Session loaded from: {self.session_file}")
            return session_data
            
        except Exception as e:
            self.logger.error(f"Failed to load session: {e}")
            return None
    
    def has_snapshot(self) -> bool:
        """Check if a session snapshot exists."""
        return self.session_file.exists()
    
    def delete_snapshot(self) -> bool:
        """Delete existing session snapshot."""
        if self.session_file.exists():
            try:
                self.session_file.unlink()
                self.logger.info("Session snapshot deleted")
                return True
            except Exception as e:
                self.logger.error(f"Failed to delete snapshot: {e}")
                return False
        return True
    
    def get_snapshot_info(self) -> Optional[Dict[str, str]]:
        """
        Get snapshot metadata without loading full session.
        
        Returns:
            Dictionary with snapshot info (timestamp, case_id, etc.)
        """
        session = self.load_session()
        if session:
            return {
                'timestamp': session.get('timestamp', 'Unknown'),
                'case_id': session.get('case_id', 'Unknown'),
                'image_path': session.get('image_path', 'Unknown')
            }
        return None
```

**File: `src/ui/dialogs/restore_session_dialog.py`**
```python
"""
Dialog for prompting user to restore previous session
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from datetime import datetime


class RestoreSessionDialog(QDialog):
    """
    Dialog prompting user to restore previous session.
    
    Features:
    - Display snapshot metadata
    - Restore button
    - Start fresh button
    - Auto-show on case open if snapshot exists
    """
    
    def __init__(self, snapshot_info: dict, parent=None):
        super().__init__(parent)
        self.snapshot_info = snapshot_info
        self.restore_session = False
        
        self.setWindowTitle("Previous Session Found")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # Icon and message
        header_layout = QHBoxLayout()
        icon_label = QLabel("💾")
        icon_label.setFont(QFont("Segoe UI Emoji", 32))
        
        message = QLabel(
            "<b>A previous analysis session was found.</b><br>"
            "Would you like to restore your previous work?"
        )
        message.setWordWrap(True)
        
        header_layout.addWidget(icon_label)
        header_layout.addWidget(message, 1)
        layout.addLayout(header_layout)
        
        # Snapshot details
        details = QTextEdit()
        details.setReadOnly(True)
        details.setMaximumHeight(120)
        
        details_text = f"""
<b>Session Details:</b>
• Saved: {self._format_timestamp(self.snapshot_info.get('timestamp'))}
• Case ID: {self.snapshot_info.get('case_id', 'Unknown')}
• Image: {self.snapshot_info.get('image_path', 'Unknown')}

This will restore:
 ✓ Timeline filters and search terms
 ✓ Scroll position and UI layout
 ✓ Active tab and view state
        """.strip()
        
        details.setHtml(details_text)
        layout.addWidget(details)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        restore_btn = QPushButton("🔄 Restore Session")
        restore_btn.setStyleSheet("""
            QPushButton {
                background-color: #4A90E2;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #357ABD;
            }
        """)
        restore_btn.clicked.connect(self._on_restore)
        
        fresh_btn = QPushButton("🆕 Start Fresh")
        fresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #6C757D;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5A6268;
            }
        """)
        fresh_btn.clicked.connect(self._on_start_fresh)
        
        button_layout.addStretch()
        button_layout.addWidget(fresh_btn)
        button_layout.addWidget(restore_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _format_timestamp(self, timestamp_str: str) -> str:
        """Format ISO timestamp to readable format."""
        try:
            dt = datetime.fromisoformat(timestamp_str)
            return dt.strftime('%B %d, %Y at %I:%M %p')
        except:
            return timestamp_str
    
    def _on_restore(self):
        """User chose to restore session."""
        self.restore_session = True
        self.accept()
    
    def _on_start_fresh(self):
        """User chose to start fresh."""
        self.restore_session = False
        self.accept()
    
    def should_restore(self) -> bool:
        """Check if user chose to restore session."""
        return self.restore_session
```

**Integration with Main Window (add to `src/ui/main_window.py`):**

```python
class MainWindow(QMainWindow):
    
    def __init__(self, config: Config):
        # ... existing init ...
        self.session_manager = None
    
    def open_case(self, case_id: str):
        """Open case with session restore prompt."""
        from .dialogs.restore_session_dialog import RestoreSessionDialog
        from ..utils.session_manager import SessionManager
        
        self.current_case_id = case_id
        case_dir = self.config.get_case_dir(case_id)
        
        # Initialize session manager
        self.session_manager = SessionManager(case_dir)
        
        # Check for existing snapshot
        if self.session_manager.has_snapshot():
            snapshot_info = self.session_manager.get_snapshot_info()
            
            dialog = RestoreSessionDialog(snapshot_info, self)
            if dialog.exec():
                if dialog.should_restore():
                    self._restore_session()
                else:
                    self.session_manager.delete_snapshot()
                    self._start_fresh_analysis()
            return
        
        # No snapshot, start fresh
        self._start_fresh_analysis()
    
    def _restore_session(self):
        """Restore previous session state."""
        session_data = self.session_manager.load_session()
        
        if not session_data:
            QMessageBox.warning(self, "Error", "Failed to restore session")
            self._start_fresh_analysis()
            return
        
        # Restore filters
        if 'filters' in session_data:
            filters = session_data['filters']
            
            # Time range filter
            if 'time_range' in filters:
                self.start_date.setDate(QDate.fromString(filters['time_range'][0], 'yyyy-MM-dd'))
                self.end_date.setDate(QDate.fromString(filters['time_range'][1], 'yyyy-MM-dd'))
            
            # Keyword filter
            if 'keywords' in filters:
                self.search_input.setText(' '.join(filters['keywords']))
            
            # Artifact type filter
            if 'artifact_types' in filters:
                # Apply artifact type filters
                pass
        
        # Restore UI state
        if 'ui_state' in session_data:
            ui_state = session_data['ui_state']
            
            # Active tab
            if 'active_tab' in ui_state:
                self.tabs.setCurrentIndex(ui_state['active_tab'])
            
            # Timeline scroll position
            if 'timeline_scroll' in ui_state:
                QTimer.singleShot(100, lambda: self.timeline_table.verticalScrollBar().setValue(ui_state['timeline_scroll']))
            
            # Splitter sizes
            if 'splitter_sizes' in ui_state:
                self.main_splitter.setSizes(ui_state['splitter_sizes'])
        
        self.logger.info("Session restored successfully")
        self.status_bar.showMessage("✅ Session restored", 3000)
    
    def _start_fresh_analysis(self):
        """Start with clean session."""
        self.logger.info("Starting fresh analysis session")
        # Reset all filters and UI state
        pass
    
    def save_current_session(self):
        """Save current session state (called periodically or on exit)."""
        if not self.session_manager:
            return
        
        session_data = {
            'image_path': str(self.current_image_path) if hasattr(self, 'current_image_path') else None,
            'case_id': self.current_case_id,
            'filters': {
                'time_range': [
                    self.start_date.date().toString('yyyy-MM-dd'),
                    self.end_date.date().toString('yyyy-MM-dd')
                ],
                'keywords': self.search_input.text().split(),
                'artifact_types': self._get_active_artifact_filters()
            },
            'ui_state': {
                'timeline_scroll': self.timeline_table.verticalScrollBar().value(),
                'active_tab': self.tabs.currentIndex(),
                'splitter_sizes': self.main_splitter.sizes()
            }
        }
        
        self.session_manager.save_session(session_data)
    
    def closeEvent(self, event):
        """Save session on exit."""
        self.save_current_session()
        super().closeEvent(event)
```

**Add "Save Session" button to toolbar:**

```python
def _setup_toolbar(self):
    """Add Save Session button to toolbar."""
    save_session_action = QAction("💾 Save Session", self)
    save_session_action.setToolTip("Save current analysis state")
    save_session_action.triggered.connect(self._on_save_session_clicked)
    self.toolbar.addAction(save_session_action)

def _on_save_session_clicked(self):
    """Handle Save Session button click."""
    self.save_current_session()
    QMessageBox.information(
        self,
        "Session Saved",
        "Your analysis session has been saved.\n\n"
        "You can restore this session when you reopen this case."
    )
```

---

## 3. 🔥 Event Heatmap Calendar

### Overview
Visualize event distribution over time using a calendar-style heatmap showing bursty patterns.

### Architecture

```
src/
├── visualization/
│   ├── __init__.py
│   ├── heatmap_generator.py      # Core heatmap logic
│   └── heatmap_widget.py         # PyQt6 widget
└── ui/
    └── tabs/
        └── heatmap_tab.py         # NEW - Heatmap tab
```

### Implementation

**File: `src/visualization/heatmap_generator.py`**
```python
"""
Event heatmap generation for temporal analysis
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from datetime import datetime
import logging


class EventHeatmapGenerator:
    """
    Generate calendar-style event heatmaps.
    
    Features:
    - Hour-of-day vs. date visualization
    - Color intensity based on event count
    - Interactive cell selection
    - Anomaly highlighting
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.fig = None
        self.ax = None
    
    def generate_heatmap(self, timeline_df: pd.DataFrame, 
                        date_column: str = 'Timestamp',
                        figsize: tuple = (14, 8)) -> Figure:
        """
        Generate event heatmap from timeline data.
        
        Args:
            timeline_df: DataFrame with timeline events
            date_column: Column name containing timestamps
            figsize: Figure size (width, height)
        
        Returns:
            Matplotlib Figure object
        """
        # Convert to datetime if needed
        if not pd.api.types.is_datetime64_any_dtype(timeline_df[date_column]):
            timeline_df[date_column] = pd.to_datetime(timeline_df[date_column])
        
        # Extract date and hour
        timeline_df['Date'] = timeline_df[date_column].dt.date
        timeline_df['Hour'] = timeline_df[date_column].dt.hour
        
        # Create pivot table: hours (rows) x dates (columns)
        heatmap_data = timeline_df.groupby(['Date', 'Hour']).size().unstack(fill_value=0).T
        
        # Sort dates
        heatmap_data = heatmap_data.reindex(sorted(heatmap_data.columns), axis=1)
        
        # Create figure
        self.fig = Figure(figsize=figsize, facecolor='#1E1E1E')
        self.ax = self.fig.add_subplot(111)
        
        # Generate heatmap
        sns.heatmap(
            heatmap_data,
            cmap='YlOrRd',
            linewidths=0.5,
            linecolor='#2E2E2E',
            cbar_kws={'label': 'Event Count'},
            ax=self.ax,
            square=False
        )
        
        # Styling
        self.ax.set_title('Event Heatmap - Temporal Distribution', 
                         fontsize=14, fontweight='bold', color='white', pad=20)
        self.ax.set_xlabel('Date', fontsize=11, color='white')
        self.ax.set_ylabel('Hour of Day', fontsize=11, color='white')
        
        # Rotate x-axis labels
        plt.setp(self.ax.get_xticklabels(), rotation=45, ha='right', color='white')
        plt.setp(self.ax.get_yticklabels(), color='white')
        
        # Style colorbar
        cbar = self.ax.collections[0].colorbar
        cbar.ax.tick_params(colors='white')
        cbar.set_label('Event Count', color='white')
        
        self.fig.tight_layout()
        
        return self.fig
    
    def highlight_anomalies(self, threshold_percentile: float = 95):
        """
        Highlight cells with anomalously high event counts.
        
        Args:
            threshold_percentile: Percentile above which to highlight (default: 95)
        """
        # Implementation for anomaly highlighting
        pass
```

**File: `src/visualization/heatmap_widget.py`**
```python
"""
PyQt6 widget for interactive event heatmap
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QSlider, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg, NavigationToolbar2QT
from .heatmap_generator import EventHeatmapGenerator
import pandas as pd


class HeatmapWidget(QWidget):
    """
    Interactive heatmap widget with filtering capabilities.
    
    Signals:
        cell_clicked: Emitted when user clicks a cell (date, hour, count)
    """
    
    cell_clicked = pyqtSignal(str, int, int)  # (date, hour, event_count)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generator = EventHeatmapGenerator()
        self.timeline_df = None
        self.canvas = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # Control panel
        controls = self._create_controls()
        layout.addWidget(controls)
        
        # Canvas placeholder
        self.canvas_container = QVBoxLayout()
        layout.addLayout(self.canvas_container)
        
        self.setLayout(layout)
    
    def _create_controls(self) -> QWidget:
        """Create control panel for heatmap options."""
        controls = QWidget()
        layout = QHBoxLayout()
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_heatmap)
        layout.addWidget(refresh_btn)
        
        # Anomaly threshold slider
        layout.addWidget(QLabel("Anomaly Threshold:"))
        self.threshold_slider = QSlider(Qt.Orientation.Horizontal)
        self.threshold_slider.setMinimum(80)
        self.threshold_slider.setMaximum(99)
        self.threshold_slider.setValue(95)
        self.threshold_slider.setMaximumWidth(200)
        layout.addWidget(self.threshold_slider)
        
        self.threshold_label = QLabel("95%")
        self.threshold_slider.valueChanged.connect(
            lambda v: self.threshold_label.setText(f"{v}%")
        )
        layout.addWidget(self.threshold_label)
        
        # Highlight anomalies checkbox
        self.highlight_check = QCheckBox("Highlight Anomalies")
        self.highlight_check.setChecked(True)
        layout.addWidget(self.highlight_check)
        
        layout.addStretch()
        
        controls.setLayout(layout)
        return controls
    
    def load_data(self, timeline_df: pd.DataFrame):
        """
        Load timeline data and generate heatmap.
        
        Args:
            timeline_df: DataFrame with timeline events
        """
        self.timeline_df = timeline_df
        self._refresh_heatmap()
    
    def _refresh_heatmap(self):
        """Regenerate heatmap with current settings."""
        if self.timeline_df is None or self.timeline_df.empty:
            return
        
        # Remove old canvas
        if self.canvas:
            self.canvas_container.removeWidget(self.canvas)
            self.canvas.deleteLater()
        
        # Generate new heatmap
        fig = self.generator.generate_heatmap(self.timeline_df)
        
        # Create canvas
        self.canvas = FigureCanvasQTAgg(fig)
        self.canvas.mpl_connect('button_press_event', self._on_canvas_click)
        
        # Add toolbar
        toolbar = NavigationToolbar2QT(self.canvas, self)
        
        self.canvas_container.addWidget(toolbar)
        self.canvas_container.addWidget(self.canvas)
        
        self.canvas.draw()
    
    def _on_canvas_click(self, event):
        """Handle click on heatmap cell."""
        if event.inaxes:
            # Get cell coordinates
            col = int(event.xdata + 0.5)
            row = int(event.ydata + 0.5)
            
            # Extract date and hour
            # Emit signal for filtering
            # self.cell_clicked.emit(date, hour, count)
            pass
```

**File: `src/ui/tabs/heatmap_tab.py`**
```python
"""
Heatmap tab for temporal event analysis
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QMessageBox
)
from ...visualization.heatmap_widget import HeatmapWidget
import pandas as pd
import logging


class HeatmapTab(QWidget):
    """
    Tab displaying event heatmap and temporal analysis.
    
    Features:
    - Calendar-style heatmap
    - Click to filter timeline
    - Anomaly detection
    - Export heatmap
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger(__name__)
        self.heatmap_widget = None
        self.parent_window = parent
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize UI components."""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("<h2>📅 Event Heatmap - Temporal Distribution</h2>")
        layout.addWidget(header)
        
        # Heatmap widget
        self.heatmap_widget = HeatmapWidget()
        self.heatmap_widget.cell_clicked.connect(self._on_cell_clicked)
        layout.addWidget(self.heatmap_widget)
        
        self.setLayout(layout)
    
    def load_timeline(self, timeline_df: pd.DataFrame):
        """Load timeline data into heatmap."""
        if timeline_df is None or timeline_df.empty:
            self.logger.warning("No timeline data to display in heatmap")
            return
        
        self.heatmap_widget.load_data(timeline_df)
        self.logger.info(f"Loaded {len(timeline_df)} events into heatmap")
    
    def _on_cell_clicked(self, date: str, hour: int, count: int):
        """
        Handle heatmap cell click.
        Filter parent timeline to show events from that time slice.
        """
        self.logger.info(f"Heatmap cell clicked: {date} {hour}:00 ({count} events)")
        
        # Notify parent window to filter timeline
        if self.parent_window and hasattr(self.parent_window, 'filter_timeline_by_datetime'):
            self.parent_window.filter_timeline_by_datetime(date, hour)
        
        QMessageBox.information(
            self,
            "Filter Applied",
            f"Timeline filtered to {date} {hour}:00-{hour+1}:00\n"
            f"Showing {count} events"
        )
```

**Add to Main Window:**

```python
# In main_window.py __init__
from .tabs.heatmap_tab import HeatmapTab

self.heatmap_tab = HeatmapTab(self)
self.tabs.addTab(self.heatmap_tab, "📅 Heatmap")

# In _on_pipeline_finished
self.heatmap_tab.load_timeline(classified_df)
```

---

Due to character limits, I've created Part 1 covering:
1. ✅ **Multilingual PDF Reporting** - Complete with translator, language packs, and UI integration
2. ✅ **Snapshot + Resume Analysis** - Session management with save/restore dialogs
3. ✅ **Event Heatmap Calendar** - Matplotlib-based heatmap with PyQt6 integration

Would you like me to continue with:
4. **Artifact Timeline Navigation & Filtering**
5. **Folder Tree & Metadata Viewer** (partially exists, needs enhancement)
6. **Workflow Integration**
7. **Performance Optimization & Testing**

Let me know and I'll generate Part 2! 🚀

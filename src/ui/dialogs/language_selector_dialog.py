"""
Language selector dialog for report export.
Allows user to choose report language before export.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QComboBox, QPushButton, QDialogButtonBox
)
from PyQt6.QtCore import Qt
from src.utils.i18n import Translator


class LanguageSelectorDialog(QDialog):
    """
    Dialog for selecting report export language.
    
    Features:
    - Dropdown with available languages
    - Preview of language name in native script
    - OK/Cancel buttons
    
    Example:
        >>> dialog = LanguageSelectorDialog(parent=self)
        >>> if dialog.exec() == QDialog.DialogCode.Accepted:
        ...     language = dialog.get_selected_language()
        ...     translator = Translator(language)
        ...     # Generate report with translator
    """
    
    def __init__(self, parent=None, default_language: str = 'en'):
        """
        Initialize language selector dialog.
        
        Args:
            parent: Parent widget
            default_language: Default selected language code
        """
        super().__init__(parent)
        self.setWindowTitle("Select Report Language")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        self.translator = Translator('en')  # Use English for dialog UI
        self.selected_language = default_language
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        
        # Title label
        title = QLabel("Choose language for exported report:")
        title.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Language selection
        lang_layout = QHBoxLayout()
        lang_label = QLabel("Language:")
        lang_label.setMinimumWidth(80)
        lang_layout.addWidget(lang_label)
        
        self.language_combo = QComboBox()
        self.language_combo.setMinimumWidth(250)
        
        # Populate with available languages
        available_languages = self.translator.get_available_languages()
        for lang_code in available_languages:
            lang_name = self.translator.get_language_name(lang_code)
            # Show both code and native name
            display_text = f"{lang_name} ({lang_code.upper()})"
            self.language_combo.addItem(display_text, lang_code)
        
        # Set default selection
        index = self.language_combo.findData(self.selected_language)
        if index >= 0:
            self.language_combo.setCurrentIndex(index)
        
        lang_layout.addWidget(self.language_combo)
        layout.addLayout(lang_layout)
        
        # Preview label
        self.preview_label = QLabel()
        self.preview_label.setStyleSheet(
            "background-color: #f0f0f0; "
            "padding: 10px; "
            "border-radius: 5px; "
            "margin-top: 10px; "
            "font-size: 12px;"
        )
        self.preview_label.setWordWrap(True)
        layout.addWidget(self.preview_label)
        
        # Update preview when selection changes
        self.language_combo.currentIndexChanged.connect(self._update_preview)
        self._update_preview()
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        layout.addStretch()
    
    def _update_preview(self):
        """Update preview text when language selection changes."""
        lang_code = self.language_combo.currentData()
        if lang_code:
            # Create translator for selected language
            preview_translator = Translator(lang_code)
            
            # Show preview text
            title = preview_translator.get('report.title')
            case_id = preview_translator.get('report.metadata.case_id')
            examiner = preview_translator.get('report.metadata.examiner')
            
            preview_text = f"<b>Preview:</b><br>"
            preview_text += f"• {title}<br>"
            preview_text += f"• {case_id}<br>"
            preview_text += f"• {examiner}"
            
            self.preview_label.setText(preview_text)
    
    def get_selected_language(self) -> str:
        """
        Get the selected language code.
        
        Returns:
            Language code (e.g., 'fr', 'hi')
        """
        return self.language_combo.currentData()


if __name__ == '__main__':
    """Quick test of the dialog."""
    import sys
    from PyQt6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    dialog = LanguageSelectorDialog(default_language='en')
    
    if dialog.exec() == QDialog.DialogCode.Accepted:
        selected = dialog.get_selected_language()
        print(f"✅ Selected language: {selected}")
    else:
        print("❌ Dialog cancelled")
    
    sys.exit(0)

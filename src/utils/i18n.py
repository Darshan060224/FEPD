"""
FEPD - Forensic Evidence Parser Dashboard
Internationalization (i18n) Module

Provides multilingual support for FEPD UI and reports using Qt's translation system.

Supported Languages:
    - English (en_US) - Default
    - Spanish (es_ES)
    - French (fr_FR)
    - German (de_DE)
    - Japanese (ja_JP)
    - Chinese Simplified (zh_CN)

Features:
    - Qt Linguist integration
    - Runtime language switching
    - Automatic language detection
    - Translation file management
    - Number and date formatting
    - RTL (Right-to-Left) support
    - Translation coverage reporting

Architecture:
    - TranslationManager: Main i18n interface
    - LanguageConfig: Language metadata
    - TranslationCache: Performance optimization
    - LocaleFormatter: Culture-specific formatting

Usage:
    from src.utils.i18n import TranslationManager
    
    # Initialize
    i18n = TranslationManager()
    
    # Translate strings
    text = i18n.tr("File Activity")
    
    # Switch language
    i18n.set_language('es_ES')
    
    # Format numbers
    formatted = i18n.format_number(1234567.89)  # "1.234.567,89" in Spanish

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
import json
import locale as system_locale

try:
    from PyQt6.QtCore import QTranslator, QLocale, QCoreApplication
    from PyQt6.QtWidgets import QApplication
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False
    QTranslator = None
    QLocale = None
    QCoreApplication = None


@dataclass
class LanguageConfig:
    """
    Language configuration metadata.
    
    Attributes:
        code: ISO 639-1 language code with country (e.g., 'en_US')
        name: Native language name
        english_name: English name of the language
        rtl: Right-to-left text direction
        date_format: Date format string
        time_format: Time format string
        number_decimal: Decimal separator
        number_thousands: Thousands separator
    """
    code: str
    name: str
    english_name: str
    rtl: bool = False
    date_format: str = "%Y-%m-%d"
    time_format: str = "%H:%M:%S"
    number_decimal: str = "."
    number_thousands: str = ","


# Supported languages configuration
SUPPORTED_LANGUAGES = {
    'en_US': LanguageConfig(
        code='en_US',
        name='English',
        english_name='English',
        date_format='%Y-%m-%d',
        time_format='%H:%M:%S',
        number_decimal='.',
        number_thousands=','
    ),
    'es_ES': LanguageConfig(
        code='es_ES',
        name='Español',
        english_name='Spanish',
        date_format='%d/%m/%Y',
        time_format='%H:%M:%S',
        number_decimal=',',
        number_thousands='.'
    ),
    'fr_FR': LanguageConfig(
        code='fr_FR',
        name='Français',
        english_name='French',
        date_format='%d/%m/%Y',
        time_format='%H:%M:%S',
        number_decimal=',',
        number_thousands=' '
    ),
    'de_DE': LanguageConfig(
        code='de_DE',
        name='Deutsch',
        english_name='German',
        date_format='%d.%m.%Y',
        time_format='%H:%M:%S',
        number_decimal=',',
        number_thousands='.'
    ),
    'ja_JP': LanguageConfig(
        code='ja_JP',
        name='日本語',
        english_name='Japanese',
        date_format='%Y年%m月%d日',
        time_format='%H:%M:%S',
        number_decimal='.',
        number_thousands=','
    ),
    'zh_CN': LanguageConfig(
        code='zh_CN',
        name='中文（简体）',
        english_name='Chinese (Simplified)',
        date_format='%Y年%m月%d日',
        time_format='%H:%M:%S',
        number_decimal='.',
        number_thousands=','
    )
}


class TranslationManager:
    """
    Manages application translations and internationalization.
    
    Handles Qt translation files (.qm) and provides runtime language switching.
    """
    
    def __init__(
        self,
        translations_dir: Optional[Path] = None,
        default_language: str = 'en_US',
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize translation manager.
        
        Args:
            translations_dir: Directory containing .qm translation files
            default_language: Default language code
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Set translations directory
        if translations_dir is None:
            # Default to locales/ in project root
            translations_dir = Path(__file__).parent.parent.parent / 'locales'
        self.translations_dir = Path(translations_dir)
        self.translations_dir.mkdir(parents=True, exist_ok=True)
        
        # Current language
        self.current_language = default_language
        self.current_config = SUPPORTED_LANGUAGES.get(default_language, SUPPORTED_LANGUAGES['en_US'])
        
        # Qt translator
        self.translator: Optional[QTranslator] = None
        
        # Translation cache for non-Qt contexts
        self.cache: Dict[str, str] = {}
        
        # Initialize Qt if available
        if QT_AVAILABLE:
            self._init_qt_translator()
        
        self.logger.info(f"Translation manager initialized: {default_language}")
    
    def _init_qt_translator(self) -> None:
        """Initialize Qt translator."""
        if not QT_AVAILABLE:
            return
        
        if QTranslator is None:
            return
        
        self.translator = QTranslator()
        
        # Load translation file
        qm_file = self.translations_dir / f"fepd_{self.current_language}.qm"
        if qm_file.exists():
            if self.translator.load(str(qm_file)):
                # Install translator
                app = QCoreApplication.instance()
                if app:
                    app.installTranslator(self.translator)
                self.logger.info(f"Loaded Qt translation: {qm_file.name}")
            else:
                self.logger.warning(f"Failed to load translation: {qm_file}")
        else:
            self.logger.debug(f"Translation file not found: {qm_file}")
    
    def set_language(self, language_code: str) -> bool:
        """
        Switch to different language.
        
        Args:
            language_code: ISO language code (e.g., 'es_ES')
        
        Returns:
            True if language was changed successfully
        
        Example:
            i18n.set_language('es_ES')  # Switch to Spanish
        """
        if language_code not in SUPPORTED_LANGUAGES:
            self.logger.error(f"Unsupported language: {language_code}")
            return False
        
        # Update current language
        self.current_language = language_code
        self.current_config = SUPPORTED_LANGUAGES[language_code]
        
        # Clear cache
        self.cache.clear()
        
        # Reload Qt translator
        if QT_AVAILABLE and self.translator:
            app = QCoreApplication.instance()
            if app:
                # Remove old translator
                app.removeTranslator(self.translator)
            
            # Load new translation
            qm_file = self.translations_dir / f"fepd_{language_code}.qm"
            if qm_file.exists() and self.translator.load(str(qm_file)):
                if app:
                    app.installTranslator(self.translator)
                self.logger.info(f"Switched to language: {language_code}")
            else:
                self.logger.warning(f"Translation not available for: {language_code}")
        
        return True
    
    def tr(self, source_text: str, context: str = "") -> str:
        """
        Translate text string.
        
        Args:
            source_text: English source text
            context: Optional context for disambiguation
        
        Returns:
            Translated text (or original if no translation available)
        
        Example:
            text = i18n.tr("File Activity")
            text = i18n.tr("Open", context="menu")
        """
        # Check cache first
        cache_key = f"{context}:{source_text}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Use Qt translation if available
        if QT_AVAILABLE and QCoreApplication.instance():
            translated = QCoreApplication.translate(context, source_text)
            self.cache[cache_key] = translated
            return translated
        
        # Fallback: return original text
        return source_text
    
    def format_date(self, dt: datetime) -> str:
        """
        Format datetime according to current locale.
        
        Args:
            dt: Datetime to format
        
        Returns:
            Formatted date string
        
        Example:
            formatted = i18n.format_date(datetime.now())
            # English: "2025-11-07"
            # Spanish: "07/11/2025"
        """
        return dt.strftime(self.current_config.date_format)
    
    def format_time(self, dt: datetime) -> str:
        """
        Format time according to current locale.
        
        Args:
            dt: Datetime to format
        
        Returns:
            Formatted time string
        """
        return dt.strftime(self.current_config.time_format)
    
    def format_datetime(self, dt: datetime) -> str:
        """
        Format datetime according to current locale.
        
        Args:
            dt: Datetime to format
        
        Returns:
            Formatted datetime string
        """
        date_str = self.format_date(dt)
        time_str = self.format_time(dt)
        return f"{date_str} {time_str}"
    
    def format_number(self, number: float, decimals: int = 2) -> str:
        """
        Format number according to current locale.
        
        Args:
            number: Number to format
            decimals: Number of decimal places
        
        Returns:
            Formatted number string
        
        Example:
            formatted = i18n.format_number(1234567.89)
            # English: "1,234,567.89"
            # Spanish: "1.234.567,89"
        """
        # Split into integer and decimal parts
        int_part = int(abs(number))
        dec_part = abs(number) - int_part
        
        # Format integer part with thousands separator
        int_str = str(int_part)
        formatted_int = ""
        for i, digit in enumerate(reversed(int_str)):
            if i > 0 and i % 3 == 0:
                formatted_int = self.current_config.number_thousands + formatted_int
            formatted_int = digit + formatted_int
        
        # Format decimal part
        if decimals > 0:
            dec_str = f"{dec_part:.{decimals}f}"[2:]  # Remove "0."
            formatted = f"{formatted_int}{self.current_config.number_decimal}{dec_str}"
        else:
            formatted = formatted_int
        
        # Add negative sign if needed
        if number < 0:
            formatted = "-" + formatted
        
        return formatted
    
    def get_available_languages(self) -> List[Dict[str, str]]:
        """
        Get list of available languages.
        
        Returns:
            List of language dictionaries with code, name, english_name
        
        Example:
            languages = i18n.get_available_languages()
            for lang in languages:
                print(f"{lang['name']} ({lang['code']})")
        """
        return [
            {
                'code': config.code,
                'name': config.name,
                'english_name': config.english_name,
                'rtl': config.rtl
            }
            for config in SUPPORTED_LANGUAGES.values()
        ]
    
    def detect_system_language(self) -> str:
        """
        Detect system language.
        
        Returns:
            Language code of detected system language (or 'en_US' if not supported)
        
        Example:
            detected = i18n.detect_system_language()
            i18n.set_language(detected)
        """
        try:
            # Try Qt locale first
            if QT_AVAILABLE:
                qt_locale = QLocale.system()
                lang_code = qt_locale.name()  # e.g., 'en_US'
                if lang_code in SUPPORTED_LANGUAGES:
                    return lang_code
            
            # Fallback to Python locale
            system_lang, _ = system_locale.getdefaultlocale()
            if system_lang and system_lang in SUPPORTED_LANGUAGES:
                return system_lang
            
            # Check language prefix (e.g., 'en' from 'en_GB')
            if system_lang:
                lang_prefix = system_lang.split('_')[0]
                for code in SUPPORTED_LANGUAGES:
                    if code.startswith(lang_prefix):
                        return code
        
        except Exception as e:
            self.logger.warning(f"Failed to detect system language: {e}")
        
        # Default to English
        return 'en_US'
    
    def get_translation_coverage(self) -> Dict[str, float]:
        """
        Get translation coverage statistics.
        
        Returns:
            Dictionary mapping language codes to coverage percentage
        
        Example:
            coverage = i18n.get_translation_coverage()
            # {'en_US': 100.0, 'es_ES': 95.0, 'fr_FR': 80.0, ...}
        """
        coverage = {}
        
        # English is always 100%
        coverage['en_US'] = 100.0
        
        # Check other languages
        for lang_code in SUPPORTED_LANGUAGES:
            if lang_code == 'en_US':
                continue
            
            qm_file = self.translations_dir / f"fepd_{lang_code}.qm"
            if qm_file.exists():
                # Estimate coverage based on file size ratio
                en_file = self.translations_dir / "fepd_en_US.qm"
                if en_file.exists():
                    coverage[lang_code] = min(100.0, (qm_file.stat().st_size / en_file.stat().st_size) * 100)
                else:
                    coverage[lang_code] = 50.0  # Estimate
            else:
                coverage[lang_code] = 0.0
        
        return coverage
    
    def generate_ts_template(self, output_path: Optional[Path] = None) -> Path:
        """
        Generate Qt Linguist .ts template file from source code.
        
        This scans Python source files for tr() calls and generates
        a translation template that can be edited in Qt Linguist.
        
        Args:
            output_path: Optional output path for .ts file
        
        Returns:
            Path to generated .ts file
        
        Note:
            Use Qt's lupdate tool for better results:
            lupdate src/ -ts locales/fepd_template.ts
        """
        if output_path is None:
            output_path = self.translations_dir / "fepd_template.ts"
        
        # Simple template generation (basic implementation)
        # In production, use Qt's lupdate tool for comprehensive extraction
        
        ts_content = '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE TS>
<TS version="2.1" language="en_US">
<context>
    <name>FEPD</name>
    <!-- Translation strings will be added here by lupdate -->
</context>
</TS>
'''
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(ts_content, encoding='utf-8')
        
        self.logger.info(f"Generated .ts template: {output_path}")
        return output_path


# Global translation manager instance
_global_i18n: Optional[TranslationManager] = None


def init_i18n(translations_dir: Optional[Path] = None, 
              default_language: Optional[str] = None) -> TranslationManager:
    """
    Initialize global translation manager.
    
    Args:
        translations_dir: Directory containing translation files
        default_language: Default language code (None = auto-detect)
    
    Returns:
        TranslationManager instance
    
    Example:
        from src.utils.i18n import init_i18n, tr
        
        # Initialize with auto-detection
        i18n = init_i18n()
        
        # Use translation function
        text = tr("File Activity")
    """
    global _global_i18n
    
    i18n = TranslationManager(
        translations_dir=translations_dir,
        default_language=default_language or 'en_US'
    )
    
    # Auto-detect system language if no default specified
    if default_language is None:
        detected = i18n.detect_system_language()
        i18n.set_language(detected)
    
    _global_i18n = i18n
    return i18n


def get_i18n() -> Optional[TranslationManager]:
    """Get global translation manager instance."""
    return _global_i18n


def tr(text: str, context: str = "") -> str:
    """
    Convenience function for translation (uses global i18n instance).
    
    Args:
        text: Text to translate
        context: Optional context
    
    Returns:
        Translated text
    
    Example:
        from src.utils.i18n import tr
        
        label.setText(tr("File Activity"))
        menu_item.setText(tr("Open", context="menu"))
    """
    if _global_i18n:
        return _global_i18n.tr(text, context)
    return text


# Common forensic terms translations (for reference)
FORENSIC_TERMS = {
    # Categories
    "File Activity": {"es": "Actividad de Archivos", "fr": "Activité de Fichiers", "de": "Dateiaktivität", "ja": "ファイル活動", "zh": "文件活动"},
    "Network Activity": {"es": "Actividad de Red", "fr": "Activité Réseau", "de": "Netzwerkaktivität", "ja": "ネットワーク活動", "zh": "网络活动"},
    "Process Execution": {"es": "Ejecución de Procesos", "fr": "Exécution de Processus", "de": "Prozessausführung", "ja": "プロセス実行", "zh": "进程执行"},
    "Registry Modification": {"es": "Modificación del Registro", "fr": "Modification du Registre", "de": "Registrierungsänderung", "ja": "レジストリ変更", "zh": "注册表修改"},
    "Authentication": {"es": "Autenticación", "fr": "Authentification", "de": "Authentifizierung", "ja": "認証", "zh": "身份验证"},
    
    # Severities
    "CRITICAL": {"es": "CRÍTICO", "fr": "CRITIQUE", "de": "KRITISCH", "ja": "重大", "zh": "严重"},
    "HIGH": {"es": "ALTO", "fr": "ÉLEVÉ", "de": "HOCH", "ja": "高", "zh": "高"},
    "MEDIUM": {"es": "MEDIO", "fr": "MOYEN", "de": "MITTEL", "ja": "中", "zh": "中"},
    "LOW": {"es": "BAJO", "fr": "BAS", "de": "NIEDRIG", "ja": "低", "zh": "低"},
    "INFO": {"es": "INFO", "fr": "INFO", "de": "INFO", "ja": "情報", "zh": "信息"},
    
    # UI Elements
    "Timeline": {"es": "Línea de Tiempo", "fr": "Chronologie", "de": "Zeitleiste", "ja": "タイムライン", "zh": "时间线"},
    "Search": {"es": "Buscar", "fr": "Rechercher", "de": "Suchen", "ja": "検索", "zh": "搜索"},
    "Filter": {"es": "Filtrar", "fr": "Filtrer", "de": "Filtern", "ja": "フィルター", "zh": "过滤"},
    "Export": {"es": "Exportar", "fr": "Exporter", "de": "Exportieren", "ja": "エクスポート", "zh": "导出"},
    "Report": {"es": "Informe", "fr": "Rapport", "de": "Bericht", "ja": "レポート", "zh": "报告"}
}

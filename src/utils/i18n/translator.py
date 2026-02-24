"""
Translator - Core translation engine for FEPD.
Loads JSON language packs and provides translation services.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class Translator:
    """
    Handles multi-language support for the application.
    
    Features:
    - Load translations from JSON files
    - Nested key access (e.g., "report.metadata.case_id")
    - Parameter substitution (e.g., "{count} files")
    - Fallback to English for missing translations
    
    Example:
        >>> translator = Translator(language='fr')
        >>> translator.get('report.title')
        'Rapport d'Analyse Forensique'
        >>> translator.get('timeline.event_count', count=465)
        '465 événements trouvés'
    """
    
    def __init__(self, language: str = 'en'):
        """
        Initialize translator with specified language.
        
        Args:
            language: Language code (en, fr, hi, es)
        """
        self.language = language
        self.translations: Dict[str, Any] = {}
        self.fallback_translations: Dict[str, Any] = {}
        
        # Determine locales directory
        self.locales_dir = self._get_locales_directory()
        
        # Load translations
        self._load_translations()
        logger.info(f"Translator initialized with language: {language}")
    
    def _get_locales_directory(self) -> Path:
        """Find the locales directory relative to project root."""
        # Start from current file location
        current_file = Path(__file__).resolve()
        
        # Navigate up to find project root (where main.py is)
        project_root = current_file.parent.parent.parent.parent
        locales_dir = project_root / 'locales'
        
        if not locales_dir.exists():
            logger.warning(f"Locales directory not found at {locales_dir}")
            # Try creating it
            locales_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created locales directory at {locales_dir}")
        
        return locales_dir
    
    def _load_translations(self) -> None:
        """Load translation files for current language and fallback (English)."""
        # Load requested language
        language_file = self.locales_dir / f"{self.language}.json"
        if language_file.exists():
            try:
                with open(language_file, 'r', encoding='utf-8') as f:
                    self.translations = json.load(f)
                logger.info(f"Loaded translations from {language_file}")
            except Exception as e:
                logger.error(f"Failed to load {language_file}: {e}")
                self.translations = {}
        else:
            logger.warning(f"Translation file not found: {language_file}")
            self.translations = {}
        
        # Always load English as fallback (unless already English)
        if self.language != 'en':
            fallback_file = self.locales_dir / "en.json"
            if fallback_file.exists():
                try:
                    with open(fallback_file, 'r', encoding='utf-8') as f:
                        self.fallback_translations = json.load(f)
                    logger.debug("Loaded English fallback translations")
                except Exception as e:
                    logger.error(f"Failed to load fallback translations: {e}")
                    self.fallback_translations = {}
    
    def get(self, key: str, **kwargs) -> str:
        """
        Get translated string for the given key.
        
        Args:
            key: Dot-notation key (e.g., "report.metadata.case_id")
            **kwargs: Parameters for string substitution
        
        Returns:
            Translated and formatted string, or key if not found
        
        Example:
            >>> t.get('timeline.filtered_events', count=50)
            'Showing 50 filtered events'
        """
        # Try to get from current language
        value = self._get_nested(self.translations, key)
        
        # Fallback to English if not found
        if value is None and self.fallback_translations:
            value = self._get_nested(self.fallback_translations, key)
            if value:
                logger.debug(f"Using fallback translation for key: {key}")
        
        # If still not found, return the key itself
        if value is None:
            logger.warning(f"Translation not found for key: {key}")
            return key
        
        # Perform parameter substitution
        if kwargs:
            try:
                return value.format(**kwargs)
            except KeyError as e:
                logger.error(f"Missing parameter for key '{key}': {e}")
                return value
        
        return value
    
    def _get_nested(self, data: Dict[str, Any], key: str) -> Optional[str]:
        """
        Get value from nested dictionary using dot notation.
        
        Args:
            data: Dictionary to search
            key: Dot-notation key (e.g., "report.metadata.title")
        
        Returns:
            Value if found, None otherwise
        """
        keys = key.split('.')
        current = data
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return None
        
        return current if isinstance(current, str) else None
    
    def set_language(self, language: str) -> None:
        """
        Change the current language.
        
        Args:
            language: New language code (en, fr, hi, es)
        """
        if language != self.language:
            self.language = language
            self._load_translations()
            logger.info(f"Language changed to: {language}")
    
    def get_available_languages(self) -> list:
        """
        Get list of available language codes.
        
        Returns:
            List of language codes (e.g., ['en', 'fr', 'hi'])
        """
        languages = []
        if self.locales_dir.exists():
            for file in self.locales_dir.glob("*.json"):
                languages.append(file.stem)
        return sorted(languages)
    
    def get_language_name(self, code: str) -> str:
        """
        Get full name for language code.
        
        Args:
            code: Language code (e.g., 'fr')
        
        Returns:
            Full language name (e.g., 'Français')
        """
        names = {
            'en': 'English',
            'fr': 'Français',
            'hi': 'हिन्दी',
            'es': 'Español',
            'de': 'Deutsch',
            'zh': '中文'
        }
        return names.get(code, code.upper())

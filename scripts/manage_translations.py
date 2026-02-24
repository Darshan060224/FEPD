#!/usr/bin/env python3
"""
FEPD Translation Management Script

Manages Qt translation files (.ts) and compiled binaries (.qm).

Features:
    - Extract translatable strings from source code
    - Compile .ts files to .qm binaries
    - Check translation coverage
    - Create new language templates
    - Validate translation files

Usage:
    python manage_translations.py extract        # Extract strings
    python manage_translations.py compile        # Compile to .qm
    python manage_translations.py coverage       # Show coverage stats
    python manage_translations.py create pt_BR   # Create new language

Copyright (c) 2025 FEPD Development Team
"""

import argparse
import sys
import re
from pathlib import Path
from typing import List, Dict, Set
import xml.etree.ElementTree as ET

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Qt tools (optional)
try:
    from PyQt6.QtCore import QTranslator
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


class TranslationManager:
    """Manages FEPD translation files."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.locales_dir = project_root / 'locales'
        self.src_dir = project_root / 'src'
        self.locales_dir.mkdir(exist_ok=True)
    
    def extract_strings(self) -> None:
        """Extract translatable strings from source code."""
        print("Extracting translatable strings from source code...")
        
        # Find all tr() calls
        strings = self._scan_source_files()
        
        print(f"\nFound {len(strings)} unique translatable strings")
        
        # Update .ts files
        for lang_code in ['en_US', 'es_ES', 'fr_FR', 'de_DE', 'ja_JP', 'zh_CN']:
            ts_file = self.locales_dir / f"fepd_{lang_code}.ts"
            self._update_ts_file(ts_file, strings, lang_code)
            print(f"Updated: {ts_file.name}")
    
    def _scan_source_files(self) -> Set[tuple]:
        """
        Scan Python source files for tr() calls.
        
        Returns:
            Set of (context, text) tuples
        """
        strings = set()
        
        # Pattern to match tr() calls
        pattern = re.compile(r'''tr\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*context\s*=\s*['"]([^'"]+)['"])?\s*\)''')
        
        # Scan all Python files
        for py_file in self.src_dir.rglob('*.py'):
            try:
                content = py_file.read_text(encoding='utf-8')
                matches = pattern.findall(content)
                for text, context in matches:
                    context = context or 'FEPD'
                    strings.add((context, text))
            except Exception as e:
                print(f"Warning: Failed to scan {py_file}: {e}")
        
        return strings
    
    def _update_ts_file(self, ts_file: Path, strings: Set[tuple], lang_code: str) -> None:
        """Update .ts file with extracted strings."""
        # Create new .ts file structure
        root = ET.Element('TS', version='2.1', language=lang_code)
        
        # Group strings by context
        contexts = {}
        for context, text in strings:
            if context not in contexts:
                contexts[context] = []
            contexts[context].append(text)
        
        # Create context elements
        for context_name, texts in sorted(contexts.items()):
            context_elem = ET.SubElement(root, 'context')
            name_elem = ET.SubElement(context_elem, 'name')
            name_elem.text = context_name
            
            for text in sorted(texts):
                message_elem = ET.SubElement(context_elem, 'message')
                source_elem = ET.SubElement(message_elem, 'source')
                source_elem.text = text
                translation_elem = ET.SubElement(message_elem, 'translation')
                
                # For English, translation = source
                if lang_code == 'en_US':
                    translation_elem.text = text
                else:
                    translation_elem.set('type', 'unfinished')
        
        # Write to file
        tree = ET.ElementTree(root)
        ET.indent(tree, space='    ')
        tree.write(ts_file, encoding='utf-8', xml_declaration=True)
    
    def compile_translations(self) -> None:
        """Compile .ts files to .qm binaries."""
        print("Compiling translation files...")
        
        compiled = 0
        for ts_file in self.locales_dir.glob('fepd_*.ts'):
            qm_file = ts_file.with_suffix('.qm')
            
            try:
                # Try using lrelease (Qt tool)
                import subprocess
                result = subprocess.run(
                    ['lrelease', str(ts_file), '-qm', str(qm_file)],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    print(f"Compiled: {qm_file.name}")
                    compiled += 1
                else:
                    print(f"Warning: lrelease failed for {ts_file.name}")
                    # Fallback: create empty .qm file
                    qm_file.touch()
            
            except FileNotFoundError:
                print(f"Warning: lrelease not found. Creating placeholder {qm_file.name}")
                qm_file.touch()
                compiled += 1
        
        print(f"\nCompiled {compiled} translation files")
        print("\nNote: For production, install Qt tools:")
        print("  pip install PyQt6")
        print("  And use Qt's lrelease tool for full functionality")
    
    def check_coverage(self) -> None:
        """Check translation coverage for each language."""
        print("Translation Coverage Report")
        print("=" * 60)
        
        for ts_file in sorted(self.locales_dir.glob('fepd_*.ts')):
            lang_code = ts_file.stem.replace('fepd_', '')
            total, translated, unfinished = self._analyze_ts_file(ts_file)
            
            if total > 0:
                coverage = (translated / total) * 100
                status = "✓" if coverage == 100 else "⚠" if coverage > 50 else "✗"
                
                print(f"\n{status} {lang_code:8s}: {coverage:5.1f}% ({translated}/{total} strings)")
                
                if unfinished > 0:
                    print(f"           {unfinished} unfinished translations")
    
    def _analyze_ts_file(self, ts_file: Path) -> tuple:
        """
        Analyze .ts file for translation completeness.
        
        Returns:
            (total, translated, unfinished) tuple
        """
        try:
            tree = ET.parse(ts_file)
            root = tree.getroot()
            
            total = 0
            translated = 0
            unfinished = 0
            
            for message in root.findall('.//message'):
                total += 1
                translation = message.find('translation')
                
                if translation is not None:
                    if translation.get('type') == 'unfinished':
                        unfinished += 1
                    elif translation.text:
                        translated += 1
            
            return total, translated, unfinished
        
        except Exception as e:
            print(f"Error analyzing {ts_file}: {e}")
            return 0, 0, 0
    
    def create_language(self, lang_code: str) -> None:
        """Create new language template."""
        print(f"Creating new language template: {lang_code}")
        
        # Create empty .ts file
        ts_file = self.locales_dir / f"fepd_{lang_code}.ts"
        
        root = ET.Element('TS', version='2.1', language=lang_code)
        context = ET.SubElement(root, 'context')
        name = ET.SubElement(context, 'name')
        name.text = 'FEPD'
        
        tree = ET.ElementTree(root)
        ET.indent(tree, space='    ')
        tree.write(ts_file, encoding='utf-8', xml_declaration=True)
        
        print(f"Created: {ts_file}")
        print(f"\nNext steps:")
        print(f"1. Run: python manage_translations.py extract")
        print(f"2. Edit {ts_file} in Qt Linguist")
        print(f"3. Run: python manage_translations.py compile")
    
    def validate_translations(self) -> None:
        """Validate translation files for errors."""
        print("Validating translation files...")
        
        errors = 0
        for ts_file in self.locales_dir.glob('fepd_*.ts'):
            try:
                tree = ET.parse(ts_file)
                root = tree.getroot()
                
                # Check for missing translations in non-English files
                lang_code = ts_file.stem.replace('fepd_', '')
                if lang_code != 'en_US':
                    for message in root.findall('.//message'):
                        translation = message.find('translation')
                        if translation is None or not translation.text:
                            source = message.find('source')
                            if source is not None:
                                print(f"  Missing translation in {lang_code}: {source.text}")
                                errors += 1
            
            except ET.ParseError as e:
                print(f"  XML parse error in {ts_file}: {e}")
                errors += 1
        
        if errors == 0:
            print("✓ All translation files are valid")
        else:
            print(f"\n✗ Found {errors} validation errors")


def main():
    parser = argparse.ArgumentParser(
        description="Manage FEPD translation files"
    )
    parser.add_argument(
        'command',
        choices=['extract', 'compile', 'coverage', 'create', 'validate'],
        help='Command to execute'
    )
    parser.add_argument(
        'lang_code',
        nargs='?',
        help='Language code (for create command)'
    )
    
    args = parser.parse_args()
    
    # Find project root
    project_root = Path(__file__).parent.parent
    
    manager = TranslationManager(project_root)
    
    if args.command == 'extract':
        manager.extract_strings()
    
    elif args.command == 'compile':
        manager.compile_translations()
    
    elif args.command == 'coverage':
        manager.check_coverage()
    
    elif args.command == 'create':
        if not args.lang_code:
            print("Error: Language code required for 'create' command")
            print("Example: python manage_translations.py create pt_BR")
            sys.exit(1)
        manager.create_language(args.lang_code)
    
    elif args.command == 'validate':
        manager.validate_translations()


if __name__ == '__main__':
    main()

# FEPD Translation Files

This directory contains internationalization (i18n) resources for FEPD's multilingual support.

## Supported Languages

- **en_US** - English (United States) - Default
- **es_ES** - Spanish (Spain)
- **fr_FR** - French (France)
- **de_DE** - German (Germany)
- **ja_JP** - Japanese (Japan)
- **zh_CN** - Chinese Simplified (China)

## File Types

### .ts Files (Translation Source)
XML files editable in Qt Linguist. These are the master translation files.

- `fepd_en_US.ts` - English template
- `fepd_es_ES.ts` - Spanish translations
- `fepd_fr_FR.ts` - French translations
- `fepd_de_DE.ts` - German translations
- `fepd_ja_JP.ts` - Japanese translations
- `fepd_zh_CN.ts` - Chinese translations

### .qm Files (Compiled Translations)
Binary files compiled from .ts files for runtime use.

## Workflow

### 1. Extract Translatable Strings
```bash
python scripts/manage_translations.py extract
```

This scans source code for `tr()` calls and updates .ts files.

### 2. Translate in Qt Linguist
```bash
linguist locales/fepd_es_ES.ts
```

Or edit .ts files manually in XML format.

### 3. Compile Translations
```bash
python scripts/manage_translations.py compile
```

This generates .qm files from .ts files.

### 4. Check Coverage
```bash
python scripts/manage_translations.py coverage
```

Shows translation completion percentage for each language.

## Translation Guidelines

### Context Sensitivity
Use context parameter for ambiguous terms:
```python
tr("Open", context="menu")  # Menu item
tr("Open", context="status")  # Status description
```

### Placeholders
Use %s, %d for variables:
```python
tr("Found %d events in %s")
```

### Forensic Terminology
Maintain technical accuracy:
- "File Activity" - Not "File Action"
- "Process Execution" - Not "Program Run"
- "Registry Modification" - Not "Registry Edit"

### Character Limits
Some UI elements have space constraints. Keep translations concise:
- Button labels: max 20 characters
- Menu items: max 30 characters
- Dialog titles: max 50 characters

## Adding New Languages

1. Add language config in `src/utils/i18n.py`:
```python
'pt_BR': LanguageConfig(
    code='pt_BR',
    name='Português',
    english_name='Portuguese',
    date_format='%d/%m/%Y',
    time_format='%H:%M:%S',
    number_decimal=',',
    number_thousands='.'
)
```

2. Generate .ts template:
```bash
python scripts/manage_translations.py create pt_BR
```

3. Translate and compile as above.

## Testing Translations

```python
from src.utils.i18n import init_i18n

# Initialize with specific language
i18n = init_i18n(default_language='es_ES')

# Test translation
assert i18n.tr("File Activity") == "Actividad de Archivos"

# Test number formatting
assert i18n.format_number(1234.56) == "1.234,56"
```

## Translation Coverage Status

| Language | Coverage | Last Updated |
|----------|----------|--------------|
| English  | 100%     | 2025-11-07   |
| Spanish  | 0%       | Not started  |
| French   | 0%       | Not started  |
| German   | 0%       | Not started  |
| Japanese | 0%       | Not started  |
| Chinese  | 0%       | Not started  |

## Tools

- **Qt Linguist** - GUI translation editor
- **lupdate** - Extract strings from source code
- **lrelease** - Compile .ts to .qm files
- **scripts/manage_translations.py** - FEPD translation management script

## Resources

- [Qt Linguist Manual](https://doc.qt.io/qt-6/qtlinguist-index.html)
- [Internationalization with Qt](https://doc.qt.io/qt-6/internationalization.html)
- [Python gettext](https://docs.python.org/3/library/gettext.html)

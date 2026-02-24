"""
FEPD Path Sanitizer - Forensic Integrity Protection
====================================================

CRITICAL SECURITY MODULE: Prevents analyzer-side path exposure.

This module enforces a fundamental forensic principle:
    "At no point must the UI, terminal, or any output expose analyzer-side paths.
     Every path shown must be only from the evidence filesystem.
     If any analyzer/host path appears, it is a tamper condition."

Two Realities:
--------------
Layer        | Example Path                              | Must be visible?
-------------|-------------------------------------------|------------------
Analyzer     | C:\\FEPD\\cases\\cs-01\\extracted\\...   | ❌ NEVER
Evidence     | C:\\Windows\\System32\\config\\SAM       | ✅ ALWAYS

This turns FEPD into a true evidence OS, not a wrapper over the host.

Copyright (c) 2026 FEPD Development Team
"""

import re
import os
import logging
from typing import Optional, Tuple, List, Dict, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# TAMPER DETECTION PATTERNS
# ============================================================================

class TamperSeverity(Enum):
    """Severity of path leakage attempt."""
    CRITICAL = "CRITICAL"    # Direct analyzer path exposure
    HIGH = "HIGH"            # Workspace/case structure visible
    MEDIUM = "MEDIUM"        # Internal path markers
    LOW = "LOW"              # Debug/temp references
    BLOCKED = "BLOCKED"      # Successfully blocked


@dataclass
class TamperEvent:
    """Record of a path sanitization event."""
    timestamp: str
    original_path: str
    sanitized_path: Optional[str]
    severity: TamperSeverity
    context: str
    blocked: bool
    component: str  # Which UI component triggered
    
    def to_coc_entry(self) -> Dict:
        """Convert to Chain of Custody log entry."""
        return {
            'event_type': 'PATH_SANITIZATION',
            'timestamp': self.timestamp,
            'original_path_hash': hash(self.original_path),  # Don't log actual path
            'severity': self.severity.value,
            'context': self.context,
            'blocked': self.blocked,
            'component': self.component
        }


# Analyzer-side path patterns that MUST NEVER appear in UI
ANALYZER_PATH_PATTERNS = [
    # FEPD workspace patterns
    r'cases[/\\]',
    r'extracted[_]?data[/\\]',
    r'partition[_]?\d+[/\\]',
    r'workspace[/\\]',
    r'artifacts[/\\]',
    r'output[/\\]',
    r'temp[/\\]',
    r'tmp[/\\]',
    r'\.fepd[/\\]',
    
    # Mount point patterns
    r'/mnt/',
    r'/media/',
    r'/tmp/',
    r'/home/.*/\.fepd',
    
    # Absolute analyzer paths on Windows
    r'C:\\FEPD',
    r'C:\\Users\\[^\\]+\\Desktop\\FEPD',
    r'C:\\Users\\[^\\]+\\AppData',
    r'D:\\FEPD',
    r'E:\\FEPD',
    
    # Python/dev environment paths
    r'\.venv[/\\]',
    r'site-packages',
    r'__pycache__',
    
    # Database and config paths
    r'\.db$',
    r'\.sqlite$',
    r'vfs\.db',
    r'case\.db',
    
    # Log paths
    r'logs[/\\]',
    r'\.log$',
    
    # VEFS internal markers
    r'/vefs/',
    r'vefs[/\\]',
    r'p\d+[/\\]',  # partition markers like p0/, p1/
]

# Compile patterns for performance
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in ANALYZER_PATH_PATTERNS]


# ============================================================================
# PATH SANITIZER CLASS
# ============================================================================

class PathSanitizer:
    """
    Forensic path sanitizer - prevents analyzer path exposure.
    
    Usage:
        sanitizer = PathSanitizer()
        
        # Before displaying ANY path in UI
        safe_path = sanitizer.sanitize(raw_path, 'files_tab')
        
        # Check if path would leak
        if sanitizer.is_analyzer_path(path):
            raise TamperAlert("Analyzer path leaked")
    
    FEPD Global Invariant:
        "FEPD SHALL NEVER expose analyzer-side filesystem paths to the investigator.
         All visible paths SHALL be reconstructed from evidence metadata only.
         Any leakage SHALL be treated as a forensic integrity breach."
    """
    
    def __init__(self, coc_callback: Optional[Callable] = None):
        """
        Initialize sanitizer.
        
        Args:
            coc_callback: Function to call for Chain of Custody logging
        """
        self.coc_callback = coc_callback
        self.events: List[TamperEvent] = []
        self._path_mapping: Dict[str, str] = {}  # internal -> evidence
        
        # Detect analyzer base path
        self.analyzer_base = self._detect_analyzer_base()
        
    def _detect_analyzer_base(self) -> str:
        """Detect the FEPD installation directory (analyzer base)."""
        try:
            # Go up from this file to find FEPD root
            current = Path(__file__).resolve()
            for parent in current.parents:
                if (parent / 'main.py').exists() or (parent / 'requirements.txt').exists():
                    return str(parent)
            return str(Path.cwd())
        except:
            return str(Path.cwd())
    
    def is_analyzer_path(self, path: str) -> bool:
        """
        Check if a path is from the analyzer/host filesystem.
        
        Args:
            path: Path string to check
            
        Returns:
            True if path should NOT be shown to investigator
        """
        if not path:
            return False
        
        # Normalize path separators
        normalized = path.replace('\\', '/')
        
        # Check against compiled patterns
        for pattern in COMPILED_PATTERNS:
            if pattern.search(normalized):
                return True
        
        # Check if path contains analyzer base
        if self.analyzer_base:
            analyzer_normalized = self.analyzer_base.replace('\\', '/')
            if analyzer_normalized in normalized:
                return True
        
        return False
    
    def get_leak_severity(self, path: str) -> TamperSeverity:
        """
        Determine severity of potential path leak.
        
        Args:
            path: Path to analyze
            
        Returns:
            TamperSeverity level
        """
        if not path:
            return TamperSeverity.LOW
        
        normalized = path.replace('\\', '/').lower()
        
        # Critical: Direct FEPD case data
        if any(p in normalized for p in ['cases/', '/extracted', 'vfs.db', 'case.db']):
            return TamperSeverity.CRITICAL
        
        # High: Workspace structure
        if any(p in normalized for p in ['workspace/', 'artifacts/', 'output/']):
            return TamperSeverity.HIGH
        
        # Medium: Mount points, partitions
        if any(p in normalized for p in ['/mnt/', 'partition_', '/tmp/', 'temp/']):
            return TamperSeverity.MEDIUM
        
        # Low: Dev/debug paths
        if any(p in normalized for p in ['.venv', '__pycache__', 'logs/']):
            return TamperSeverity.LOW
        
        return TamperSeverity.LOW
    
    def sanitize(
        self,
        path: str,
        component: str = "unknown",
        evidence_mapping: Optional[str] = None,
        raise_on_leak: bool = True
    ) -> str:
        """
        Sanitize a path for safe display to investigator.
        
        CRITICAL: Call this before ANY path is shown in:
        - Files tab
        - Breadcrumb bar
        - Right-click details
        - Terminal output (ls, pwd, find)
        - Reports
        - Exports
        - User-visible logs
        
        Args:
            path: Raw path (may contain analyzer paths)
            component: UI component requesting sanitization
            evidence_mapping: Optional known evidence path to use instead
            raise_on_leak: If True, raises exception on leak attempt
            
        Returns:
            Safe path for display
            
        Raises:
            ForensicIntegrityError: If analyzer path leaks and raise_on_leak=True
        """
        if not path:
            return ""
        
        # If we have explicit evidence mapping, use it
        if evidence_mapping:
            self._record_event(
                path, evidence_mapping, TamperSeverity.BLOCKED,
                f"Mapped to evidence path", True, component
            )
            return evidence_mapping
        
        # Check if this is an analyzer path
        if self.is_analyzer_path(path):
            severity = self.get_leak_severity(path)
            
            # Try to extract evidence path from internal path
            evidence_path = self._extract_evidence_path(path)
            
            if evidence_path:
                # Successfully sanitized
                self._record_event(
                    path, evidence_path, TamperSeverity.BLOCKED,
                    "Analyzer path sanitized to evidence path", True, component
                )
                return evidence_path
            else:
                # Cannot sanitize - potential integrity breach
                self._record_event(
                    path, None, severity,
                    "ANALYZER PATH EXPOSURE BLOCKED", True, component
                )
                
                if raise_on_leak:
                    raise ForensicIntegrityError(
                        f"Analyzer path exposure attempt blocked.\n"
                        f"Component: {component}\n"
                        f"Evidence integrity preserved.\n"
                        f"This incident has been logged to Chain of Custody."
                    )
                else:
                    # Return a safe placeholder
                    return "[PATH REDACTED - Forensic Integrity Protection]"
        
        # Path appears safe
        return path
    
    def _extract_evidence_path(self, internal_path: str) -> Optional[str]:
        """
        Extract evidence path from internal FEPD path.
        
        Examples:
            /cases/cs-01/vefs/p3/Users/LoneWolf/Desktop/file.txt
            -> C:\\Users\\LoneWolf\\Desktop\\file.txt
            
            C:\\FEPD\\cases\\test\\extracted_data\\partition_0\\Windows\\System32
            -> C:\\Windows\\System32
            
        Args:
            internal_path: Internal FEPD path
            
        Returns:
            Evidence path if extractable, None otherwise
        """
        if not internal_path:
            return None
        
        # Normalize
        path = internal_path.replace('\\', '/')
        
        # Pattern 1: /cases/.../vefs/p{n}/...
        match = re.search(r'/vefs/p\d+/(.+)$', path, re.IGNORECASE)
        if match:
            evidence_relative = match.group(1)
            return self._to_windows_path(evidence_relative)
        
        # Pattern 2: /cases/.../partition_{n}/...
        match = re.search(r'/partition[_]?\d+/(.+)$', path, re.IGNORECASE)
        if match:
            evidence_relative = match.group(1)
            return self._to_windows_path(evidence_relative)
        
        # Pattern 3: /cases/.../extracted_data/.../{Windows|Users|Program Files}/...
        match = re.search(
            r'/(Windows|Users|Program Files|ProgramData|System Volume Information)(/.*)?$',
            path, re.IGNORECASE
        )
        if match:
            windows_part = match.group(1) + (match.group(2) or '')
            return 'C:' + windows_part.replace('/', '\\')
        
        # Pattern 4: Check for drive letter style already in path
        match = re.search(r'([A-Za-z]):/(.+)$', path)
        if match:
            drive = match.group(1).upper()
            rest = match.group(2)
            # Only if the rest doesn't contain workspace markers
            if not any(m in rest.lower() for m in ['cases/', 'workspace/', 'extracted']):
                return f"{drive}:\\{rest.replace('/', '\\')}"
        
        # Pattern 5: Linux evidence paths
        match = re.search(r'/(home|etc|var|usr|opt|root)(/.*)?$', path)
        if match:
            linux_part = '/' + match.group(1) + (match.group(2) or '')
            return linux_part
        
        return None
    
    def _to_windows_path(self, path: str) -> str:
        """Convert Unix-style path to Windows evidence path."""
        # Remove leading slash if present
        if path.startswith('/'):
            path = path[1:]
        
        # Assume C: drive unless path indicates otherwise
        return f"C:\\{path.replace('/', '\\')}"
    
    def _record_event(
        self,
        original: str,
        sanitized: Optional[str],
        severity: TamperSeverity,
        context: str,
        blocked: bool,
        component: str
    ):
        """Record a sanitization event for audit trail."""
        event = TamperEvent(
            timestamp=datetime.now().isoformat(),
            original_path=original,
            sanitized_path=sanitized,
            severity=severity,
            context=context,
            blocked=blocked,
            component=component
        )
        
        self.events.append(event)
        
        # Log to CoC if callback provided
        if self.coc_callback:
            try:
                self.coc_callback('PATH_SANITIZATION', event.to_coc_entry())
            except Exception as e:
                logger.error(f"Failed to log CoC event: {e}")
        
        # Also log based on severity
        if severity in (TamperSeverity.CRITICAL, TamperSeverity.HIGH):
            logger.warning(
                f"[FORENSIC] Path sanitization: {severity.value} - {context} "
                f"(component: {component})"
            )
    
    def register_path_mapping(self, internal_path: str, evidence_path: str):
        """
        Register a known mapping from internal to evidence path.
        
        Call this when extracting artifacts to build the mapping table.
        
        Args:
            internal_path: Internal FEPD storage path
            evidence_path: Original evidence location
        """
        self._path_mapping[internal_path.replace('\\', '/')] = evidence_path
    
    def get_stats(self) -> Dict:
        """Get sanitization statistics."""
        from collections import Counter
        severity_counts = Counter(e.severity.value for e in self.events)
        
        return {
            'total_events': len(self.events),
            'by_severity': dict(severity_counts),
            'blocked_count': sum(1 for e in self.events if e.blocked),
            'leaked_count': sum(1 for e in self.events if not e.blocked)
        }


# ============================================================================
# EXCEPTIONS
# ============================================================================

class ForensicIntegrityError(Exception):
    """
    Raised when forensic integrity is at risk.
    
    This exception indicates that analyzer-side paths were about to
    be exposed to the investigator, which would compromise:
    - Evidence integrity
    - Chain of custody
    - Court admissibility
    """
    pass


class TamperAlert(ForensicIntegrityError):
    """
    Critical alert: Analyzer path leak detected.
    
    This must be treated as a potential forensic integrity breach.
    """
    pass


# ============================================================================
# GLOBAL SANITIZER INSTANCE
# ============================================================================

# Singleton instance for application-wide use
_global_sanitizer: Optional[PathSanitizer] = None


def get_sanitizer(coc_callback: Optional[Callable] = None) -> PathSanitizer:
    """
    Get the global path sanitizer instance.
    
    Args:
        coc_callback: Optional CoC logging callback (only used on first call)
        
    Returns:
        PathSanitizer instance
    """
    global _global_sanitizer
    if _global_sanitizer is None:
        _global_sanitizer = PathSanitizer(coc_callback)
    return _global_sanitizer


def safe_path(
    path: str,
    component: str = "unknown",
    evidence_mapping: Optional[str] = None
) -> str:
    """
    Convenience function to sanitize a path.
    
    CRITICAL: Call this BEFORE ANY UI or terminal output!
    
    Args:
        path: Raw path to sanitize
        component: UI component name
        evidence_mapping: Optional known evidence path
        
    Returns:
        Safe path for display
    """
    return get_sanitizer().sanitize(path, component, evidence_mapping)


def is_safe_path(path: str) -> bool:
    """
    Check if a path is safe to display.
    
    Args:
        path: Path to check
        
    Returns:
        True if path can be safely shown to investigator
    """
    return not get_sanitizer().is_analyzer_path(path)


def validate_output_paths(paths: List[str], component: str) -> List[str]:
    """
    Validate and sanitize a list of paths before output.
    
    Args:
        paths: List of paths to validate
        component: Component requesting validation
        
    Returns:
        List of safe paths
    """
    sanitizer = get_sanitizer()
    return [sanitizer.sanitize(p, component, raise_on_leak=False) for p in paths]


# ============================================================================
# DECORATOR FOR UI METHODS
# ============================================================================

def sanitize_paths(component: str):
    """
    Decorator to auto-sanitize path returns from UI methods.
    
    Usage:
        @sanitize_paths('files_tab')
        def get_selected_path(self) -> str:
            return self._internal_path  # Will be sanitized
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            if isinstance(result, str):
                return safe_path(result, component)
            elif isinstance(result, list):
                return [safe_path(p, component) if isinstance(p, str) else p for p in result]
            return result
        return wrapper
    return decorator


# ============================================================================
# FORENSIC INTEGRITY CONTRACT
# ============================================================================

FORENSIC_INTEGRITY_CONTRACT = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                     FEPD FORENSIC INTEGRITY CONTRACT                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  "FEPD SHALL NEVER expose analyzer-side filesystem paths to the             ║
║   investigator.                                                             ║
║                                                                              ║
║   All visible paths SHALL be reconstructed from evidence metadata only.     ║
║                                                                              ║
║   Any leakage SHALL be treated as a forensic integrity breach."             ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This contract makes FEPD court-grade forensic software.                    ║
║  You are not building a tool. You are building a forensic operating system. ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


# ============================================================================
# TEST / VALIDATION
# ============================================================================

if __name__ == "__main__":
    print(FORENSIC_INTEGRITY_CONTRACT)
    print("\n" + "="*70)
    print("PATH SANITIZER VALIDATION")
    print("="*70)
    
    sanitizer = PathSanitizer()
    
    # Test cases
    test_paths = [
        # Should be blocked (analyzer paths)
        ("cases/cs-01/vefs/p3/Users/LoneWolf/Desktop/file.txt", True),
        ("C:\\FEPD\\cases\\test\\extracted_data\\partition_0\\Windows\\System32", True),
        ("/mnt/evidence/Users/Admin/Documents", True),
        ("workspace/artifacts/registry/SYSTEM.hive", True),
        ("C:\\Users\\darsh\\Desktop\\FEPD\\cases\\demo", True),
        
        # Should be allowed (evidence paths)
        ("C:\\Windows\\System32\\config\\SAM", False),
        ("C:\\Users\\LoneWolf\\Desktop\\report.pdf", False),
        ("/home/victim/.bashrc", False),
        ("/etc/passwd", False),
        ("D:\\Documents\\secret.docx", False),
    ]
    
    print("\nTest Results:")
    print("-" * 70)
    
    for path, should_block in test_paths:
        is_blocked = sanitizer.is_analyzer_path(path)
        status = "✓" if is_blocked == should_block else "✗"
        action = "BLOCKED" if is_blocked else "ALLOWED"
        expected = "BLOCKED" if should_block else "ALLOWED"
        
        print(f"{status} [{action:8}] (expected: {expected:8}) {path[:50]}...")
        
        if is_blocked:
            try:
                result = sanitizer.sanitize(path, "test", raise_on_leak=False)
                print(f"   → Sanitized to: {result}")
            except Exception as e:
                print(f"   → Error: {e}")
    
    print("\n" + "="*70)
    print("Sanitization Stats:")
    stats = sanitizer.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

"""
FEPD Forensic Path Utilities
=============================

Provides forensic path tagging and formatting to distinguish:
- EVIDENCE paths: Original location inside the forensic image
- WORKSPACE paths: Where FEPD stored/extracted the artifact

This distinction is critical for:
- Legal chain of custody
- Court admissibility
- Clear documentation of artifact provenance

Copyright (c) 2025 FEPD Development Team
"""

from pathlib import Path
from typing import Optional, Tuple
import re


# ============================================================================
# PATH TAGGING CONSTANTS
# ============================================================================

EVIDENCE_PREFIX = "[EVIDENCE]"
WORKSPACE_PREFIX = "[WORKSPACE]"

EVIDENCE_EMOJI = "📀"  # Disk/evidence
WORKSPACE_EMOJI = "📁"  # Folder/workspace


# ============================================================================
# PATH CLASSIFICATION
# ============================================================================

def is_evidence_path(path: str) -> bool:
    """
    Determine if a path is from inside a forensic evidence image.
    
    Evidence paths typically:
    - Start with / (Unix) or C:\\ (Windows partition)
    - Contain partition markers (/Partition1/, /Disk0/)
    - Reference Windows system paths (/Windows/, /Users/)
    - Don't contain 'cases/' or 'artifacts/' workspace markers
    """
    if not path:
        return False
    
    path_lower = path.lower().replace('\\', '/')
    
    # Workspace paths start with cases/ or contain artifacts/
    workspace_markers = ['cases/', '/artifacts/', '/workspace/', 'dataa/']
    for marker in workspace_markers:
        if marker in path_lower:
            return False
    
    # Evidence paths contain these patterns
    evidence_markers = [
        '/partition', '/disk0', '/disk1', '/volume',
        '/windows/', '/users/', '/system32/',
        '/home/', '/etc/', '/var/',
        'c:/', 'd:/', 'e:/',
    ]
    for marker in evidence_markers:
        if marker in path_lower:
            return True
    
    # Default: if path starts with / and doesn't have workspace markers, assume evidence
    return path.startswith('/')


def is_workspace_path(path: str) -> bool:
    """Check if path is from FEPD workspace/case directory."""
    if not path:
        return False
    
    path_lower = path.lower().replace('\\', '/')
    
    workspace_markers = [
        'cases/', '/artifacts/', '/workspace/', '/extracted/',
        '/dataa/', '/output/', '/reports/'
    ]
    
    return any(marker in path_lower for marker in workspace_markers)


def classify_path(path: str) -> str:
    """
    Classify a path as 'evidence', 'workspace', or 'unknown'.
    
    Args:
        path: Path string to classify
        
    Returns:
        'evidence', 'workspace', or 'unknown'
    """
    if is_evidence_path(path):
        return 'evidence'
    elif is_workspace_path(path):
        return 'workspace'
    else:
        return 'unknown'


# ============================================================================
# PATH FORMATTING
# ============================================================================

def format_evidence_path(path: str, use_emoji: bool = True) -> str:
    """
    Format an evidence path with proper tagging.
    
    Args:
        path: Original evidence path
        use_emoji: Whether to use emoji (True) or text prefix (False)
        
    Returns:
        Formatted path like "📀 EVIDENCE:/C:/Windows/System32/config/SYSTEM"
    """
    if use_emoji:
        return f"{EVIDENCE_EMOJI} EVIDENCE:{path}"
    else:
        return f"{EVIDENCE_PREFIX} {path}"


def format_workspace_path(path: str, use_emoji: bool = True) -> str:
    """
    Format a workspace path with proper tagging.
    
    Args:
        path: Workspace path
        use_emoji: Whether to use emoji (True) or text prefix (False)
        
    Returns:
        Formatted path like "📁 cases/csae-12/artifacts/SYSTEM.hive"
    """
    if use_emoji:
        return f"{WORKSPACE_EMOJI} {path}"
    else:
        return f"{WORKSPACE_PREFIX} {path}"


def format_path_auto(path: str, use_emoji: bool = True) -> str:
    """
    Automatically detect and format a path with appropriate tagging.
    
    Args:
        path: Any path
        use_emoji: Whether to use emoji
        
    Returns:
        Formatted path with evidence/workspace tag
    """
    path_type = classify_path(path)
    
    if path_type == 'evidence':
        return format_evidence_path(path, use_emoji)
    elif path_type == 'workspace':
        return format_workspace_path(path, use_emoji)
    else:
        # Unknown - return as-is with indicator
        return f"❓ {path}" if use_emoji else f"[UNKNOWN] {path}"


def format_dual_path(
    evidence_path: Optional[str],
    workspace_path: Optional[str],
    separator: str = "\n"
) -> str:
    """
    Format both evidence and workspace paths for display.
    
    Args:
        evidence_path: Original path inside evidence image
        workspace_path: Path where artifact was extracted
        separator: Separator between the two paths
        
    Returns:
        Formatted dual-path string like:
        "📀 EVIDENCE:/C:/Windows/System32/config/SYSTEM
         📁 cases/csae-12/artifacts/SYSTEM.hive"
    """
    lines = []
    
    if evidence_path:
        lines.append(f"{EVIDENCE_EMOJI} Source: EVIDENCE:{evidence_path}")
    
    if workspace_path:
        lines.append(f"{WORKSPACE_EMOJI} Stored: {workspace_path}")
    
    return separator.join(lines) if lines else "No path information"


# ============================================================================
# HTML FORMATTING (for Qt Rich Text)
# ============================================================================

def format_path_html(path: str) -> str:
    """
    Format a path as HTML with color coding.
    
    Evidence paths: Blue
    Workspace paths: Green
    """
    path_type = classify_path(path)
    
    if path_type == 'evidence':
        return f'<span style="color: #4fc3f7;">{EVIDENCE_EMOJI} EVIDENCE:{path}</span>'
    elif path_type == 'workspace':
        return f'<span style="color: #81c784;">{WORKSPACE_EMOJI} {path}</span>'
    else:
        return f'<span style="color: #888888;">❓ {path}</span>'


def format_dual_path_html(
    evidence_path: Optional[str],
    workspace_path: Optional[str]
) -> str:
    """
    Format dual paths as HTML for rich text display.
    """
    html_parts = []
    
    if evidence_path:
        html_parts.append(
            f'<div style="color: #4fc3f7; font-family: monospace;">'
            f'{EVIDENCE_EMOJI} <b>Source:</b> EVIDENCE:{evidence_path}</div>'
        )
    
    if workspace_path:
        html_parts.append(
            f'<div style="color: #81c784; font-family: monospace;">'
            f'{WORKSPACE_EMOJI} <b>Stored:</b> {workspace_path}</div>'
        )
    
    return ''.join(html_parts) if html_parts else '<span style="color: #888;">No path information</span>'


# ============================================================================
# PATH EXTRACTION UTILITIES
# ============================================================================

def extract_evidence_path_from_artifact(artifact_data: dict) -> Optional[str]:
    """
    Extract the evidence path from an artifact record.
    
    Looks for keys like: internal_path, evidence_path, source_path, original_path
    """
    path_keys = ['internal_path', 'evidence_path', 'source_path', 'original_path', 'image_path']
    
    for key in path_keys:
        if key in artifact_data and artifact_data[key]:
            return artifact_data[key]
    
    return None


def extract_workspace_path_from_artifact(artifact_data: dict) -> Optional[str]:
    """
    Extract the workspace path from an artifact record.
    
    Looks for keys like: extracted_path, workspace_path, path, file_path
    """
    path_keys = ['extracted_path', 'workspace_path', 'stored_path', 'path', 'file_path']
    
    for key in path_keys:
        if key in artifact_data and artifact_data[key]:
            path = artifact_data[key]
            # Convert Path objects to string
            if hasattr(path, '__fspath__'):
                path = str(path)
            return path
    
    return None


def get_artifact_paths(artifact_data: dict) -> Tuple[Optional[str], Optional[str]]:
    """
    Get both evidence and workspace paths from artifact data.
    
    Returns:
        Tuple of (evidence_path, workspace_path)
    """
    evidence_path = extract_evidence_path_from_artifact(artifact_data)
    workspace_path = extract_workspace_path_from_artifact(artifact_data)
    
    return evidence_path, workspace_path

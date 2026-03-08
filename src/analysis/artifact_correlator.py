"""
FEPD - Artifact Correlation & File Activity Reconstruction Engine

Provides:
  - MACB (Modified / Accessed / Created / Birth) file-activity tracking
  - Cross-artifact correlation (Prefetch ↔ Registry ↔ EventLog ↔ Browser)
  - File lifecycle reconstruction
  - Process-tree building from PID / PPID
  - Unknown-artifact analysis (entropy, signature, heuristic scoring)
  - Attack-phase classification (kill-chain mapping)

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

from __future__ import annotations

import math
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

logger = logging.getLogger(__name__)


# ───────────────────────────── Data classes ──────────────────────────────

@dataclass
class MACBActivity:
    """MACB (Modified / Accessed / Created / Birth) timestamps for a file."""
    modified: Optional[str] = None
    accessed: Optional[str] = None
    created: Optional[str] = None
    birth: Optional[str] = None
    executed: Optional[str] = None  # extra forensic flag

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "Modified": self.modified,
            "Accessed": self.accessed,
            "Created": self.created,
            "Birth": self.birth,
            "Executed": self.executed,
        }


@dataclass
class RelatedArtifact:
    """A cross-reference to another artifact source."""
    source: str          # e.g. "Prefetch", "Registry", "EventLog", "Browser"
    description: str     # human-readable summary
    timestamp: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileLifecycleStep:
    """One step in a file's lifecycle."""
    timestamp: str
    operation: str       # Created / Modified / Executed / Deleted / Downloaded / Accessed
    program: str = ""
    pid: int = 0
    user: str = ""
    source: str = ""     # artifact source that produced the evidence


@dataclass
class ProcessNode:
    """A node in a process tree."""
    pid: int
    ppid: int
    name: str
    user: str = ""
    timestamp: str = ""
    children: List["ProcessNode"] = field(default_factory=list)


@dataclass
class AttackStoryStep:
    """One step of the reconstructed attack story."""
    phase: str           # e.g. "Initial Access", "Execution", …
    timestamp: str
    description: str
    pid: int = 0
    program: str = ""
    event_index: int = -1   # back-reference into DataFrame


@dataclass
class UnknownArtifactResult:
    """Heuristic analysis of an unrecognised artifact."""
    likely_type: str = "Unknown"
    entropy: float = 0.0
    suspicious_score: float = 0.0
    notes: str = ""


# ───────────────── Operation → color mapping ────────────────────────────

OPERATION_COLORS = {
    "Created":    "#22B573",   # green
    "Modified":   "#3C7DD9",   # blue
    "Executed":   "#E8A317",   # orange
    "Deleted":    "#D64550",   # red
    "Downloaded": "#9B59B6",   # purple
    "Accessed":   "#17A2B8",   # teal
}

# ──────────────── Attack-phase definitions ──────────────────────────────

ATTACK_PHASES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Lateral Movement",
    "Exfiltration Prep",
    "Exfiltration",
    "Cleanup / Anti-Forensics",
]

_PHASE_RULES: List[Tuple[str, List[str]]] = [
    ("Initial Access",         ["download", "phishing", "browser download", "email attachment"]),
    ("Execution",              ["process execution", "execution", "process started", "powershell",
                                "cmd.exe", "wscript", "cscript", "mshta"]),
    ("Persistence",            ["registry run key", "scheduled task", "startup", "service created",
                                "persistence", "autostart"]),
    ("Privilege Escalation",   ["privilege", "elevation", "token", "uac bypass", "runas"]),
    ("Lateral Movement",       ["lateral", "psexec", "smb", "wmi remote", "rdp", "winrm"]),
    ("Exfiltration Prep",      ["archive", "zip", "rar", "7z", "staging", "compress"]),
    ("Exfiltration",           ["upload", "exfiltration", "ftp", "http post", "transfer"]),
    ("Cleanup / Anti-Forensics", ["log clear", "event log cleared", "deletion", "anti-forensic",
                                  "wipe", "timestamp", "1102"]),
]


# ─────────────────────── Helper functions ───────────────────────────────

def classify_phase(description: str, rule_class: str = "") -> str:
    """Map a textual event description to a kill-chain phase."""
    text = (description + " " + rule_class).lower()
    for phase, keywords in _PHASE_RULES:
        for kw in keywords:
            if kw in text:
                return phase
    return ""


def compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 4)


def analyze_unknown_artifact(
    file_path: str,
    file_size: int = 0,
    header_bytes: bytes = b"",
) -> UnknownArtifactResult:
    """Lightweight heuristic analysis of an unknown artifact."""
    result = UnknownArtifactResult()
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

    # Signature checks
    sigs = {
        b"MZ":      "PE Executable",
        b"\x7fELF": "ELF Binary",
        b"PK":      "ZIP / Office Archive",
        b"Rar":     "RAR Archive",
        b"\x89PNG":  "PNG Image",
        b"\xff\xd8": "JPEG Image",
        b"%PDF":     "PDF Document",
        b"SQLite":   "SQLite Database",
        b"regf":     "Registry Hive",
    }
    for sig, label in sigs.items():
        if header_bytes.startswith(sig):
            result.likely_type = label
            break

    if result.likely_type == "Unknown" and ext:
        ext_map = {
            "exe": "Executable", "dll": "Library", "sys": "Driver",
            "ps1": "PowerShell Script", "bat": "Batch Script",
            "vbs": "VBScript", "js": "JScript",
            "evtx": "Event Log", "pf": "Prefetch",
            "lnk": "Shortcut", "db": "Database",
        }
        result.likely_type = ext_map.get(ext, f"Unknown (.{ext})")

    # Entropy
    if header_bytes:
        result.entropy = compute_entropy(header_bytes)

    # Suspicious score
    score = 0.0
    if result.entropy > 7.0:
        score += 0.3
    if result.likely_type in ("PE Executable", "Executable", "PowerShell Script", "VBScript"):
        score += 0.3
    suspicious_exts = {"exe", "dll", "ps1", "vbs", "bat", "js", "scr", "com", "cmd"}
    if ext in suspicious_exts:
        score += 0.2
    if file_size and file_size < 50_000:
        score += 0.1   # small executables are often droppers
    result.suspicious_score = min(round(score, 2), 1.0)

    notes_parts = []
    if result.entropy > 7.0:
        notes_parts.append("High entropy – possibly packed / encrypted")
    if result.suspicious_score >= 0.7:
        notes_parts.append("Elevated suspicion – review recommended")
    result.notes = "; ".join(notes_parts)

    return result


# ───────────────── Artifact correlator ──────────────────────────────────

class ArtifactCorrelator:
    """Cross-references artifacts by file path / name and builds lifecycle."""

    def __init__(self):
        self._events: List[Dict[str, Any]] = []

    def load_events(self, events_df: pd.DataFrame):
        """Load normalised events DataFrame."""
        self._events = events_df.to_dict("records") if events_df is not None else []

    def add_event(self, event: Dict[str, Any]):
        self._events.append(event)

    # ---- MACB ----

    def get_macb(self, file_path: str) -> MACBActivity:
        """Build MACB timestamps for a specific file."""
        macb = MACBActivity()
        fp = file_path.lower()
        for ev in self._events:
            ev_path = (ev.get("filepath") or ev.get("artifact_path") or "").lower()
            if fp not in ev_path:
                continue
            op = (ev.get("operation") or ev.get("event_type") or "").lower()
            ts = str(ev.get("ts_utc") or ev.get("timestamp") or "")
            if "creat" in op:
                macb.created = macb.created or ts
            if "modif" in op or "write" in op:
                macb.modified = ts  # keep latest
            if "access" in op or "read" in op:
                macb.accessed = ts
            if "birth" in op:
                macb.birth = macb.birth or ts
            if "execut" in op or "run" in op or "start" in op:
                macb.executed = ts
        return macb

    # ---- Related artifacts ----

    def get_related_artifacts(self, file_path: str) -> List[RelatedArtifact]:
        """Find artifacts from different sources that mention the same file."""
        results: List[RelatedArtifact] = []
        seen_sources: Dict[str, list] = defaultdict(list)
        fp = file_path.lower()
        fname = fp.rsplit("\\", 1)[-1] if "\\" in fp else fp.rsplit("/", 1)[-1]

        for ev in self._events:
            ev_path = (ev.get("filepath") or ev.get("artifact_path") or ev.get("path") or "").lower()
            ev_desc = (ev.get("description") or "").lower()
            if fname not in ev_path and fname not in ev_desc:
                continue
            source = ev.get("artifact_source") or ev.get("source") or ev.get("subtype") or "Unknown"
            seen_sources[source].append(ev)

        for source, evts in seen_sources.items():
            desc_parts = []
            for e in evts[:5]:
                op = e.get("operation") or e.get("event_type") or ""
                ts = str(e.get("ts_utc") or e.get("timestamp") or "")
                desc_parts.append(f"{op} @ {ts}")
            results.append(RelatedArtifact(
                source=source,
                description="; ".join(desc_parts),
                timestamp=str(evts[0].get("ts_utc") or evts[0].get("timestamp") or ""),
            ))
        return results

    # ---- File lifecycle ----

    def build_file_lifecycle(self, file_path: str) -> List[FileLifecycleStep]:
        """Reconstruct ordered lifecycle of a file across all sources."""
        steps: List[FileLifecycleStep] = []
        fp = file_path.lower()
        fname = fp.rsplit("\\", 1)[-1] if "\\" in fp else fp.rsplit("/", 1)[-1]

        for ev in self._events:
            ev_path = (ev.get("filepath") or ev.get("artifact_path") or ev.get("path") or "").lower()
            ev_desc = (ev.get("description") or "").lower()
            if fname not in ev_path and fname not in ev_desc:
                continue

            op = ev.get("operation") or ev.get("event_type") or "Unknown"
            ts = str(ev.get("ts_utc") or ev.get("timestamp") or "")
            steps.append(FileLifecycleStep(
                timestamp=ts,
                operation=_normalise_operation(op),
                program=ev.get("exe_name") or ev.get("program") or "",
                pid=int(ev.get("pid") or 0),
                user=ev.get("user_account") or ev.get("user") or "",
                source=ev.get("artifact_source") or ev.get("source") or "",
            ))

        steps.sort(key=lambda s: s.timestamp)
        return steps


# ───────────────── Process-tree builder ─────────────────────────────────

class ProcessTreeBuilder:
    """Builds a process tree from events containing PID / PPID."""

    def __init__(self):
        self._nodes: Dict[int, ProcessNode] = {}

    def load_events(self, events_df: pd.DataFrame):
        """Populate tree from events DataFrame."""
        if events_df is None or events_df.empty:
            return
        for _, row in events_df.iterrows():
            pid = int(row.get("pid") or 0)
            ppid = int(row.get("ppid") or 0)
            if pid == 0:
                continue
            if pid not in self._nodes:
                self._nodes[pid] = ProcessNode(
                    pid=pid, ppid=ppid,
                    name=row.get("exe_name") or row.get("program") or "",
                    user=row.get("user_account") or row.get("user") or "",
                    timestamp=str(row.get("ts_utc") or row.get("timestamp") or ""),
                )

        # Link children
        for node in self._nodes.values():
            parent = self._nodes.get(node.ppid)
            if parent and parent.pid != node.pid:
                parent.children.append(node)

    def get_tree_text(self, root_pid: int, indent: int = 0) -> str:
        """Render a text-based tree starting from *root_pid*."""
        node = self._nodes.get(root_pid)
        if not node:
            return ""
        prefix = "    " * indent + ("└── " if indent else "")
        lines = [f"{prefix}{node.name} (PID {node.pid})"]
        for child in sorted(node.children, key=lambda c: c.timestamp):
            lines.append(self.get_tree_text(child.pid, indent + 1))
        return "\n".join(lines)

    def get_root_pid(self, pid: int) -> int:
        """Walk up the tree to find the root PID."""
        visited = set()
        current = pid
        while current in self._nodes and current not in visited:
            visited.add(current)
            parent_pid = self._nodes[current].ppid
            if parent_pid == 0 or parent_pid not in self._nodes:
                break
            current = parent_pid
        return current

    def get_related_pids(self, pid: int) -> List[int]:
        """Return PIDs for parent, self, and all descendants."""
        result: List[int] = []
        node = self._nodes.get(pid)
        if not node:
            return [pid]
        # parent
        if node.ppid and node.ppid in self._nodes:
            result.append(node.ppid)
        # self + descendants
        result.append(pid)
        self._collect_children(pid, result)
        return result

    def _collect_children(self, pid: int, out: List[int]):
        node = self._nodes.get(pid)
        if not node:
            return
        for ch in node.children:
            out.append(ch.pid)
            self._collect_children(ch.pid, out)


# ───────────────── Attack-story generator ───────────────────────────────

class AttackStoryGenerator:
    """Groups classified events into kill-chain phases."""

    def generate(self, events_df: pd.DataFrame) -> List[AttackStoryStep]:
        """Return ordered attack-story steps from events."""
        if events_df is None or events_df.empty:
            return []

        steps: List[AttackStoryStep] = []
        for idx, (_, row) in enumerate(events_df.iterrows()):
            desc = row.get("description") or row.get("event_type") or ""
            rule_class = row.get("rule_class") or ""
            phase = classify_phase(str(desc), str(rule_class))
            if not phase:
                continue
            steps.append(AttackStoryStep(
                phase=phase,
                timestamp=str(row.get("ts_utc") or row.get("timestamp") or ""),
                description=str(desc),
                pid=int(row.get("pid") or 0),
                program=row.get("exe_name") or row.get("program") or "",
                event_index=idx,
            ))

        steps.sort(key=lambda s: s.timestamp)
        return steps

    def group_by_phase(self, steps: List[AttackStoryStep]) -> Dict[str, List[AttackStoryStep]]:
        """Group steps by attack phase, preserving phase ordering."""
        groups: Dict[str, List[AttackStoryStep]] = {}
        for phase in ATTACK_PHASES:
            matching = [s for s in steps if s.phase == phase]
            if matching:
                groups[phase] = matching
        return groups


# ───────────────── Helpers ──────────────────────────────────────────────

def _normalise_operation(raw: str) -> str:
    """Map raw operation strings to canonical labels."""
    r = raw.lower()
    if "creat" in r:
        return "Created"
    if "modif" in r or "write" in r or "change" in r:
        return "Modified"
    if "access" in r or "read" in r or "open" in r:
        return "Accessed"
    if "delet" in r or "remov" in r:
        return "Deleted"
    if "execut" in r or "run" in r or "start" in r or "launch" in r:
        return "Executed"
    if "download" in r:
        return "Downloaded"
    return raw.title() if raw else "Unknown"

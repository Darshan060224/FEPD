"""
FEPD - Court-Defensible Audit Logging
=======================================
Comprehensive audit logging for forensic investigations.

All ML operations, evidence access, and analyst actions are logged
for chain of custody, court defensibility, and compliance.

Log Principles:
- Immutable logs
- Timestamped entries
- Operator attribution
- Complete audit trail
- Searchable and filterable
- Export for court

Copyright (c) 2026 FEPD Development Team
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import uuid


class LogLevel(Enum):
    """Audit log severity levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventType(Enum):
    """Types of auditable events"""
    # Evidence handling
    EVIDENCE_UPLOAD = "EVIDENCE_UPLOAD"
    EVIDENCE_ACCESS = "EVIDENCE_ACCESS"
    EVIDENCE_HASH = "EVIDENCE_HASH"
    EVIDENCE_VERIFY = "EVIDENCE_VERIFY"
    
    # ML operations
    ML_PREDICTION = "ML_PREDICTION"
    ML_EXPLANATION = "ML_EXPLANATION"
    ML_MODEL_LOAD = "ML_MODEL_LOAD"
    
    # Artifact extraction
    ARTIFACT_EXTRACT = "ARTIFACT_EXTRACT"
    FEATURE_ENGINEER = "FEATURE_ENGINEER"
    
    # Analyst actions
    ANALYST_LOGIN = "ANALYST_LOGIN"
    ANALYST_LOGOUT = "ANALYST_LOGOUT"
    ANALYST_EXPORT = "ANALYST_EXPORT"
    ANALYST_NOTE = "ANALYST_NOTE"
    
    # Case management
    CASE_CREATE = "CASE_CREATE"
    CASE_OPEN = "CASE_OPEN"
    CASE_CLOSE = "CASE_CLOSE"
    CASE_EXPORT = "CASE_EXPORT"
    
    # System events
    SYSTEM_START = "SYSTEM_START"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    ERROR_OCCURRED = "ERROR_OCCURRED"


@dataclass
class AuditLogEntry:
    """Single audit log entry"""
    event_id: str
    timestamp: str
    event_type: str
    level: str
    case_id: Optional[str]
    operator: str
    action: str
    details: Dict[str, Any]
    evidence_id: Optional[str] = None
    ip_address: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict):
        """Create from dictionary"""
        return cls(**data)


class ForensicAuditLogger:
    """
    Court-defensible audit logger for FEPD.
    
    All operations are logged to:
    - Case-specific audit log (cases/{case_id}/audit.jsonl)
    - System-wide audit log (logs/system_audit.jsonl)
    - Console (for real-time monitoring)
    """
    
    def __init__(self, case_id: Optional[str] = None, case_path: Optional[Path] = None,
                 operator: str = "system", logger: Optional[logging.Logger] = None):
        self.case_id = case_id
        self.case_path = Path(case_path) if case_path else None
        self.operator = operator
        self.console_logger = logger or logging.getLogger(__name__)
        
        # Case-specific audit log
        if self.case_path:
            self.case_audit_file = self.case_path / "audit.jsonl"
            self.case_path.mkdir(parents=True, exist_ok=True)
        else:
            self.case_audit_file = None
        
        # System-wide audit log
        self.system_audit_file = Path("logs/system_audit.jsonl")
        self.system_audit_file.parent.mkdir(parents=True, exist_ok=True)
    
    def log(self, event_type: EventType, action: str, details: Dict[str, Any] = None,
            level: LogLevel = LogLevel.INFO, evidence_id: str = None) -> AuditLogEntry:
        """
        Log an auditable event.
        
        Args:
            event_type: Type of event
            action: Human-readable description
            details: Additional details (must be JSON-serializable)
            level: Log severity
            evidence_id: Optional evidence identifier
            
        Returns:
            AuditLogEntry that was logged
        """
        # Create audit entry
        entry = AuditLogEntry(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            event_type=event_type.value,
            level=level.value,
            case_id=self.case_id,
            operator=self.operator,
            action=action,
            details=details or {},
            evidence_id=evidence_id
        )
        
        # Write to case audit log
        if self.case_audit_file:
            with open(self.case_audit_file, 'a') as f:
                f.write(entry.to_json() + '\n')
        
        # Write to system audit log
        with open(self.system_audit_file, 'a') as f:
            f.write(entry.to_json() + '\n')
        
        # Console logging
        log_method = getattr(self.console_logger, level.value.lower())
        log_method(f"[{event_type.value}] {action}")
        
        return entry
    
    def log_evidence_upload(self, evidence_path: Path, sha256: str, size_bytes: int):
        """Log evidence upload"""
        self.log(
            EventType.EVIDENCE_UPLOAD,
            f"Evidence uploaded: {evidence_path.name}",
            details={
                "path": str(evidence_path),
                "sha256": sha256,
                "size_bytes": size_bytes
            },
            level=LogLevel.INFO
        )
    
    def log_evidence_access(self, evidence_id: str, purpose: str):
        """Log evidence access"""
        self.log(
            EventType.EVIDENCE_ACCESS,
            f"Evidence accessed: {evidence_id}",
            details={"purpose": purpose},
            evidence_id=evidence_id,
            level=LogLevel.INFO
        )
    
    def log_ml_prediction(self, model_name: str, prediction: int, confidence: float,
                         evidence_id: str = None):
        """Log ML prediction"""
        self.log(
            EventType.ML_PREDICTION,
            f"ML prediction: {model_name}",
            details={
                "model": model_name,
                "prediction": prediction,
                "confidence": confidence
            },
            evidence_id=evidence_id,
            level=LogLevel.INFO
        )
    
    def log_ml_explanation(self, model_name: str, explanation_method: str,
                          evidence_id: str = None):
        """Log ML explanation generation"""
        self.log(
            EventType.ML_EXPLANATION,
            f"Explanation generated: {model_name}",
            details={
                "model": model_name,
                "method": explanation_method
            },
            evidence_id=evidence_id,
            level=LogLevel.INFO
        )
    
    def log_analyst_action(self, action: str, details: Dict = None):
        """Log analyst action"""
        self.log(
            EventType.ANALYST_NOTE,
            f"Analyst action: {action}",
            details=details,
            level=LogLevel.INFO
        )
    
    def log_error(self, error_msg: str, details: Dict = None):
        """Log error"""
        self.log(
            EventType.ERROR_OCCURRED,
            f"Error: {error_msg}",
            details=details,
            level=LogLevel.ERROR
        )
    
    def get_audit_trail(self, event_type: Optional[EventType] = None,
                       start_time: Optional[datetime] = None,
                       end_time: Optional[datetime] = None) -> List[AuditLogEntry]:
        """
        Retrieve audit trail with optional filtering.
        
        Args:
            event_type: Filter by event type
            start_time: Filter by start time
            end_time: Filter by end time
            
        Returns:
            List of AuditLogEntry objects
        """
        entries = []
        
        # Read from case audit log if available
        log_file = self.case_audit_file if self.case_audit_file and self.case_audit_file.exists() else self.system_audit_file
        
        if not log_file.exists():
            return entries
        
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    entry = AuditLogEntry.from_dict(data)
                    
                    # Apply filters
                    if event_type and entry.event_type != event_type.value:
                        continue
                    
                    entry_time = datetime.fromisoformat(entry.timestamp)
                    if start_time and entry_time < start_time:
                        continue
                    if end_time and entry_time > end_time:
                        continue
                    
                    entries.append(entry)
                except json.JSONDecodeError:
                    self.console_logger.warning(f"Skipping malformed log entry: {line}")
        
        return entries
    
    def export_chain_of_custody(self, output_path: Path) -> Path:
        """
        Export complete chain of custody report.
        
        Args:
            output_path: Where to save the report
            
        Returns:
            Path to generated report
        """
        entries = self.get_audit_trail()
        
        report = {
            "case_id": self.case_id,
            "generated_at": datetime.now().isoformat(),
            "total_events": len(entries),
            "event_types": list(set(e.event_type for e in entries)),
            "operators": list(set(e.operator for e in entries)),
            "entries": [e.to_dict() for e in entries]
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.console_logger.info(f"Chain of custody exported: {output_path}")
        
        return output_path
    
    def export_markdown_report(self, output_path: Path) -> Path:
        """
        Export audit trail as markdown report for court.
        
        Args:
            output_path: Where to save the report
            
        Returns:
            Path to generated report
        """
        entries = self.get_audit_trail()
        
        lines = [
            f"# Audit Trail Report",
            f"",
            f"**Case ID**: {self.case_id}  ",
            f"**Generated**: {datetime.now().isoformat()}  ",
            f"**Total Events**: {len(entries)}  ",
            f"",
            f"## Chain of Custody",
            f"",
            f"| Timestamp | Event Type | Operator | Action | Details |",
            f"|-----------|------------|----------|--------|---------|"
        ]
        
        for entry in entries:
            details = json.dumps(entry.details) if entry.details else ""
            lines.append(
                f"| {entry.timestamp} | {entry.event_type} | {entry.operator} | {entry.action} | {details[:50]} |"
            )
        
        lines.extend([
            f"",
            f"## Event Summary",
            f""
        ])
        
        # Event type summary
        event_counts = {}
        for entry in entries:
            event_counts[entry.event_type] = event_counts.get(entry.event_type, 0) + 1
        
        lines.append("| Event Type | Count |")
        lines.append("|------------|-------|")
        for event_type, count in sorted(event_counts.items()):
            lines.append(f"| {event_type} | {count} |")
        
        # Write to file
        markdown = "\n".join(lines)
        with open(output_path, 'w') as f:
            f.write(markdown)
        
        self.console_logger.info(f"Markdown report exported: {output_path}")
        
        return output_path


if __name__ == "__main__":
    # Test audit logger
    logging.basicConfig(level=logging.INFO)
    
    # Create test logger
    case_path = Path("cases/TEST_AUDIT")
    case_path.mkdir(parents=True, exist_ok=True)
    
    audit_logger = ForensicAuditLogger(
        case_id="TEST_AUDIT",
        case_path=case_path,
        operator="test_analyst"
    )
    
    # Log some events
    audit_logger.log_evidence_upload(
        Path("evidence.e01"),
        "abc123...",
        1024000
    )
    
    audit_logger.log_ml_prediction(
        "malware_classifier",
        prediction=1,
        confidence=0.85,
        evidence_id="FILE001"
    )
    
    audit_logger.log_analyst_action(
        "Reviewed ML findings",
        {"findings": 3, "flagged": 1}
    )
    
    # Export chain of custody
    coc_path = case_path / "chain_of_custody.json"
    audit_logger.export_chain_of_custody(coc_path)
    
    # Export markdown report
    md_path = case_path / "audit_report.md"
    audit_logger.export_markdown_report(md_path)
    
    print("\n✓ Audit logging test complete")
    print(f"Chain of custody: {coc_path}")
    print(f"Markdown report: {md_path}")

"""
Forensic Audit Logging Module
Comprehensive logging of all evidence handling operations for court defensibility.
"""

import logging
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from enum import Enum


class AuditEventType(Enum):
    """Types of auditable events."""
    EVIDENCE_VALIDATION_STARTED = "evidence_validation_started"
    EVIDENCE_VALIDATION_SUCCESS = "evidence_validation_success"
    EVIDENCE_VALIDATION_FAILED = "evidence_validation_failed"
    EVIDENCE_HASH_CALCULATED = "evidence_hash_calculated"
    EVIDENCE_INGESTED = "evidence_ingested"
    CASE_CREATED = "case_created"
    CASE_ACCESSED = "case_accessed"
    CASE_DELETED = "case_deleted"
    ML_PREDICTION_MADE = "ml_prediction_made"
    ML_INTEGRITY_VERIFIED = "ml_integrity_verified"
    ML_INTEGRITY_FAILED = "ml_integrity_failed"
    ARTIFACT_EXTRACTED = "artifact_extracted"
    SEARCH_EXECUTED = "search_executed"
    EXPORT_PERFORMED = "export_performed"
    TOCTOU_VIOLATION_DETECTED = "toctou_violation_detected"
    E01_HEADER_VALIDATION = "e01_header_validation"
    MIXED_EVIDENCE_DETECTED = "mixed_evidence_detected"
    DUPLICATE_EVIDENCE_DETECTED = "duplicate_evidence_detected"


class ForensicAuditLogger:
    """
    Court-grade audit logging for all forensic operations.
    Provides immutable audit trail for legal defensibility.
    """
    
    def __init__(self, case_dir: Optional[Path] = None):
        """
        Initialize forensic audit logger.
        
        Args:
            case_dir: Case directory (optional, for case-specific logs)
        """
        self.case_dir = case_dir
        
        if case_dir:
            self.audit_log_file = case_dir / "forensic_audit.log"
            self.audit_json_file = case_dir / "forensic_audit.json"
        else:
            # Global audit log
            global_log_dir = Path("logs")
            global_log_dir.mkdir(exist_ok=True)
            self.audit_log_file = global_log_dir / "fepd_global_audit.log"
            self.audit_json_file = global_log_dir / "fepd_global_audit.json"
        
        self.logger = logging.getLogger(__name__)
        self._init_audit_log()
    
    def _init_audit_log(self):
        """Initialize audit log files."""
        # Create JSON file if it doesn't exist
        if not self.audit_json_file.exists():
            with open(self.audit_json_file, 'w') as f:
                json.dump({"version": "1.0.0", "events": []}, f, indent=2)
    
    def _append_to_json_log(self, event: Dict[str, Any]):
        """Append event to JSON audit log."""
        try:
            # Read existing log
            with open(self.audit_json_file, 'r') as f:
                log_data = json.load(f)
            
            # Append new event
            log_data["events"].append(event)
            
            # Write back
            with open(self.audit_json_file, 'w') as f:
                json.dump(log_data, f, indent=2)
        
        except Exception as e:
            self.logger.error(f"Failed to append to JSON audit log: {e}")
    
    def log_event(
        self,
        event_type: AuditEventType,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        case_id: Optional[str] = None,
        success: bool = True
    ):
        """
        Log a forensic audit event.
        
        Args:
            event_type: Type of event
            description: Human-readable description
            metadata: Additional event metadata
            user: User/investigator performing action
            evidence_hash: SHA-256 hash of evidence (if applicable)
            case_id: Case ID (if applicable)
            success: Whether operation succeeded
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Create audit event
        event = {
            "timestamp": timestamp,
            "event_type": event_type.value,
            "description": description,
            "success": success,
            "user": user,
            "case_id": case_id,
            "evidence_hash": evidence_hash,
            "metadata": metadata or {}
        }
        
        # Log to text file
        with open(self.audit_log_file, 'a') as f:
            f.write(
                f"[{timestamp}] {event_type.value.upper()} | "
                f"Success={success} | User={user} | Case={case_id} | "
                f"Evidence={evidence_hash[:16] + '...' if evidence_hash else 'N/A'} | "
                f"{description}\n"
            )
        
        # Append to JSON log
        self._append_to_json_log(event)
        
        # Also log to standard logger
        log_level = logging.INFO if success else logging.ERROR
        self.logger.log(
            log_level,
            f"AUDIT: {event_type.value} - {description} (success={success})"
        )
    
    def log_validation_started(self, file_paths: list, user: str):
        """Log evidence validation start."""
        self.log_event(
            AuditEventType.EVIDENCE_VALIDATION_STARTED,
            f"Started validation of {len(file_paths)} file(s)",
            metadata={"file_paths": [str(p) for p in file_paths]},
            user=user
        )
    
    def log_validation_success(
        self,
        file_paths: list,
        evidence_type: str,
        primary_hash: str,
        user: str
    ):
        """Log successful evidence validation."""
        self.log_event(
            AuditEventType.EVIDENCE_VALIDATION_SUCCESS,
            f"Successfully validated {evidence_type} evidence",
            metadata={
                "file_paths": [str(p) for p in file_paths],
                "evidence_type": evidence_type
            },
            user=user,
            evidence_hash=primary_hash,
            success=True
        )
    
    def log_validation_failed(
        self,
        file_paths: list,
        error_message: str,
        user: str
    ):
        """Log failed evidence validation."""
        self.log_event(
            AuditEventType.EVIDENCE_VALIDATION_FAILED,
            f"Evidence validation FAILED: {error_message}",
            metadata={
                "file_paths": [str(p) for p in file_paths],
                "error": error_message
            },
            user=user,
            success=False
        )
    
    def log_toctou_violation(
        self,
        file_path: str,
        validation_time: str,
        ingestion_time: str,
        user: str
    ):
        """Log TOCTOU violation detection."""
        self.log_event(
            AuditEventType.TOCTOU_VIOLATION_DETECTED,
            f"CRITICAL: File modified between validation and ingestion: {file_path}",
            metadata={
                "file_path": file_path,
                "validation_time": validation_time,
                "ingestion_time": ingestion_time
            },
            user=user,
            success=False
        )
    
    def log_e01_validation(
        self,
        file_path: str,
        is_valid: bool,
        user: str
    ):
        """Log E01 header validation."""
        self.log_event(
            AuditEventType.E01_HEADER_VALIDATION,
            f"E01 header validation: {'PASSED' if is_valid else 'FAILED'} for {file_path}",
            metadata={"file_path": file_path, "is_valid_e01": is_valid},
            user=user,
            success=is_valid
        )
    
    def log_mixed_evidence(
        self,
        detected_patterns: list,
        user: str
    ):
        """Log mixed evidence set detection."""
        self.log_event(
            AuditEventType.MIXED_EVIDENCE_DETECTED,
            f"CRITICAL: Mixed evidence patterns detected: {detected_patterns}",
            metadata={"patterns": detected_patterns},
            user=user,
            success=False
        )
    
    def log_duplicate_evidence(
        self,
        evidence_hash: str,
        original_case_id: str,
        user: str
    ):
        """Log duplicate evidence detection."""
        self.log_event(
            AuditEventType.DUPLICATE_EVIDENCE_DETECTED,
            f"Duplicate evidence detected - already in case {original_case_id}",
            metadata={"original_case": original_case_id},
            user=user,
            evidence_hash=evidence_hash,
            success=False
        )
    
    def log_case_created(
        self,
        case_id: str,
        evidence_hash: str,
        user: str
    ):
        """Log case creation."""
        self.log_event(
            AuditEventType.CASE_CREATED,
            f"Case created: {case_id}",
            user=user,
            case_id=case_id,
            evidence_hash=evidence_hash,
            success=True
        )
    
    def log_ml_prediction(
        self,
        artifact_path: str,
        artifact_hash: str,
        model_name: str,
        prediction: str,
        confidence: float,
        user: str,
        case_id: str
    ):
        """Log ML prediction."""
        self.log_event(
            AuditEventType.ML_PREDICTION_MADE,
            f"ML prediction: {model_name} on {artifact_path}",
            metadata={
                "artifact_path": artifact_path,
                "model_name": model_name,
                "prediction": prediction,
                "confidence": confidence
            },
            user=user,
            case_id=case_id,
            evidence_hash=artifact_hash
        )
    
    def log_ml_integrity_check(
        self,
        artifact_path: str,
        is_valid: bool,
        user: str,
        case_id: str
    ):
        """Log ML integrity verification."""
        event_type = (
            AuditEventType.ML_INTEGRITY_VERIFIED 
            if is_valid 
            else AuditEventType.ML_INTEGRITY_FAILED
        )
        
        self.log_event(
            event_type,
            f"ML integrity check {'PASSED' if is_valid else 'FAILED'}: {artifact_path}",
            metadata={"artifact_path": artifact_path},
            user=user,
            case_id=case_id,
            success=is_valid
        )

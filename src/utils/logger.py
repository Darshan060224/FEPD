"""
Logging Configuration Module
Sets up comprehensive logging for FEPD
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional
from datetime import datetime


def setup_logging(config, log_level: Optional[str] = None):
    """
    Configure application-wide logging.
    
    Args:
        config: Configuration object
        log_level: Override log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Get log configuration
    level = log_level or config.get('LOG_LEVEL', 'INFO')
    log_file = config.get_path('LOG_FILE', Path('logs/fepd.log'))
    audit_log_file = config.get_path('AUDIT_LOG_FILE', Path('logs/audit.log'))
    max_bytes = config.get_int('LOG_MAX_SIZE_MB', 100) * 1024 * 1024
    backup_count = config.get_int('LOG_BACKUP_COUNT', 5)
    
    # Create logs directory
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with color formatting
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)
    
    # Audit logger (separate file for security events)
    if config.get_bool('AUDIT_LOGGING', True):
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False
        
        audit_handler = logging.handlers.RotatingFileHandler(
            audit_log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        audit_format = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        audit_handler.setFormatter(audit_format)
        audit_logger.addHandler(audit_handler)
    
    logging.info("Logging system initialized")


class ForensicLogger:
    """
    Specialized logger for forensic operations.
    Ensures all forensic actions are logged with proper context.
    """
    
    def __init__(self, name: str):
        """Initialize forensic logger."""
        self.logger = logging.getLogger(f"forensic.{name}")
        self.audit = logging.getLogger("audit")
    
    def log_evidence_access(self, image_path: str, operation: str, hash_value: str):
        """Log evidence access with full details."""
        msg = f"Evidence Access - Path: {image_path}, Operation: {operation}, Hash: {hash_value}"
        self.logger.info(msg)
        self.audit.info(msg)
    
    def log_artifact_extraction(self, artifact_path: str, hash_value: str):
        """Log artifact extraction."""
        msg = f"Artifact Extracted - Path: {artifact_path}, Hash: {hash_value}"
        self.logger.info(msg)
        self.audit.info(msg)
    
    def log_parsing_start(self, artifact_type: str, count: int):
        """Log start of parsing operation."""
        msg = f"Parsing Started - Type: {artifact_type}, Count: {count}"
        self.logger.info(msg)
    
    def log_parsing_complete(self, artifact_type: str, records_parsed: int, duration: float):
        """Log completion of parsing operation."""
        msg = f"Parsing Complete - Type: {artifact_type}, Records: {records_parsed}, Duration: {duration:.2f}s"
        self.logger.info(msg)
    
    def log_classification(self, event_count: int, duration: float):
        """Log classification operation."""
        msg = f"Classification Complete - Events: {event_count}, Duration: {duration:.2f}s"
        self.logger.info(msg)
    
    def log_report_generation(self, report_path: str, report_hash: str):
        """Log report generation."""
        msg = f"Report Generated - Path: {report_path}, Hash: {report_hash}"
        self.logger.info(msg)
        self.audit.info(msg)
    
    def log_error(self, operation: str, error: str):
        """Log forensic operation error."""
        msg = f"Forensic Error - Operation: {operation}, Error: {error}"
        self.logger.error(msg)
        self.audit.error(msg)
    
    def log_integrity_violation(self, detail: str):
        """Log integrity violation (critical security event)."""
        msg = f"INTEGRITY VIOLATION - {detail}"
        self.logger.critical(msg)
        self.audit.critical(msg)
    
    # Standard logging methods for compatibility
    def info(self, msg: str, *args, **kwargs):
        """Log info message."""
        self.logger.info(msg, *args, **kwargs)
    
    def debug(self, msg: str, *args, **kwargs):
        """Log debug message."""
        self.logger.debug(msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs):
        """Log warning message."""
        self.logger.warning(msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        """Log error message."""
        self.logger.error(msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs):
        """Log critical message."""
        self.logger.critical(msg, *args, **kwargs)

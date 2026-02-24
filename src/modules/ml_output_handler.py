"""
FEPD - ML Output Handler
Standardized output for all ML results - ensures findings are visible everywhere.

This module solves the "nothing returns" problem by providing a consistent
output contract for all ML modules.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class MLEntity:
    """Entity that was analyzed."""
    user_id: str
    device_id: str
    platform: str  # 'android', 'ios', 'windows', 'linux'


@dataclass
class MLFinding:
    """Single ML finding/anomaly."""
    finding_id: str
    entity: MLEntity
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    score: float  # 0.0 - 1.0
    explanations: List[str]
    correlations: List[str]
    recommendation: str
    model_metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['entity'] = asdict(self.entity)
        return data


class MLOutputHandler:
    """
    Handles all ML output writing - JSON, timeline events, report sections.
    
    Usage:
        handler = MLOutputHandler(case_path)
        handler.write_findings(module='MOBILE_UEBA', findings=[...])
    """
    
    def __init__(self, case_path: Path, logger: Optional[logging.Logger] = None):
        """
        Initialize ML output handler.
        
        Args:
            case_path: Path to case directory
            logger: Optional logger instance
        """
        self.case_path = Path(case_path)
        self.logger = logger or logging.getLogger(__name__)
        
        # Create output directories
        self.results_dir = self.case_path / "results"
        self.timeline_dir = self.case_path / "timeline"
        self.reports_dir = self.case_path / "reports"
        
        for dir_path in [self.results_dir, self.timeline_dir, self.reports_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def write_findings(
        self,
        module: str,
        findings: List[MLFinding],
        status: str = "COMPLETED",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Write ML findings to JSON file (PRIMARY OUTPUT).
        
        Args:
            module: Module name (e.g., 'MOBILE_UEBA', 'DISK_ANOMALY')
            findings: List of ML findings
            status: Completion status
            metadata: Optional additional metadata
            
        Returns:
            Path to written JSON file
        """
        output = {
            "case_id": self.case_path.name,
            "module": module,
            "status": status,
            "summary": {
                "entities_analyzed": len(set(f.entity.user_id for f in findings)),
                "anomalies_detected": len(findings),
                "confidence": self._calculate_overall_confidence(findings)
            },
            "findings": [f.to_dict() for f in findings],
            "generated_at": datetime.utcnow().isoformat() + "Z"
        }
        
        if metadata:
            output["metadata"] = metadata
        
        # Write to JSON file
        output_file = self.results_dir / f"{module.lower()}_findings.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"✅ ML findings written to: {output_file}")
        self.logger.info(f"   Module: {module}, Findings: {len(findings)}, Status: {status}")
        
        # Also write timeline events
        self._write_timeline_events(module, findings)
        
        # Generate report section
        self._write_report_section(module, findings)
        
        return output_file
    
    def _calculate_overall_confidence(self, findings: List[MLFinding]) -> str:
        """Calculate overall confidence level."""
        if not findings:
            return "N/A"
        
        avg_score = sum(f.score for f in findings) / len(findings)
        
        if avg_score >= 0.85:
            return "HIGH"
        elif avg_score >= 0.65:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _write_timeline_events(self, module: str, findings: List[MLFinding]) -> None:
        """Write ML findings as timeline events."""
        timeline_file = self.timeline_dir / "ml_events.json"
        
        # Load existing events if file exists
        events = []
        if timeline_file.exists():
            try:
                with open(timeline_file, 'r', encoding='utf-8') as f:
                    events = json.load(f)
            except:
                events = []
        
        # Add new events
        for finding in findings:
            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "UEBA_ALERT" if "UEBA" in module else "ML_ALERT",
                "source": "ML",
                "severity": finding.severity,
                "description": f"ML Alert: {finding.explanations[0] if finding.explanations else 'Anomaly detected'}",
                "linked_finding": finding.finding_id,
                "module": module
            }
            events.append(event)
        
        # Write back
        with open(timeline_file, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2)
        
        self.logger.info(f"✅ Timeline events written: {len(findings)} new events")
    
    def _write_report_section(self, module: str, findings: List[MLFinding]) -> None:
        """Generate forensic report section (court-safe language)."""
        report_file = self.reports_dir / f"{module.lower()}_section.md"
        
        if "MOBILE" in module and "UEBA" in module:
            content = self._generate_mobile_ueba_report(findings)
        else:
            content = self._generate_generic_ml_report(module, findings)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.logger.info(f"✅ Report section written to: {report_file}")
    
    def _generate_mobile_ueba_report(self, findings: List[MLFinding]) -> str:
        """Generate mobile UEBA report section."""
        if not findings:
            return """### Mobile Behavioral Analysis (UEBA)

An automated behavioral analysis was conducted on mobile device artifacts extracted from the submitted evidence.

No statistically significant deviations from established user behavior patterns were identified during the analysis period.

This result indicates that observed activity fell within expected behavioral ranges based on available data.
"""
        
        # Has findings
        report = """### Mobile Behavioral Analysis (UEBA)

An automated behavioral analysis was conducted on mobile device artifacts extracted from the submitted evidence.

This analysis evaluates deviations from previously observed user behavior patterns using statistical and machine learning techniques. The results are intended to assist investigators in prioritizing areas for further review.

"""
        
        if len(findings) == 1:
            report += "One behavioral deviation of high significance was identified for a mobile device associated with the examined user account.\n\n"
        else:
            report += f"{len(findings)} behavioral deviations were identified across the examined mobile devices.\n\n"
        
        for idx, finding in enumerate(findings, 1):
            report += f"#### Finding {idx}: {finding.finding_id}\n\n"
            report += f"**Entity:** {finding.entity.user_id} / {finding.entity.platform}\n"
            report += f"**Severity:** {finding.severity}\n"
            report += f"**Deviation Score:** {finding.score:.2f}\n\n"
            
            report += "**Observed Indicators:**\n"
            for explanation in finding.explanations:
                report += f"- {explanation}\n"
            report += "\n"
            
            if finding.correlations:
                report += "**Correlated Evidence:**\n"
                for correlation in finding.correlations:
                    report += f"- {correlation}\n"
                report += "\n"
            
            report += f"**Recommendation:** {finding.recommendation}\n\n"
        
        report += """---

**Important Note:** These findings do not by themselves indicate malicious intent. They represent automated identification of atypical behavior and should be evaluated in conjunction with other forensic evidence.
"""
        
        return report
    
    def _generate_generic_ml_report(self, module: str, findings: List[MLFinding]) -> str:
        """Generate generic ML report section."""
        if not findings:
            return f"""### {module} Analysis

An automated analysis was conducted using machine learning techniques.

No significant anomalies or deviations were detected during the analysis period.
"""
        
        report = f"""### {module} Analysis

An automated analysis was conducted using machine learning techniques. {len(findings)} finding(s) of interest were identified.

"""
        
        for idx, finding in enumerate(findings, 1):
            report += f"**Finding {idx}:** {finding.finding_id}\n"
            report += f"- Severity: {finding.severity}\n"
            report += f"- Score: {finding.score:.2f}\n"
            for explanation in finding.explanations:
                report += f"- {explanation}\n"
            report += "\n"
        
        return report
    
    def write_empty_result(self, module: str, reason: str = "No data available") -> Path:
        """
        Write an empty result (important - no silent failures).
        
        Args:
            module: Module name
            reason: Why no results
            
        Returns:
            Path to written JSON file
        """
        output = {
            "case_id": self.case_path.name,
            "module": module,
            "status": "COMPLETED",
            "summary": {
                "entities_analyzed": 0,
                "anomalies_detected": 0,
                "confidence": "N/A",
                "reason": reason
            },
            "findings": [],
            "generated_at": datetime.utcnow().isoformat() + "Z"
        }
        
        output_file = self.results_dir / f"{module.lower()}_findings.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        
        self.logger.info(f"✅ Empty result written for {module}: {reason}")
        
        # Still generate report section
        self._write_report_section(module, [])
        
        return output_file

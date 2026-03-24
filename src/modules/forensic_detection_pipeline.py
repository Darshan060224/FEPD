"""
FEPD Forensic Detection Pipeline

Implementation-focused orchestration for:
1. E01/DD extraction -> filesystem + registry artifacts
2. Structured registry intelligence parsing
3. Memory dump live-state reconstruction
4. Cross-source correlation and malware-chain detection
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .artifact_extractor import extract_artifacts_from_image
from .memory_analyzer import MemoryAnalyzer
from ..parsers.mft_parser import MFTParser
from ..parsers.prefetch_parser import PrefetchParser
from ..parsers.registry_parser import RegistryParser


logger = logging.getLogger(__name__)


@dataclass
class DetectionFinding:
    executable: str
    execution_time: str
    file_state: str
    process_seen: bool
    network_seen: bool
    remote_ips: List[str]
    score: int
    verdict: str
    evidence: Dict[str, Any]


class CorrelationEngine:
    """Correlate execution, disk-state, memory-process, and network evidence."""

    def detect_deleted_executed_connected(
        self,
        execution_artifacts: List[Dict[str, Any]],
        mft_events: List[Dict[str, Any]],
        memory_processes: List[Dict[str, Any]],
        memory_connections: List[Dict[str, Any]],
        suspicious_ips: Optional[Set[str]] = None,
    ) -> List[DetectionFinding]:
        suspicious_ips = suspicious_ips or set()
        findings: List[DetectionFinding] = []

        mft_paths = {
            (e.get("filepath") or "").lower()
            for e in mft_events
            if isinstance(e, dict)
        }

        proc_names = {
            (p.get("name") or "").lower()
            for p in memory_processes
            if isinstance(p, dict)
        }

        for exec_art in execution_artifacts:
            exe = (exec_art.get("exe_name") or "").lower()
            if not exe:
                continue

            exe_stem = exe[:-4] if exe.endswith(".exe") else exe
            execution_time = str(exec_art.get("ts_utc") or "")

            path_on_disk = str(exec_art.get("artifact_path") or "").lower()
            present_in_mft = any(
                exe in p or exe_stem in p
                for p in mft_paths
            )

            file_state = "Present" if present_in_mft else "DeletedOrMissing"
            process_seen = any(exe in p or exe_stem in p for p in proc_names)

            remote_ips = []
            for conn in memory_connections:
                ip = str(conn.get("ip") or conn.get("remote_ip") or "")
                if ip:
                    remote_ips.append(ip)
            network_seen = len(remote_ips) > 0

            score = 0
            if exec_art:
                score += 30
            if file_state == "DeletedOrMissing":
                score += 20
            if process_seen:
                score += 30
            if network_seen:
                score += 40

            if suspicious_ips:
                if any(ip in suspicious_ips for ip in remote_ips):
                    score += 20

            if score >= 120:
                verdict = "Critical"
            elif score >= 80:
                verdict = "High"
            elif score >= 40:
                verdict = "Medium"
            else:
                verdict = "Low"

            if score < 80:
                continue

            findings.append(
                DetectionFinding(
                    executable=exe,
                    execution_time=execution_time,
                    file_state=file_state,
                    process_seen=process_seen,
                    network_seen=network_seen,
                    remote_ips=sorted(set(remote_ips)),
                    score=score,
                    verdict=verdict,
                    evidence={
                        "execution_artifact": exec_art,
                        "matching_mft_paths": [p for p in mft_paths if exe in p or exe_stem in p][:20],
                    },
                )
            )

        return findings


class ForensicDetectionPipeline:
    """Runs extraction, parsing, memory reconstruction, and correlation."""

    def __init__(
        self,
        image_path: str,
        output_dir: str,
        memory_dump: Optional[str] = None,
        memory_scan_limit_bytes: Optional[int] = None,
    ):
        self.image_path = str(image_path)
        self.memory_dump = str(memory_dump) if memory_dump else None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.registry_parser = RegistryParser()
        self.prefetch_parser = PrefetchParser()
        self.mft_parser = MFTParser()
        self.correlation_engine = CorrelationEngine()

        # Full memory parsing is the default for forensic completeness.
        # Optional limit can be provided explicitly or via env for constrained runs.
        env_limit_raw = os.getenv("FEPD_MEMORY_SCAN_LIMIT_BYTES", "").strip()
        env_limit: Optional[int] = None
        if env_limit_raw:
            try:
                parsed = int(env_limit_raw)
                env_limit = parsed if parsed > 0 else None
            except ValueError:
                env_limit = None

        self.memory_scan_limit_bytes = (
            memory_scan_limit_bytes
            if memory_scan_limit_bytes is not None
            else env_limit
        )

    def run(self, suspicious_ips: Optional[List[str]] = None) -> Dict[str, Any]:
        started = datetime.utcnow().isoformat() + "Z"

        extraction_output = self.output_dir / "extracted_artifacts"
        extraction_results = extract_artifacts_from_image(
            self.image_path,
            str(extraction_output),
            verify_hash=True,
        )

        structured_registry = self._parse_structured_registry(extraction_output)
        prefetch_events = self._parse_prefetch(extraction_output)
        mft_events = self._parse_mft(extraction_output)

        memory_state: Dict[str, Any] = {}
        if self.memory_dump:
            memory_state = self._reconstruct_memory_state(prefetch_events)

        findings = self.correlation_engine.detect_deleted_executed_connected(
            execution_artifacts=prefetch_events,
            mft_events=mft_events,
            memory_processes=memory_state.get("processes", []),
            memory_connections=memory_state.get("network_connections", []),
            suspicious_ips={ip.strip() for ip in (suspicious_ips or []) if ip.strip()},
        )

        timeline = self._build_timeline(prefetch_events, mft_events, memory_state)

        result = {
            "started_at": started,
            "completed_at": datetime.utcnow().isoformat() + "Z",
            "image_path": self.image_path,
            "memory_dump": self.memory_dump,
            "extraction": extraction_results,
            "registry": structured_registry,
            "prefetch_events": prefetch_events,
            "mft_events_count": len(mft_events),
            "memory": memory_state,
            "detections": [asdict(f) for f in findings],
            "timeline": timeline,
            "summary": {
                "registry_hives_parsed": len(structured_registry),
                "prefetch_events": len(prefetch_events),
                "mft_events": len(mft_events),
                "detections": len(findings),
                "high_or_critical": len([f for f in findings if f.verdict in {"High", "Critical"}]),
            },
        }

        output_file = self.output_dir / "forensic_detection_results.json"
        output_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        logger.info("Forensic detection results saved: %s", output_file)

        return result

    def _parse_structured_registry(self, extraction_output: Path) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        for hive_name in ["SYSTEM", "SOFTWARE"]:
            for hive_path in extraction_output.rglob(hive_name):
                try:
                    parsed = self.registry_parser.parse_structured_artifacts(hive_path, hive_name=hive_name)
                    data[f"{hive_name}:{hive_path}"] = parsed
                except Exception as exc:
                    data[f"{hive_name}:{hive_path}"] = {"error": str(exc)}
        return data

    def _parse_prefetch(self, extraction_output: Path) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for pf_path in extraction_output.rglob("*.pf"):
            try:
                events.extend(self.prefetch_parser.parse_file(pf_path))
            except Exception:
                continue
        return events

    def _parse_mft(self, extraction_output: Path) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        mft_cap_raw = os.getenv("FEPD_MFT_MAX_RECORDS", "").strip()
        mft_cap: Optional[int] = None
        if mft_cap_raw:
            try:
                parsed = int(mft_cap_raw)
                mft_cap = parsed if parsed > 0 else None
            except ValueError:
                mft_cap = None

        for mft_path in extraction_output.rglob("$MFT"):
            try:
                events.extend(self.mft_parser.parse_file(mft_path, max_records=mft_cap))
            except Exception:
                continue
        return events

    def _reconstruct_memory_state(self, prefetch_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        expected = [
            str(e.get("exe_name") or "").lower()
            for e in prefetch_events
            if e.get("exe_name")
        ]
        analyzer = MemoryAnalyzer(self.memory_dump or "")
        return analyzer.reconstruct_live_state(
            expected_executables=expected,
            max_scan_bytes=self.memory_scan_limit_bytes,
        )

    def _build_timeline(
        self,
        prefetch_events: List[Dict[str, Any]],
        mft_events: List[Dict[str, Any]],
        memory_state: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []

        for e in prefetch_events:
            timeline.append(
                {
                    "timestamp": e.get("ts_utc"),
                    "type": "execution",
                    "detail": e.get("description"),
                }
            )

        for e in mft_events[:20000]:
            timeline.append(
                {
                    "timestamp": e.get("ts_utc"),
                    "type": "file_activity",
                    "detail": e.get("description"),
                }
            )

        for c in memory_state.get("network_connections", []):
            timeline.append(
                {
                    "timestamp": memory_state.get("analysis_time"),
                    "type": "network",
                    "detail": f"{c.get('ip')}:{c.get('port')}",
                }
            )

        timeline = [t for t in timeline if t.get("timestamp")]
        timeline.sort(key=lambda item: str(item.get("timestamp")))
        return timeline


def run_forensic_detection_pipeline(
    image_path: str,
    output_dir: str,
    memory_dump: Optional[str] = None,
    suspicious_ips: Optional[List[str]] = None,
    memory_scan_limit_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """Convenience entrypoint for one-shot pipeline execution."""
    pipeline = ForensicDetectionPipeline(
        image_path=image_path,
        output_dir=output_dir,
        memory_dump=memory_dump,
        memory_scan_limit_bytes=memory_scan_limit_bytes,
    )
    return pipeline.run(suspicious_ips=suspicious_ips)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run full FEPD forensic detection pipeline")
    parser.add_argument("image", help="Path to E01/DD/RAW image")
    parser.add_argument("--memory", help="Path to memory dump (.mem/.dmp)", default=None)
    parser.add_argument("--out", help="Output directory", default="output/forensic_detection")
    parser.add_argument(
        "--ioc-ip",
        action="append",
        default=[],
        help="Suspicious remote IP (repeat flag for multiple IPs)",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    run_forensic_detection_pipeline(
        image_path=args.image,
        memory_dump=args.memory,
        output_dir=args.out,
        suspicious_ips=args.ioc_ip,
    )
"""Pipeline and hydration contract tests for FEPD.

These tests validate the core architecture path:
Case Context -> Unified Store -> Forensic Tab Engine -> Routed section payloads.

They are intentionally data-contract focused (headless, non-GUI) so they can run
in CI and quickly detect regressions in synchronization logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.services.forensic_tab_engine import ForensicTabExtractionEngine
from src.services.unified_forensic_store import UnifiedForensicStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REAL_CASE_PATH = PROJECT_ROOT / "cases" / "real"


def _require_real_case() -> Path:
    if not REAL_CASE_PATH.exists():
        pytest.skip("cases/real is not available in this workspace")
    return REAL_CASE_PATH


def _engine_for_real_case() -> tuple[UnifiedForensicStore, ForensicTabExtractionEngine]:
    case_path = _require_real_case()
    store = UnifiedForensicStore(case_path)
    store.rebuild_case_index()
    return store, ForensicTabExtractionEngine(store)


def test_unified_store_rebuild_has_indexed_records() -> None:
    store, _ = _engine_for_real_case()
    stats = store.rebuild_case_index()

    assert stats.get("files", 0) > 0, "Unified store should index at least one file"
    assert stats.get("artifacts", 0) > 0, "Unified store should index at least one artifact"


def test_forensic_sections_have_expected_schema() -> None:
    _, engine = _engine_for_real_case()

    expected = {
        "Activity Timeline": "events",
        "Top Findings": "findings",
        "Anomaly Detection": "anomalies",
        "UEBA Profiling": "profiles",
        "Network Intrusion": "events",
        "Threat Intelligence": "indicators",
    }

    for section, top_key in expected.items():
        payload = engine.extract_section(section)
        assert payload.get("section") == section
        assert isinstance(payload.get("fields"), dict)
        assert top_key in payload["fields"], f"Missing '{top_key}' in {section}"
        assert isinstance(payload["fields"][top_key], list), f"{section}.{top_key} must be a list"


def test_network_intrusion_events_have_timestamp_when_present() -> None:
    _, engine = _engine_for_real_case()
    events = engine.extract_section("Network Intrusion").get("fields", {}).get("events", [])

    if not events:
        pytest.skip("No network intrusion events produced for this case")

    missing_ts = [e for e in events if not e.get("timestamp")]
    assert not missing_ts, "All network intrusion events must include a timestamp"


def test_anomaly_section_matches_top_findings_threshold_logic() -> None:
    _, engine = _engine_for_real_case()

    findings = engine.extract_section("Top Findings").get("fields", {}).get("findings", [])
    anomalies = engine.extract_section("Anomaly Detection").get("fields", {}).get("anomalies", [])

    expected_count = sum(1 for f in findings if int(f.get("risk_score") or 0) >= 60)
    assert len(anomalies) == expected_count, (
        "Anomaly section must deterministically reflect Top Findings threshold logic"
    )


def test_case_metadata_contains_evidence_image_contract() -> None:
    case_path = _require_real_case()
    case_json = case_path / "case.json"

    assert case_json.exists(), "case.json must exist for active case"

    import json

    payload = json.loads(case_json.read_text(encoding="utf-8"))
    evidence = payload.get("evidence_image", {})

    assert isinstance(evidence, dict), "case.json.evidence_image must be an object"
    assert str(evidence.get("filename") or "").strip(), "evidence_image.filename must be present"
    assert str(evidence.get("path") or "").strip(), "evidence_image.path must be present"

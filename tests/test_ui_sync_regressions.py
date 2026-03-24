"""UI synchronization regression tests for recently fixed tab/data issues."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from PyQt6.QtWidgets import QApplication

from src.core.case_manager import CaseManager
from src.ui.tabs.case_details_tab import CaseDetailsTab
from src.ui.tabs.image_ingest_tab import ImageIngestTab


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _write_case_json(case_path: Path) -> None:
    payload = {
        "case_id": case_path.name,
        "case_name": case_path.name,
        "investigator": "tester",
        "created_date": "2026-03-21T10:00:00",
        "last_modified": "2026-03-21T12:00:00",
        "status": "open",
        "evidence_image": {
            "path": "C:/evidence/LoneWolf.E01",
            "filename": "LoneWolf.E01",
            "size_bytes": 123456789,
            "sha256_hash": "abc",
        },
    }
    (case_path / "case.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_case_db_with_ui_tables(case_path: Path, files: int = 10, artifacts: int = 5) -> None:
    db = case_path / "case.db"
    conn = sqlite3.connect(str(db))
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS ui_files (id INTEGER PRIMARY KEY, name TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS ui_artifacts (id INTEGER PRIMARY KEY, type TEXT)")
    cur.execute("DELETE FROM ui_files")
    cur.execute("DELETE FROM ui_artifacts")
    for i in range(files):
        cur.execute("INSERT INTO ui_files (name) VALUES (?)", (f"file_{i}",))
    for i in range(artifacts):
        cur.execute("INSERT INTO ui_artifacts (type) VALUES (?)", ("execution",))
    conn.commit()
    conn.close()


def test_case_details_reads_runtime_ml_summary(tmp_path: Path, qapp: QApplication) -> None:
    case_path = tmp_path / "case_rt"
    (case_path / "results").mkdir(parents=True)
    _write_case_json(case_path)
    _write_case_db_with_ui_tables(case_path, files=3, artifacts=2)

    runtime_summary = {
        "generated_at": "2026-03-21T12:34:56Z",
        "anomalies_detected": 7,
        "high_risk_events": 3,
        "total_events": 44,
    }
    (case_path / "results" / "runtime_ml_summary.json").write_text(
        json.dumps(runtime_summary), encoding="utf-8"
    )

    tab = CaseDetailsTab(case_metadata={"case_id": "case_rt", "path": str(case_path)}, case_path=case_path)
    stats = tab._query_case_stats()

    assert stats["anomalies"] == 7
    assert stats["high_risk"] == 3
    assert stats["events"] == 44


def test_case_details_reads_ueba_findings_summary(tmp_path: Path, qapp: QApplication) -> None:
    case_path = tmp_path / "case_ueba"
    (case_path / "results").mkdir(parents=True)
    _write_case_json(case_path)
    _write_case_db_with_ui_tables(case_path, files=1, artifacts=1)

    ueba_summary = {
        "summary": {"anomalies_detected": 5},
        "findings": [{"id": 1}],
    }
    (case_path / "results" / "ueba_findings.json").write_text(json.dumps(ueba_summary), encoding="utf-8")

    tab = CaseDetailsTab(case_metadata={"case_id": "case_ueba", "path": str(case_path)}, case_path=case_path)
    stats = tab._query_case_stats()

    assert stats["anomalies"] == 5


def test_image_ingest_loads_evidence_from_case_metadata(tmp_path: Path, qapp: QApplication) -> None:
    cases_root = tmp_path / "cases"
    case_path = cases_root / "case_ingest"
    case_path.mkdir(parents=True)
    _write_case_json(case_path)

    cm = CaseManager(base_cases_dir=str(cases_root))
    tab = ImageIngestTab(case_manager=cm)

    tab.set_case({"case_id": "case_ingest", "path": str(case_path)})

    assert tab.tbl_evidence.rowCount() >= 1
    assert "loaded" in tab.lbl_status.text().lower()

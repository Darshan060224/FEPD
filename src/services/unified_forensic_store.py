"""
Unified forensic data store for Files and Artifacts UI tabs.

This module builds a normalized SQLite-backed view for a case:
- ui_files: raw filesystem-centric records
- ui_artifacts: interpreted artifact-centric records linked to ui_files
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class UnifiedForensicStore:
    """Build and query normalized case data for UI."""

    def __init__(self, case_path: Path):
        self.case_path = Path(case_path)
        self.case_id = self.case_path.name
        self.db_path = self.case_path / "case.db"
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        conn = self._connect()
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ui_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                size INTEGER DEFAULT 0,
                type TEXT,
                created TEXT,
                modified TEXT,
                accessed TEXT,
                owner TEXT,
                extension TEXT,
                source TEXT,
                evidence_id TEXT,
                sha256 TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ui_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT,
                timestamp TEXT,
                user TEXT,
                source TEXT,
                confidence REAL DEFAULT 0.5,
                related_file_id INTEGER,
                metadata_json TEXT,
                evidence_id TEXT,
                FOREIGN KEY(related_file_id) REFERENCES ui_files(id)
            )
            """
        )

        cur.execute("CREATE INDEX IF NOT EXISTS idx_ui_files_modified ON ui_files(modified)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ui_files_ext ON ui_files(extension)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ui_artifacts_type ON ui_artifacts(type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ui_artifacts_related ON ui_artifacts(related_file_id)")

        conn.commit()
        conn.close()

    def rebuild_case_index(self) -> Dict[str, int]:
        """Rebuild normalized files/artifacts records for this case."""
        conn = self._connect()
        cur = conn.cursor()

        cur.execute("DELETE FROM ui_artifacts WHERE evidence_id = ?", (self.case_id,))
        cur.execute("DELETE FROM ui_files WHERE evidence_id = ?", (self.case_id,))

        files_count = self._index_files(cur)
        artifacts_count = self._index_artifacts(cur)

        conn.commit()
        conn.close()

        logger.info(
            "Unified store indexed case %s: %d files, %d artifacts",
            self.case_id,
            files_count,
            artifacts_count,
        )
        return {"files": files_count, "artifacts": artifacts_count}

    def _index_files(self, cur: sqlite3.Cursor) -> int:
        count = 0
        roots = [
            self.case_path / "extracted_data",
            self.case_path / "artifacts",
            self.case_path / "forensic_detection",
        ]

        for root in roots:
            if not root.exists():
                continue
            for file_path in root.rglob("*"):
                if not file_path.is_file():
                    continue

                try:
                    stat = file_path.stat()
                    created = datetime.fromtimestamp(stat.st_ctime).isoformat()
                    modified = datetime.fromtimestamp(stat.st_mtime).isoformat()
                    accessed = datetime.fromtimestamp(stat.st_atime).isoformat()
                    size = stat.st_size
                except Exception:
                    created = modified = accessed = None
                    size = 0

                owner = self._extract_owner(file_path)
                extension = file_path.suffix.lower()
                source = self._infer_source(file_path)

                cur.execute(
                    """
                    INSERT OR REPLACE INTO ui_files
                    (name, path, size, type, created, modified, accessed, owner, extension, source, evidence_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        file_path.name,
                        str(file_path),
                        size,
                        extension.lstrip("."),
                        created,
                        modified,
                        accessed,
                        owner,
                        extension,
                        source,
                        self.case_id,
                    ),
                )
                count += 1
        return count

    def _index_artifacts(self, cur: sqlite3.Cursor) -> int:
        count = 0
        artifacts_root = self.case_path / "artifacts"

        if artifacts_root.exists():
            for type_dir in artifacts_root.iterdir():
                if not type_dir.is_dir():
                    continue

                a_source = type_dir.name
                for artifact_path in type_dir.rglob("*"):
                    if not artifact_path.is_file():
                        continue

                    ts = None
                    size = 0
                    try:
                        st = artifact_path.stat()
                        ts = datetime.fromtimestamp(st.st_mtime).isoformat()
                        size = st.st_size
                    except Exception:
                        pass

                    artifact_type = self._infer_artifact_type(type_dir.name, artifact_path)
                    confidence = self._confidence_for_source(type_dir.name)
                    related_file_id = self._link_related_file(cur, artifact_path)

                    metadata = {"size": size, "relative_path": self._safe_rel(artifact_path)}
                    user = self._extract_owner(artifact_path)

                    cur.execute(
                        """
                        INSERT INTO ui_artifacts
                        (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            artifact_type,
                            artifact_path.name,
                            str(artifact_path),
                            ts,
                            user,
                            a_source,
                            confidence,
                            related_file_id,
                            json.dumps(metadata),
                            self.case_id,
                        ),
                    )
                    count += 1

        memory_json = self.case_path / "memory_analysis" / "quick_scan_results.json"
        if memory_json.exists():
            try:
                payload = json.loads(memory_json.read_text(encoding="utf-8"))
                for proc in payload.get("processes", []):
                    cur.execute(
                        """
                        INSERT INTO ui_artifacts
                        (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "process",
                            str(proc),
                            "",
                            payload.get("scan_time"),
                            "",
                            "memory",
                            0.8,
                            None,
                            json.dumps({"from": "quick_scan_results"}),
                            self.case_id,
                        ),
                    )
                    count += 1

                for ip in payload.get("network", []):
                    cur.execute(
                        """
                        INSERT INTO ui_artifacts
                        (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "network",
                            str(ip),
                            "",
                            payload.get("scan_time"),
                            "",
                            "memory",
                            0.75,
                            None,
                            json.dumps({"from": "quick_scan_results"}),
                            self.case_id,
                        ),
                    )
                    count += 1

                for cmd in payload.get("command_history", []):
                    cmd_text = ""
                    if isinstance(cmd, dict):
                        cmd_text = str(cmd.get("command") or "").strip()
                    else:
                        cmd_text = str(cmd or "").strip()
                    if not cmd_text:
                        continue
                    cur.execute(
                        """
                        INSERT INTO ui_artifacts
                        (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "command",
                            cmd_text[:500],
                            "",
                            payload.get("scan_time"),
                            "",
                            "memory",
                            0.8,
                            None,
                            json.dumps({"from": "quick_scan_results"}),
                            self.case_id,
                        ),
                    )
                    count += 1

                for cred in payload.get("credential_indicators", []):
                    if not isinstance(cred, dict):
                        continue
                    name = str(cred.get("value") or cred.get("keyword") or "").strip()
                    if not name:
                        continue
                    cur.execute(
                        """
                        INSERT INTO ui_artifacts
                        (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "credential_indicator",
                            name[:500],
                            "",
                            payload.get("scan_time"),
                            "",
                            "memory",
                            0.8,
                            None,
                            json.dumps({"from": "quick_scan_results", "detail": cred}),
                            self.case_id,
                        ),
                    )
                    count += 1
            except Exception as exc:
                logger.warning("Failed to index memory quick scan: %s", exc)

        # Index richer pipeline outputs when forensic detection results exist.
        fd_payload = self._load_latest_forensic_detection_results()
        if fd_payload:
            completed_at = fd_payload.get("completed_at")

            for proc in (fd_payload.get("memory") or {}).get("processes", [])[:10000]:
                name = str(proc.get("name") or "").strip()
                if not name:
                    continue
                cur.execute(
                    """
                    INSERT INTO ui_artifacts
                    (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "process",
                        name,
                        "",
                        proc.get("first_seen") or (fd_payload.get("memory") or {}).get("analysis_time") or completed_at,
                        "",
                        "memory",
                        0.85,
                        None,
                        json.dumps({
                            "pid": proc.get("pid"),
                            "offset": proc.get("offset"),
                            "from": "forensic_detection",
                        }),
                        self.case_id,
                    ),
                )
                count += 1

            for conn in (fd_payload.get("memory") or {}).get("network_connections", [])[:10000]:
                ip = str(conn.get("ip") or "").strip()
                if not ip:
                    continue
                name = f"{ip}:{conn.get('port')}"
                cur.execute(
                    """
                    INSERT INTO ui_artifacts
                    (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "network",
                        name,
                        "",
                        (fd_payload.get("memory") or {}).get("analysis_time") or completed_at,
                        "",
                        "memory",
                        0.85,
                        None,
                        json.dumps({
                            "ip": ip,
                            "port": conn.get("port"),
                            "protocol": conn.get("protocol"),
                            "offset": conn.get("offset"),
                            "from": "forensic_detection",
                        }),
                        self.case_id,
                    ),
                )
                count += 1

            for cmd in (fd_payload.get("memory") or {}).get("command_history", [])[:10000]:
                cmd_text = str(cmd.get("command") or "").strip()
                if not cmd_text:
                    continue
                cur.execute(
                    """
                    INSERT INTO ui_artifacts
                    (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "command",
                        cmd_text[:500],
                        "",
                        (fd_payload.get("memory") or {}).get("analysis_time") or completed_at,
                        "",
                        "memory",
                        0.9,
                        None,
                        json.dumps({
                            "command_type": cmd.get("type"),
                            "offset": cmd.get("offset"),
                            "from": "forensic_detection",
                        }),
                        self.case_id,
                    ),
                )
                count += 1

            for finding in fd_payload.get("detections", [])[:10000]:
                exe = str(finding.get("executable") or "").strip()
                if not exe:
                    continue
                cur.execute(
                    """
                    INSERT INTO ui_artifacts
                    (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "detection",
                        exe,
                        "",
                        finding.get("execution_time") or completed_at,
                        "",
                        "forensic_detection",
                        0.95,
                        None,
                        json.dumps({
                            "score": finding.get("score"),
                            "verdict": finding.get("verdict"),
                            "file_state": finding.get("file_state"),
                            "network_seen": finding.get("network_seen"),
                            "remote_ips": finding.get("remote_ips"),
                        }),
                        self.case_id,
                    ),
                )
                count += 1

            for event in fd_payload.get("timeline", [])[:20000]:
                detail = str(event.get("detail") or "").strip()
                if not detail:
                    continue
                cur.execute(
                    """
                    INSERT INTO ui_artifacts
                    (type, name, path, timestamp, user, source, confidence, related_file_id, metadata_json, evidence_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(event.get("type") or "event"),
                        detail[:500],
                        "",
                        event.get("timestamp") or completed_at,
                        "",
                        "forensic_detection",
                        0.8,
                        None,
                        json.dumps({"from": "forensic_detection_timeline"}),
                        self.case_id,
                    ),
                )
                count += 1

        return count

    def _load_latest_forensic_detection_results(self) -> Dict[str, Any]:
        root = self.case_path / "forensic_detection"
        if not root.exists():
            return {}

        candidates = list(root.rglob("forensic_detection_results.json"))
        if not candidates:
            return {}

        latest = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]
        try:
            return json.loads(latest.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load forensic detection results: %s", exc)
            return {}

    def query_files(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM ui_files
            WHERE evidence_id = ?
            ORDER BY COALESCE(modified, created) DESC
            LIMIT ? OFFSET ?
            """,
            (self.case_id, limit, offset),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def query_artifacts(
        self,
        limit: int = 100,
        offset: int = 0,
        type_filter: Optional[str] = None,
        search_text: str = "",
    ) -> List[Dict[str, Any]]:
        conn = self._connect()
        cur = conn.cursor()

        sql = """
            SELECT * FROM ui_artifacts
            WHERE evidence_id = ?
        """
        params: List[Any] = [self.case_id]

        if type_filter and type_filter != "All Types":
            sql += " AND LOWER(type) = LOWER(?)"
            params.append(type_filter)

        if search_text:
            sql += " AND (LOWER(name) LIKE ? OR LOWER(path) LIKE ? OR LOWER(source) LIKE ?)"
            like = f"%{search_text.lower()}%"
            params.extend([like, like, like])

        sql += " ORDER BY COALESCE(timestamp, id) DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur.execute(sql, tuple(params))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def _link_related_file(self, cur: sqlite3.Cursor, artifact_path: Path) -> Optional[int]:
        cur.execute(
            "SELECT id FROM ui_files WHERE LOWER(path)=LOWER(?) LIMIT 1",
            (str(artifact_path),),
        )
        row = cur.fetchone()
        if row:
            return int(row[0])

        cur.execute(
            "SELECT id FROM ui_files WHERE LOWER(name)=LOWER(?) LIMIT 1",
            (artifact_path.name,),
        )
        row = cur.fetchone()
        if row:
            return int(row[0])

        if artifact_path.suffix.lower() == ".pf" and "-" in artifact_path.stem:
            exe_name = artifact_path.stem.split("-")[0].lower() + ".exe"
            cur.execute("SELECT id FROM ui_files WHERE LOWER(name)=? LIMIT 1", (exe_name,))
            row = cur.fetchone()
            if row:
                return int(row[0])

        return None

    @staticmethod
    def _extract_owner(path: Path) -> str:
        normalized = str(path).replace("\\", "/")
        marker = "/Users/"
        if marker in normalized:
            return normalized.split(marker, 1)[1].split("/", 1)[0]
        return ""

    @staticmethod
    def _infer_source(path: Path) -> str:
        p = str(path).lower().replace("\\", "/")
        if "/mft/" in p or path.name == "$MFT":
            return "MFT"
        if "/prefetch/" in p:
            return "Prefetch"
        if "/registry/" in p:
            return "Registry"
        if "/evtx/" in p:
            return "EVTX"
        if "/browser/" in p:
            return "Browser"
        return "Filesystem"

    @staticmethod
    def _infer_artifact_type(folder_name: str, artifact_path: Path) -> str:
        folder = folder_name.lower()
        if folder == "prefetch":
            return "execution"
        if folder == "registry":
            return "registry"
        if folder == "evtx":
            return "event_log"
        if folder == "browser":
            return "browser"
        if folder == "mft":
            return "file_activity"
        if artifact_path.suffix.lower() == ".pf":
            return "execution"
        return folder_name

    @staticmethod
    def _confidence_for_source(source: str) -> float:
        s = source.lower()
        if s in {"prefetch", "mft", "evtx", "registry"}:
            return 0.95
        if s in {"browser", "lnk", "script"}:
            return 0.85
        if s == "memory":
            return 0.80
        return 0.70

    def _safe_rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.case_path))
        except Exception:
            return str(path)

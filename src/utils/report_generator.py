"""
FEPD – Professional Forensic PDF Report Generator
===================================================

Flow-based ReportLab layout with:
  - Automatic spacing, page breaks, and table resizing
  - No empty sections — they are hidden when there is no data
  - Proper data collection pipeline:
      case.json -> evidence metadata -> artifacts -> timeline -> ML -> CoC
  - Embedded Matplotlib charts (timeline, severity, artifact distribution)
  - Professional 11-section forensic report structure

Copyright (c) 2026 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

# ---------------------------------------------------------------------------
# ReportLab availability
# ---------------------------------------------------------------------------

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Image as RLImage,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------------------------------------------------------------------
# Matplotlib - for embedded chart images
# ---------------------------------------------------------------------------

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure

    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False

logger = logging.getLogger(__name__)

# ===========================================================================
# CONSTANTS
# ===========================================================================

_PAGE_W, _PAGE_H = letter  # 612 x 792 pt
_MARGIN = 0.75 * inch
_CONTENT_W = _PAGE_W - 2 * _MARGIN  # usable width

# Branding
APP_NAME = "Forensic Evidence Parser Dashboard"
APP_SHORT = "FEPD"
APP_VERSION = "v2.0.0"
ORGANIZATION = "Darshan Research Lab"

# Palette
_C_PRIMARY = colors.HexColor("#1a237e")
_C_SECONDARY = colors.HexColor("#3949ab")
_C_ACCENT = colors.HexColor("#5c6bc0")
_C_WARNING = colors.HexColor("#ff6f00")
_C_DANGER = colors.HexColor("#c62828")
_C_SUCCESS = colors.HexColor("#2e7d32")
_C_TEXT = colors.HexColor("#212121")
_C_LIGHT = colors.HexColor("#f5f5f5")
_C_WHITE = colors.white

# Evidence-image format detection by extension
_IMAGE_FORMATS = {
    ".e01": "EnCase (E01)",
    ".ex01": "EnCase (Ex01)",
    ".aff": "AFF",
    ".aff4": "AFF4",
    ".dd": "Raw / DD",
    ".raw": "Raw / DD",
    ".img": "Raw Image",
    ".iso": "ISO 9660",
    ".vmdk": "VMware (VMDK)",
    ".vhd": "VHD",
    ".vhdx": "VHDX",
    ".qcow2": "QCOW2",
    ".mem": "Memory Dump",
    ".dmp": "Memory Dump",
    ".lime": "LiME Memory",
}


# ===========================================================================
# DATA COLLECTOR
# ===========================================================================


class _CaseDataCollector:
    """
    Gathers all forensic data for a case into a single dict.

    Pipeline:
        1. case.json               -> case metadata
        2. evidence_image key       -> hash, size, format, filename
        3. artifacts/ directory     -> per-type counts and file list
        4. extraction_log.json      -> artifact extraction audit
        5. classified_events.csv    -> timeline events  (or normalized)
        6. events/events.parquet    -> timeline events  (fallback)
        7. ml/ directory            -> anomalies.json, findings.json
        8. chain_of_custody.log     -> CoC entries
    """

    def __init__(
        self,
        case_metadata: Dict[str, Any],
        case_path: Path,
        classified_df: Optional[pd.DataFrame] = None,
        artifacts_data: Optional[List[Dict]] = None,
        coc_log_path: Optional[Path] = None,
    ):
        self.meta = case_metadata
        self.path = Path(case_path)
        self._classified_df = classified_df
        self._artifacts_data = artifacts_data
        self._coc_log_path = coc_log_path

    # -- public ---------------------------------------------------------

    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        data["meta"] = self._case_meta()
        data["evidence"] = self._evidence_meta()
        data["artifacts"] = self._artifacts()
        data["timeline"] = self._timeline()
        data["ml"] = self._ml_results()
        data["coc"] = self._chain_of_custody()
        data["system"] = self._system_overview()
        return data

    # -- helpers --------------------------------------------------------

    def _case_meta(self) -> Dict[str, Any]:
        return {
            "case_id": self.meta.get("case_id", ""),
            "case_name": self.meta.get("case_name", ""),
            "investigator": self.meta.get("investigator", ""),
            "examiner": self.meta.get("examiner", self.meta.get("investigator", "")),
            "created": self.meta.get("created_date", ""),
            "modified": self.meta.get("last_modified", ""),
            "status": self.meta.get("status", "open"),
            "timezone": self.meta.get("timezone", "UTC"),
        }

    def _evidence_meta(self) -> Dict[str, Any]:
        ev = self.meta.get("evidence_image", {})
        filename = ev.get("filename", "")
        ext = Path(filename).suffix.lower() if filename else ""
        fmt = _IMAGE_FORMATS.get(ext, ext.upper().lstrip(".") if ext else "")

        # Handle both key names: sha256_hash (case.json) and sha256 (legacy)
        sha = ev.get("sha256_hash") or ev.get("sha256") or ""
        md5 = ev.get("md5_hash") or ev.get("md5") or ""

        return {
            "filename": filename,
            "path": ev.get("path", ""),
            "format": fmt,
            "size_bytes": ev.get("size_bytes", 0),
            "sha256": sha,
            "md5": md5,
            "platform": self.meta.get("platform", ""),
        }

    def _artifacts(self) -> Dict[str, Any]:
        """Collect artifact data from pre-supplied list or by scanning."""
        arts = self._artifacts_data or []
        if not arts:
            arts = self._scan_artifacts()

        # Build counts
        counts: Dict[str, int] = {}
        total_size = 0
        for a in arts:
            t = a.get("type", "other")
            counts[t] = counts.get(t, 0) + 1
            total_size += a.get("size", 0)

        return {
            "items": arts,
            "counts": counts,
            "total": len(arts),
            "total_size": total_size,
        }

    def _scan_artifacts(self) -> List[Dict]:
        adir = self.path / "artifacts"
        if not adir.exists():
            return []
        types = [
            "evtx", "registry", "prefetch", "mft", "browser",
            "lnk", "linux_config", "linux_log", "script", "binary", "other",
        ]
        arts: List[Dict] = []
        for t in types:
            td = adir / t
            if not td.exists():
                continue
            for f in td.rglob("*"):
                if f.is_file():
                    try:
                        st = f.stat()
                        arts.append({
                            "type": t,
                            "name": f.name,
                            "path": str(f.relative_to(adir)),
                            "size": st.st_size,
                            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        })
                    except OSError:
                        pass
        return arts

    def _timeline(self) -> Dict[str, Any]:
        df = self._classified_df

        # Try loading from disk if not supplied
        if df is None or len(df) == 0:
            for name in ("classified_events.csv", "normalized_events.csv"):
                p = self.path / name
                if p.exists():
                    try:
                        df = pd.read_csv(p)
                        break
                    except Exception:
                        pass

        # Try parquet
        if df is None or len(df) == 0:
            pq = self.path / "events" / "events.parquet"
            if pq.exists():
                try:
                    df = pd.read_parquet(pq)
                except Exception:
                    pass

        if df is None or len(df) == 0:
            return {"total": 0, "df": None, "earliest": None, "latest": None,
                    "time_span_days": None, "source_counts": pd.Series(dtype=int),
                    "class_counts": pd.Series(dtype=int), "suspicious_hours": 0,
                    "ts_col": None, "cls_col": None}

        # Parse timestamps
        ts_col = None
        for c in ("ts_utc", "timestamp", "Timestamp", "datetime"):
            if c in df.columns:
                ts_col = c
                break

        earliest = latest = time_span = None
        if ts_col:
            try:
                df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")
                earliest = df[ts_col].min()
                latest = df[ts_col].max()
                if pd.notna(earliest) and pd.notna(latest):
                    time_span = (latest - earliest).days
            except Exception:
                pass

        # Artifact-source breakdown
        src_col = None
        for c in ("artifact_source", "source", "Source"):
            if c in df.columns:
                src_col = c
                break
        source_counts = df[src_col].value_counts().head(15) if src_col else pd.Series(dtype=int)

        # Classification breakdown
        cls_col = None
        for c in ("rule_class", "classification", "severity", "Severity"):
            if c in df.columns:
                cls_col = c
                break
        class_counts = df[cls_col].value_counts() if cls_col else pd.Series(dtype=int)

        # Suspicious-hour breakdown (22:00-06:00)
        suspicious_hours = 0
        if ts_col and ts_col in df.columns:
            try:
                hours = df[ts_col].dt.hour
                suspicious_hours = int(((hours >= 22) | (hours < 6)).sum())
            except Exception:
                pass

        return {
            "total": len(df),
            "df": df,
            "earliest": str(earliest) if earliest is not None and pd.notna(earliest) else None,
            "latest": str(latest) if latest is not None and pd.notna(latest) else None,
            "time_span_days": time_span,
            "source_counts": source_counts,
            "class_counts": class_counts,
            "suspicious_hours": suspicious_hours,
            "ts_col": ts_col,
            "cls_col": cls_col,
        }

    def _ml_results(self) -> Dict[str, Any]:
        ml_dir = self.path / "ml"
        out: Dict[str, Any] = {"anomalies": [], "findings": []}
        if not ml_dir.exists():
            return out
        for name, key in (("anomalies.json", "anomalies"), ("findings.json", "findings")):
            p = ml_dir / name
            if p.exists():
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        out[key] = json.load(fh)
                except Exception:
                    pass
        return out

    def _chain_of_custody(self) -> Dict[str, Any]:
        path = self._coc_log_path
        if path is None:
            path = self.path / "chain_of_custody.log"
        if not path.exists():
            return {"entries": [], "path": ""}

        entries: List[Dict] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except Exception:
            pass

        return {"entries": entries, "path": str(path)}

    def _system_overview(self) -> Dict[str, Any]:
        """Infer OS / partition / filesystem from artifacts and case data."""
        platform = self.meta.get("platform", "")

        # Try to detect OS from artifacts
        arts = self.path / "artifacts"
        has_evtx = False
        has_registry = False
        has_prefetch = False
        has_linux = False

        if arts.exists():
            for d, attr in [("evtx", "has_evtx"), ("registry", "has_registry"),
                            ("prefetch", "has_prefetch")]:
                td = arts / d
                if td.exists():
                    try:
                        if any(td.iterdir()):
                            if attr == "has_evtx":
                                has_evtx = True
                            elif attr == "has_registry":
                                has_registry = True
                            elif attr == "has_prefetch":
                                has_prefetch = True
                    except OSError:
                        pass

            for d in ("linux_config", "linux_log"):
                td = arts / d
                if td.exists():
                    try:
                        if any(td.iterdir()):
                            has_linux = True
                            break
                    except OSError:
                        pass

        if not platform:
            if has_evtx or has_registry or has_prefetch:
                platform = "Windows"
            elif has_linux:
                platform = "Linux"

        # Partition info from extracted_data
        partitions: List[str] = []
        ed = self.path / "extracted_data"
        if ed.exists():
            try:
                partitions = [d.name for d in sorted(ed.iterdir()) if d.is_dir()]
            except OSError:
                pass

        return {
            "platform": platform,
            "partitions": partitions,
            "has_evtx": has_evtx,
            "has_registry": has_registry,
            "has_prefetch": has_prefetch,
            "has_linux": has_linux,
        }


# ===========================================================================
# CHART GENERATOR  (Matplotlib -> PNG bytes)
# ===========================================================================


class _ChartGenerator:
    """Generate small, dark-themed Matplotlib charts and return PNG bytes."""

    _DARK_BG = "#1e1e1e"
    _AXES_BG = "#252526"
    _TEXT = "#cccccc"
    _GRID = "#3e3e42"
    _COLORS = [
        "#4fc3f7", "#81c784", "#ffb74d", "#e57373",
        "#ba68c8", "#4dd0e1", "#aed581", "#ff8a65",
    ]

    @classmethod
    def _setup(cls) -> dict:
        return {
            "figure.facecolor": cls._DARK_BG,
            "axes.facecolor": cls._AXES_BG,
            "axes.edgecolor": cls._GRID,
            "axes.labelcolor": cls._TEXT,
            "text.color": cls._TEXT,
            "xtick.color": cls._TEXT,
            "ytick.color": cls._TEXT,
            "grid.color": cls._GRID,
            "grid.alpha": 0.4,
        }

    @classmethod
    def artifact_distribution(cls, counts: Dict[str, int]) -> Optional[bytes]:
        if not _HAS_MPL or not counts:
            return None
        with plt.rc_context(cls._setup()):
            fig, ax = plt.subplots(figsize=(5, 3), dpi=130)
            labels = [k.replace("_", " ").title() for k in counts]
            vals = list(counts.values())
            cs = cls._COLORS[: len(labels)]
            result = ax.pie(
                vals, labels=None, autopct="%1.0f%%", startangle=140,
                colors=cs, pctdistance=0.8,
                wedgeprops={"width": 0.45, "edgecolor": cls._DARK_BG},
            )
            autotexts = result[2] if len(result) > 2 else []
            for t in autotexts:
                t.set_fontsize(7)
                t.set_color(cls._TEXT)
            ax.legend(labels, loc="center left", bbox_to_anchor=(1, 0.5),
                      fontsize=7, frameon=False)
            ax.set_title("Artifact Distribution", fontsize=10, pad=10)
            fig.tight_layout()
            return cls._to_png(fig)

    @classmethod
    def severity_chart(cls, class_counts: "pd.Series") -> Optional[bytes]:
        if not _HAS_MPL or class_counts is None or class_counts.empty:
            return None
        sev_colors = {
            "CRITICAL": "#e53935", "HIGH": "#ff7043", "SUSPICIOUS": "#ff7043",
            "MEDIUM": "#ffb74d", "ANOMALOUS": "#ffb74d",
            "LOW": "#66bb6a", "NORMAL": "#66bb6a", "INFO": "#42a5f5",
        }
        with plt.rc_context(cls._setup()):
            fig, ax = plt.subplots(figsize=(5, 2.5), dpi=130)
            labels = [str(lbl) for lbl in class_counts.index]
            vals = class_counts.values
            bar_colors = [sev_colors.get(lbl.upper(), "#90a4ae") for lbl in labels]
            bars = ax.barh(labels, vals, color=bar_colors, edgecolor=cls._AXES_BG)
            for bar, val in zip(bars, vals):
                ax.text(bar.get_width() + max(vals) * 0.02, bar.get_y() + bar.get_height() / 2,
                        f"{int(val):,}", va="center", fontsize=7)
            ax.set_title("Event Classification", fontsize=10, pad=10)
            ax.invert_yaxis()
            ax.set_xlabel("Count")
            fig.tight_layout()
            return cls._to_png(fig)

    @classmethod
    def timeline_chart(cls, df: pd.DataFrame, ts_col: str) -> Optional[bytes]:
        if not _HAS_MPL or df is None or ts_col not in df.columns:
            return None

        try:
            ts = pd.to_datetime(df[ts_col], errors="coerce").dropna()
            if ts.empty:
                return None
            # Resample to daily counts
            counts = ts.dt.floor("D").value_counts().sort_index()
            if counts.empty:
                return None
        except Exception:
            return None

        with plt.rc_context(cls._setup()):
            fig, ax = plt.subplots(figsize=(6, 2.5), dpi=130)
            ax.fill_between(counts.index, counts.values, alpha=0.35, color="#4fc3f7")
            ax.plot(counts.index, counts.values, color="#4fc3f7", linewidth=1.2)

            # Annotate peak
            peak_idx = counts.idxmax()
            peak_val = counts.max()
            ax.annotate(
                f"Peak: {int(peak_val):,}",
                xy=(peak_idx, peak_val),
                xytext=(0, 12),
                textcoords="offset points",
                fontsize=7,
                ha="center",
                arrowprops={"arrowstyle": "->", "color": "#e57373", "lw": 0.8},
                color="#e57373",
            )

            ax.set_title("Event Timeline (daily)", fontsize=10, pad=10)
            ax.set_ylabel("Events")
            fig.autofmt_xdate(rotation=30, ha="right")
            fig.tight_layout()
            return cls._to_png(fig)

    @staticmethod
    def _to_png(fig: "Figure") -> bytes:
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return buf.read()


# ===========================================================================
# REPORT GENERATOR
# ===========================================================================


class ReportGenerator:
    """
    Professional forensic PDF report generator.

    Uses ReportLab *flowable* layout - no fixed-coordinate positioning.
    Empty sections are omitted automatically.
    Charts (Matplotlib) are embedded inline.
    """

    # Kept for backward compatibility with callers that reference these
    APP_NAME = APP_NAME
    APP_SHORT_NAME = APP_SHORT
    APP_VERSION = APP_VERSION
    ORGANIZATION = ORGANIZATION

    def __init__(
        self,
        case_metadata: Dict[str, Any],
        case_path: Path,
        classified_df: Optional[pd.DataFrame] = None,
        artifacts_data: Optional[List[Dict]] = None,
        coc_log_path: Optional[Path] = None,
        logger: Optional[logging.Logger] = None,
    ):
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "ReportLab is required for PDF generation.  "
                "Install with:  pip install reportlab"
            )

        self.case_metadata = case_metadata  # keep for compat
        self.case_path = Path(case_path)
        self.logger = logger or logging.getLogger(__name__)
        self.report_ts = datetime.now(timezone.utc)

        # Also keep compat attr
        self.report_timestamp = self.report_ts

        # Collect all data through pipeline
        collector = _CaseDataCollector(
            case_metadata, case_path, classified_df, artifacts_data, coc_log_path
        )
        self.data = collector.collect()

        # Styles
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()

    # ------------------------------------------------------------------
    # PUBLIC
    # ------------------------------------------------------------------

    def generate_report(self, output_path: Optional[Path] = None) -> Path:
        """Build the PDF and return its path."""
        if output_path is None:
            rdir = self.case_path / "report"
            rdir.mkdir(exist_ok=True)
            ts = self.report_ts.strftime("%Y%m%d_%H%M%S")
            cid = self.data["meta"]["case_id"] or "unknown"
            output_path = rdir / f"FEPD_Report_{cid}_{ts}.pdf"
        output_path = Path(output_path)

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=_MARGIN,
            leftMargin=_MARGIN,
            topMargin=1 * inch,
            bottomMargin=0.75 * inch,
        )

        story = self._build_story()

        doc.build(
            story,
            onFirstPage=self._page_decorations,
            onLaterPages=self._page_decorations,
        )

        report_hash = _file_hash(output_path)
        self.logger.info("Report generated: %s  (SHA-256: %s)", output_path, report_hash)

        self._save_metadata(output_path, report_hash)
        return output_path

    # ------------------------------------------------------------------
    # STORY BUILDER  (all sections, conditionally)
    # ------------------------------------------------------------------

    def _build_story(self) -> list:
        story: list = []

        # 1 - Cover / header  (always)
        story.extend(self._sec_header())
        story.append(PageBreak())

        # 2 - Executive Summary  (always)
        story.extend(self._sec_executive_summary())
        story.append(Spacer(1, 0.25 * inch))

        # 3 - Case Information  (always)
        story.extend(self._sec_case_info())
        story.append(Spacer(1, 0.25 * inch))

        # 4 - Evidence Overview  (if evidence metadata present)
        sec = self._sec_evidence_overview()
        if sec:
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 5 - System Overview  (if platform detected)
        sec = self._sec_system_overview()
        if sec:
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 6 - Timeline Analysis (if events exist)
        sec = self._sec_timeline()
        if sec:
            story.append(PageBreak())
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 7 - Suspicious Activity  (if flagged events exist)
        sec = self._sec_suspicious_activity()
        if sec:
            story.append(PageBreak())
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 8 - Artifact Analysis  (if artifacts present)
        sec = self._sec_artifact_analysis()
        if sec:
            story.append(PageBreak())
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 9 - ML Anomaly Findings  (if ML ran)
        sec = self._sec_ml_findings()
        if sec:
            story.append(PageBreak())
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 10 - Evidence Integrity  (if hash present)
        sec = self._sec_evidence_integrity()
        if sec:
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 11 - Chain of Custody  (if entries present)
        sec = self._sec_chain_of_custody()
        if sec:
            story.extend(sec)
            story.append(Spacer(1, 0.25 * inch))

        # 12 - Appendices  (always - legal disclaimer)
        story.append(PageBreak())
        story.extend(self._sec_appendices())

        return story

    # ==================================================================
    # SECTION BUILDERS
    # ==================================================================

    # -- 1. Header -----------------------------------------------------

    def _sec_header(self) -> list:
        els: list = []

        # Logo
        logo = Path(__file__).parent.parent.parent / "logo" / "logo.png"
        if logo.exists():
            try:
                img = RLImage(str(logo), width=1.4 * inch, height=1.4 * inch)
                img.hAlign = "CENTER"
                els.append(img)
                els.append(Spacer(1, 0.15 * inch))
            except Exception:
                pass

        els.append(Paragraph(
            f"<b>{APP_NAME}</b><br/>({APP_SHORT})",
            self.styles["ReportTitle"],
        ))
        els.append(Paragraph(
            f"<b>Version:</b> {APP_VERSION} &nbsp;|&nbsp; "
            f"<b>Organization:</b> {ORGANIZATION}",
            self.styles["Normal"],
        ))
        els.append(Spacer(1, 0.1 * inch))

        meta = self.data["meta"]
        rid = f"RPT-{meta['case_id']}-{self.report_ts.strftime('%Y%m%d')}"
        els.append(Paragraph(
            f"<b>Report Date:</b> {self.report_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>"
            f"<b>Report ID:</b> {rid}<br/>"
            f"<b>Case ID:</b> {meta['case_id']}",
            self.styles["Normal"],
        ))
        els.append(Spacer(1, 0.2 * inch))
        els.append(self._separator())
        return els

    # -- 2. Executive Summary ------------------------------------------

    def _sec_executive_summary(self) -> list:
        els = [self._heading("1. Executive Summary")]
        meta = self.data["meta"]
        ev = self.data["evidence"]
        arts = self.data["artifacts"]
        tl = self.data["timeline"]
        ml = self.data["ml"]

        parts: List[str] = []

        if ev["filename"]:
            parts.append(
                f"This investigation analysed evidence file "
                f"<b>{_esc(ev['filename'])}</b>"
                f"{' (' + ev['format'] + ')' if ev['format'] else ''}"
                f", size <b>{_fmt_size(ev['size_bytes'])}</b>."
            )
        else:
            parts.append(
                f"Case <b>{_esc(meta['case_name'])}</b> has been created but "
                f"no evidence has been ingested yet."
            )

        if arts["total"] > 0:
            parts.append(
                f"<b>{arts['total']:,}</b> artifact files were extracted "
                f"({_fmt_size(arts['total_size'])})."
            )

        if tl["total"] > 0:
            span_text = f" spanning <b>{tl['time_span_days']}</b> days" if tl.get("time_span_days") else ""
            parts.append(
                f"Timeline analysis produced <b>{tl['total']:,}</b> events"
                + span_text + "."
            )
            if tl["suspicious_hours"]:
                parts.append(
                    f"Of these, <b>{tl['suspicious_hours']:,}</b> occurred during "
                    f"off-hours (22:00-06:00)."
                )

        anom_count = len(ml.get("anomalies", []))
        find_count = len(ml.get("findings", []))
        if anom_count or find_count:
            parts.append(
                f"ML analysis detected <b>{anom_count}</b> anomalies and "
                f"<b>{find_count}</b> forensic findings."
            )

        els.append(Paragraph(" ".join(parts), self.styles["BodyFlow"]))
        return els

    # -- 3. Case Information -------------------------------------------

    def _sec_case_info(self) -> list:
        els = [self._heading("2. Case Information")]
        m = self.data["meta"]
        rows = [
            ["Case Name", m["case_name"]],
            ["Case ID", m["case_id"]],
            ["Investigator", m["investigator"]],
            ["Examiner", m["examiner"]],
            ["Created", m["created"]],
            ["Last Modified", m["modified"]],
            ["Time Zone", m["timezone"]],
            ["Status", m["status"].title()],
        ]
        els.append(self._kv_table(rows))
        return els

    # -- 4. Evidence Overview ------------------------------------------

    def _sec_evidence_overview(self) -> Optional[list]:
        ev = self.data["evidence"]
        if not ev["filename"]:
            return None

        els = [self._heading("3. Evidence Overview")]
        rows = [
            ["Evidence File", ev["filename"]],
            ["Full Path", ev["path"]],
            ["Image Format", ev["format"] or "Unknown"],
            ["File Size", _fmt_size(ev["size_bytes"])],
        ]
        if ev["sha256"]:
            rows.append(["SHA-256 Hash", ev["sha256"]])
        if ev["md5"]:
            rows.append(["MD5 Hash", ev["md5"]])
        if ev["platform"]:
            rows.append(["Platform", ev["platform"]])

        els.append(self._kv_table(rows))
        return els

    # -- 5. System Overview --------------------------------------------

    def _sec_system_overview(self) -> Optional[list]:
        sys_info = self.data["system"]
        if not sys_info["platform"] and not sys_info["partitions"]:
            return None

        els = [self._heading("4. System Overview")]
        rows: List[List[str]] = []
        if sys_info["platform"]:
            rows.append(["Operating System", sys_info["platform"]])

        # Detected artifact types
        detected: List[str] = []
        if sys_info["has_evtx"]:
            detected.append("Windows Event Logs")
        if sys_info["has_registry"]:
            detected.append("Registry Hives")
        if sys_info["has_prefetch"]:
            detected.append("Prefetch Files")
        if sys_info["has_linux"]:
            detected.append("Linux Configs / Logs")
        if detected:
            rows.append(["Detected Artifact Types", ", ".join(detected)])

        if sys_info["partitions"]:
            rows.append(["Partitions", ", ".join(sys_info["partitions"])])

        if rows:
            els.append(self._kv_table(rows))
        return els

    # -- 6. Timeline Analysis ------------------------------------------

    def _sec_timeline(self) -> Optional[list]:
        tl = self.data["timeline"]
        if tl["total"] == 0:
            return None

        els = [self._heading("5. Timeline Analysis")]

        # Statistics table
        rows = [["Total Events", f"{tl['total']:,}"]]
        if tl["earliest"]:
            rows.append(["Earliest Event", tl["earliest"][:19]])
        if tl["latest"]:
            rows.append(["Latest Event", tl["latest"][:19]])
        if tl["time_span_days"] is not None:
            rows.append(["Time Span", f"{tl['time_span_days']} days"])
        if tl["suspicious_hours"]:
            rows.append(["Off-Hours Events (22-06)", f"{tl['suspicious_hours']:,}"])
        els.append(self._kv_table(rows))
        els.append(Spacer(1, 0.15 * inch))

        # Embedded timeline chart
        if tl["df"] is not None and tl["ts_col"]:
            chart_png = _ChartGenerator.timeline_chart(tl["df"], tl["ts_col"])
            if chart_png:
                els.append(self._embed_chart(chart_png, width=5.5))
                els.append(Spacer(1, 0.15 * inch))

        # Source breakdown table
        sc = tl["source_counts"]
        if sc is not None and not sc.empty:
            els.append(self._subheading("Events by Source (Top 15)"))
            tbl_data = [["Source", "Count"]]
            for src, cnt in sc.items():
                tbl_data.append([str(src), f"{cnt:,}"])
            els.append(self._data_table(tbl_data, col_widths=[4 * inch, 2.5 * inch]))
            els.append(Spacer(1, 0.15 * inch))

        # Classification breakdown
        cc = tl["class_counts"]
        if cc is not None and not cc.empty:
            els.append(self._subheading("Event Classifications"))
            total = tl["total"]
            tbl_data = [["Classification", "Count", "Percentage"]]
            for cls_name, cnt in cc.items():
                pct = 100 * cnt / total if total else 0
                tbl_data.append([str(cls_name), f"{cnt:,}", f"{pct:.1f}%"])
            els.append(self._data_table(
                tbl_data, col_widths=[3 * inch, 1.5 * inch, 2 * inch]
            ))

            # Embedded severity chart
            sev_png = _ChartGenerator.severity_chart(cc)
            if sev_png:
                els.append(Spacer(1, 0.1 * inch))
                els.append(self._embed_chart(sev_png, width=5))

        return els

    # -- 7. Suspicious Activity ----------------------------------------

    def _sec_suspicious_activity(self) -> Optional[list]:
        tl = self.data["timeline"]
        if tl["total"] == 0 or tl["df"] is None:
            return None

        df = tl["df"]
        cls_col = tl["cls_col"]
        if not cls_col or cls_col not in df.columns:
            return None

        suspect_labels = {"SUSPICIOUS", "ANOMALOUS", "CRITICAL", "HIGH_RISK", "MALWARE", "HIGH"}
        mask = df[cls_col].astype(str).str.upper().isin(suspect_labels)
        flagged = df[mask]
        if flagged.empty:
            return None

        els = [self._heading("6. Suspicious Activity")]
        els.append(Paragraph(
            f"<b>{len(flagged):,}</b> suspicious / anomalous events detected.",
            self.styles["WarningText"],
        ))
        els.append(Spacer(1, 0.1 * inch))

        # Table - top 60
        ts_col = tl["ts_col"]
        desc_col = next(
            (c for c in ("description", "Description", "event_type", "EventType") if c in df.columns),
            None,
        )
        tbl_data = [["Timestamp", "Event", "Description", "Classification"]]
        for _, row in flagged.head(60).iterrows():
            tbl_data.append([
                str(row.get(ts_col, ""))[:19] if ts_col else "",
                str(row.get("event_type", row.get("EventType", "")))[:30],
                str(row.get(desc_col, ""))[:55] if desc_col else "",
                str(row.get(cls_col, "")),
            ])

        els.append(self._data_table(
            tbl_data,
            col_widths=[1.3 * inch, 1.1 * inch, 2.6 * inch, 1.5 * inch],
            header_color=_C_DANGER,
            font_size=7,
        ))

        if len(flagged) > 60:
            els.append(Paragraph(
                f"<i>... and {len(flagged) - 60:,} more flagged events (see appendix).</i>",
                self.styles["Normal"],
            ))

        return els

    # -- 8. Artifact Analysis ------------------------------------------

    def _sec_artifact_analysis(self) -> Optional[list]:
        arts = self.data["artifacts"]
        if arts["total"] == 0:
            return None

        els = [self._heading("7. Artifact Analysis")]

        # Summary table
        tbl_data = [["Artifact Type", "Count", "Size"]]
        for atype, cnt in sorted(arts["counts"].items()):
            type_size = sum(a.get("size", 0) for a in arts["items"] if a.get("type") == atype)
            tbl_data.append([
                atype.replace("_", " ").title(),
                str(cnt),
                _fmt_size(type_size),
            ])
        tbl_data.append(["Total", str(arts["total"]), _fmt_size(arts["total_size"])])
        els.append(self._data_table(
            tbl_data,
            col_widths=[3 * inch, 1.5 * inch, 2 * inch],
        ))
        els.append(Spacer(1, 0.15 * inch))

        # Embedded donut chart
        chart_png = _ChartGenerator.artifact_distribution(arts["counts"])
        if chart_png:
            els.append(self._embed_chart(chart_png, width=4.5))
            els.append(Spacer(1, 0.15 * inch))

        # Per-type detail tables (top 20 each)
        grouped: Dict[str, List[Dict]] = {}
        for a in arts["items"]:
            grouped.setdefault(a.get("type", "other"), []).append(a)

        for atype, items in sorted(grouped.items()):
            els.append(self._subheading(f"{atype.replace('_', ' ').title()} ({len(items)})"))
            tbl = [["File", "Path", "Size", "Modified"]]
            for it in items[:20]:
                tbl.append([
                    it["name"][:35],
                    it.get("path", "")[:42],
                    _fmt_size(it.get("size", 0)),
                    it.get("modified", "")[:19],
                ])
            if len(items) > 20:
                tbl.append([f"... and {len(items) - 20} more", "", "", ""])
            els.append(self._data_table(
                tbl,
                col_widths=[2 * inch, 2 * inch, 0.9 * inch, 1.6 * inch],
                header_color=_C_ACCENT,
                font_size=7,
            ))
            els.append(Spacer(1, 0.1 * inch))

        return els

    # -- 9. ML Anomaly Findings ----------------------------------------

    def _sec_ml_findings(self) -> Optional[list]:
        ml = self.data["ml"]
        anomalies = ml.get("anomalies", [])
        findings = ml.get("findings", [])
        if not anomalies and not findings:
            return None

        els = [self._heading("8. ML Anomaly Findings")]

        if anomalies:
            els.append(Paragraph(
                f"<b>{len(anomalies)}</b> anomalies detected by the ML engine.",
                self.styles["WarningText"],
            ))
            els.append(Spacer(1, 0.1 * inch))

            # If items are dicts with score/severity
            if isinstance(anomalies, list) and anomalies and isinstance(anomalies[0], dict):
                # Severity distribution
                sev_counter = Counter(a.get("severity", "UNKNOWN") for a in anomalies)
                if sev_counter:
                    sev_rows = [["Severity", "Count"]]
                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        if sev in sev_counter:
                            sev_rows.append([sev, str(sev_counter[sev])])
                    for sev, cnt in sev_counter.items():
                        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                            sev_rows.append([sev, str(cnt)])
                    els.append(self._data_table(sev_rows, col_widths=[3 * inch, 3 * inch]))
                    els.append(Spacer(1, 0.1 * inch))

                # Top anomalies table (top 30)
                sorted_anoms = sorted(anomalies, key=lambda a: a.get("score", a.get("anomaly_score", 0)), reverse=True)
                tbl = [["Timestamp", "Event", "Score", "Severity", "Flags"]]
                for a in sorted_anoms[:30]:
                    tbl.append([
                        str(a.get("timestamp", ""))[:19],
                        str(a.get("event_type", a.get("type", "")))[:25],
                        f"{a.get('score', a.get('anomaly_score', 0)):.3f}",
                        str(a.get("severity", "")),
                        str(a.get("flags", a.get("explanation", "")))[:50],
                    ])
                els.append(self._data_table(
                    tbl,
                    col_widths=[1.2 * inch, 1.3 * inch, 0.7 * inch, 0.8 * inch, 2.5 * inch],
                    header_color=_C_DANGER,
                    font_size=7,
                ))

        if findings:
            els.append(Spacer(1, 0.15 * inch))
            els.append(self._subheading(f"Forensic Findings ({len(findings)})"))
            for i, finding in enumerate(findings[:20], 1):
                if isinstance(finding, dict):
                    title = finding.get("title", finding.get("description", f"Finding {i}"))
                    sev = finding.get("severity", "")
                    desc = finding.get("description", "")
                    text = f"<b>#{i} [{sev}]</b> {_esc(title)}"
                    if desc and desc != title:
                        text += f"<br/><font size='8'>{_esc(desc[:200])}</font>"
                    els.append(Paragraph(text, self.styles["Normal"]))
                    els.append(Spacer(1, 4))

        return els

    # -- 10. Evidence Integrity ----------------------------------------

    def _sec_evidence_integrity(self) -> Optional[list]:
        ev = self.data["evidence"]
        if not ev["sha256"] and not ev["md5"]:
            return None

        els = [self._heading("9. Evidence Integrity")]
        rows = [["Algorithm", "Hash Value"]]
        if ev["sha256"]:
            rows.append(["SHA-256", ev["sha256"]])
        if ev["md5"]:
            rows.append(["MD5", ev["md5"]])

        tbl = Table(rows, colWidths=[1.5 * inch, 5 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _C_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), _C_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        els.append(tbl)
        els.append(Spacer(1, 0.1 * inch))
        els.append(Paragraph(
            "Hashes were computed at evidence ingestion time and are stored in "
            "the case metadata for independent verification.",
            self.styles["Normal"],
        ))
        return els

    # -- 11. Chain of Custody ------------------------------------------

    def _sec_chain_of_custody(self) -> Optional[list]:
        coc = self.data["coc"]
        entries = coc.get("entries", [])
        if not entries:
            return None

        els = [self._heading("10. Chain of Custody")]
        els.append(Paragraph(
            f"<b>{len(entries)}</b> chain-of-custody entries recorded.  "
            f"Each entry is cryptographically linked to its predecessor "
            f"(blockchain-style hash chain).",
            self.styles["Normal"],
        ))
        els.append(Spacer(1, 0.1 * inch))

        # Action summary table
        action_counts = Counter(e.get("action", "UNKNOWN") for e in entries)
        tbl = [["Action", "Count"]]
        for action, cnt in action_counts.most_common():
            tbl.append([action, str(cnt)])
        els.append(self._data_table(tbl, col_widths=[4 * inch, 2.5 * inch]))
        els.append(Spacer(1, 0.1 * inch))

        # First entry
        first = entries[0]
        els.append(Paragraph(
            f"<b>First entry:</b> {first.get('action', '')} - "
            f"{first.get('timestamp', '')[:19]} - "
            f"<font size='7'>{first.get('self_hash', '')[:40]}...</font>",
            self.styles["Normal"],
        ))
        # Last entry
        last = entries[-1]
        els.append(Paragraph(
            f"<b>Latest entry:</b> {last.get('action', '')} - "
            f"{last.get('timestamp', '')[:19]} - "
            f"<font size='7'>{last.get('self_hash', '')[:40]}...</font>",
            self.styles["Normal"],
        ))

        return els

    # -- 12. Appendices ------------------------------------------------

    def _sec_appendices(self) -> list:
        els = [self._heading("11. Appendices")]

        els.append(self._subheading("A. Report Configuration"))
        els.append(Paragraph(
            f"<b>Hash Algorithm:</b> SHA-256<br/>"
            f"<b>Report Format:</b> PDF (ReportLab flowable layout)<br/>"
            f"<b>Parser Version:</b> {APP_VERSION}<br/>"
            f"<b>Generated:</b> {self.report_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            self.styles["Normal"],
        ))
        els.append(Spacer(1, 0.15 * inch))

        els.append(self._subheading("B. Case Paths"))
        els.append(Paragraph(
            f"<b>Case Directory:</b> {self.case_path}<br/>"
            f"<b>Artifacts:</b> {self.case_path / 'artifacts'}<br/>"
            f"<b>Reports:</b> {self.case_path / 'report'}",
            self.styles["Normal"],
        ))
        els.append(Spacer(1, 0.15 * inch))

        els.append(self._subheading("C. Sections Included"))
        manifest = self._section_manifest()
        els.append(Paragraph(
            "<br/>".join(f"&bull; {s}" for s in manifest),
            self.styles["Normal"],
        ))
        els.append(Spacer(1, 0.15 * inch))

        els.append(self._subheading("D. Legal Disclaimer"))
        els.append(Paragraph(
            "This forensic report was generated by automated analysis tools and "
            "should be reviewed by qualified forensic examiners. The findings are "
            "based on the data available at the time of analysis and may not "
            "represent a complete picture of all activities on the analysed system. "
            "This report is intended for professional forensic investigation "
            "purposes only and should be handled according to applicable legal and "
            "regulatory requirements.",
            self.styles["Normal"],
        ))
        els.append(Spacer(1, 0.3 * inch))

        els.append(Paragraph(
            f"<b>Generated by:</b> {APP_NAME} ({APP_SHORT}) {APP_VERSION}<br/>"
            f"<b>Organization:</b> {ORGANIZATION}<br/>"
            f"<b>Timestamp:</b> {self.report_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            self.styles["Normal"],
        ))
        return els

    # ==================================================================
    # STYLE & WIDGET HELPERS
    # ==================================================================

    def _add_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name="ReportTitle",
            parent=self.styles["Heading1"],
            fontSize=22,
            textColor=_C_PRIMARY,
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ))
        self.styles.add(ParagraphStyle(
            name="SectionHead",
            parent=self.styles["Heading2"],
            fontSize=15,
            textColor=_C_PRIMARY,
            spaceAfter=10,
            spaceBefore=14,
            fontName="Helvetica-Bold",
            borderWidth=1,
            borderColor=_C_PRIMARY,
            borderPadding=5,
            backColor=_C_LIGHT,
        ))
        self.styles.add(ParagraphStyle(
            name="SubHead",
            parent=self.styles["Heading3"],
            fontSize=12,
            textColor=_C_SECONDARY,
            spaceAfter=8,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        ))
        self.styles.add(ParagraphStyle(
            name="WarningText",
            parent=self.styles["Normal"],
            fontSize=11,
            textColor=_C_WARNING,
            fontName="Helvetica-Bold",
            leftIndent=15,
        ))
        self.styles.add(ParagraphStyle(
            name="BodyFlow",
            parent=self.styles["Normal"],
            fontSize=10,
            leading=14,
            spaceAfter=8,
        ))

    def _heading(self, text: str):
        return Paragraph(text, self.styles["SectionHead"])

    def _subheading(self, text: str):
        return Paragraph(text, self.styles["SubHead"])

    def _separator(self):
        t = Table([[""]], colWidths=[_CONTENT_W])
        t.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 2, _C_PRIMARY)]))
        return t

    # -- Tables --------------------------------------------------------

    def _kv_table(self, rows: List[List[str]]) -> Table:
        """Two-column key/value table with auto width."""
        styled = [
            [
                Paragraph(f"<b>{r[0]}</b>", self.styles["Normal"]),
                Paragraph(str(r[1]), self.styles["Normal"]),
            ]
            for r in rows
        ]
        tbl = Table(styled, colWidths=[2.2 * inch, _CONTENT_W - 2.2 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), _C_LIGHT),
            ("TEXTCOLOR", (0, 0), (-1, -1), _C_TEXT),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("ALIGN", (1, 0), (1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        return tbl

    def _data_table(
        self,
        rows: List[List[str]],
        col_widths: Optional[List[float]] = None,
        header_color=None,
        font_size: int = 9,
    ) -> Table:
        """General data table with header row. Uses repeatRows=1 for auto page breaks."""
        if header_color is None:
            header_color = _C_SECONDARY

        # Auto-calculate equal widths if not provided
        if col_widths is None:
            ncols = len(rows[0]) if rows else 1
            col_widths = [_CONTENT_W / ncols] * ncols

        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), header_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), _C_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), font_size),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_C_WHITE, _C_LIGHT]),
        ]))
        return tbl

    # -- Charts --------------------------------------------------------

    @staticmethod
    def _embed_chart(png_bytes: bytes, width: float = 5.0) -> RLImage:
        """Wrap PNG bytes as a ReportLab Image flowable."""
        buf = io.BytesIO(png_bytes)
        img = RLImage(buf, width=width * inch, height=width * 0.5 * inch)
        img.hAlign = "CENTER"
        return img

    # -- Page decorations ----------------------------------------------

    def _page_decorations(self, canvas_obj, doc):
        canvas_obj.saveState()
        page_num = canvas_obj.getPageNumber()
        cid = self.data["meta"]["case_id"]

        # Footer
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(colors.grey)
        canvas_obj.drawCentredString(
            _PAGE_W / 2, 0.45 * inch,
            f"FEPD Report - Case {cid} - Page {page_num}",
        )
        canvas_obj.drawRightString(
            _PAGE_W - _MARGIN, 0.45 * inch,
            "CONFIDENTIAL",
        )
        canvas_obj.restoreState()

    # -- Metadata persistence ------------------------------------------

    def _save_metadata(self, report_path: Path, report_hash: str):
        meta = {
            "report_id": report_path.stem,
            "case_id": self.data["meta"]["case_id"],
            "generated": self.report_ts.isoformat(),
            "report_path": str(report_path),
            "sha256": report_hash,
            "generator": f"{APP_NAME} {APP_VERSION}",
            "organization": ORGANIZATION,
            "sections_included": self._section_manifest(),
        }
        mp = report_path.with_suffix(".json")
        with open(mp, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

    def _section_manifest(self) -> List[str]:
        """List which sections were included in this report."""
        present: List[str] = ["Header", "Executive Summary", "Case Information"]
        if self.data["evidence"]["filename"]:
            present.append("Evidence Overview")
        if self.data["system"]["platform"] or self.data["system"]["partitions"]:
            present.append("System Overview")
        if self.data["timeline"]["total"]:
            present.append("Timeline Analysis")
        tl = self.data["timeline"]
        if tl["df"] is not None and tl["cls_col"]:
            present.append("Suspicious Activity")
        if self.data["artifacts"]["total"]:
            present.append("Artifact Analysis")
        ml = self.data["ml"]
        if ml.get("anomalies") or ml.get("findings"):
            present.append("ML Anomaly Findings")
        if self.data["evidence"]["sha256"] or self.data["evidence"]["md5"]:
            present.append("Evidence Integrity")
        if self.data["coc"]["entries"]:
            present.append("Chain of Custody")
        present.append("Appendices")
        return present


# ===========================================================================
# UTILITIES
# ===========================================================================


def _fmt_size(n: int) -> str:
    v = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024:
            return f"{v:.2f} {u}"
        v /= 1024
    return f"{v:.2f} PB"


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def _esc(text: str) -> str:
    """Escape XML-special characters for ReportLab paragraphs."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

"""
Dynamic forensic UI renderer.
Renders strict JSON section payloads into runtime-generated labels and tables.
"""

from __future__ import annotations

from typing import Any, Dict, List

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QScrollArea,
)


class DynamicForensicRenderer:
    """Render section payloads with no hardcoded field widgets."""

    def __init__(self, tabs: QTabWidget):
        self.tabs = tabs

    def render_section(self, payload: Dict[str, Any]) -> None:
        section = str(payload.get("section", "Unnamed Section"))
        fields = payload.get("fields", {})
        if not isinstance(fields, dict):
            fields = {}

        tab = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        container = QWidget()
        layout = QVBoxLayout(container)

        # Render scalar fields first.
        for key, value in fields.items():
            if isinstance(value, list):
                continue
            layout.addWidget(QLabel(f"<b>{key}:</b> {self._fmt(value)}"))

        # Render list fields as tables.
        for key, value in fields.items():
            if not isinstance(value, list):
                continue
            layout.addWidget(QLabel(f"<b>{key}</b>"))
            layout.addWidget(self._build_table(value))

        # Footer meta.
        sources = payload.get("source", [])
        confidence = payload.get("confidence", 0)
        notes = payload.get("notes", "")
        layout.addWidget(QLabel(f"<b>Sources:</b> {', '.join([str(s) for s in sources])}"))
        layout.addWidget(QLabel(f"<b>Confidence:</b> {confidence}"))
        if notes:
            layout.addWidget(QLabel(f"<b>Notes:</b> {notes}"))

        scroll.setWidget(container)
        wrapper_layout = QVBoxLayout(tab)
        wrapper_layout.addWidget(scroll)

        self.tabs.addTab(tab, section)

    def _build_table(self, rows: List[Any]) -> QTableWidget:
        if not rows or not isinstance(rows[0], dict):
            table = QTableWidget(0, 1)
            table.setHorizontalHeaderLabels(["value"])
            for i, item in enumerate(rows):
                table.insertRow(i)
                table.setItem(i, 0, QTableWidgetItem(self._fmt(item)))
            return table

        columns = list(rows[0].keys())
        table = QTableWidget(len(rows), len(columns))
        table.setHorizontalHeaderLabels(columns)

        for r, row in enumerate(rows):
            for c, col in enumerate(columns):
                val = row.get(col, "") if isinstance(row, dict) else ""
                table.setItem(r, c, QTableWidgetItem(self._fmt(val)))

        table.resizeColumnsToContents()
        table.setAlternatingRowColors(True)
        return table

    @staticmethod
    def _fmt(value: Any) -> str:
        if value is None:
            return "null"
        return str(value)

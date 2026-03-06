"""
FEPD Breadcrumb Navigation Widget
===================================

Clickable breadcrumb bar that shows the current VFS path as interactive
segments, matching the Windows Explorer address-bar style.

Example display:
    This PC  ›  C:  ›  Users  ›  Alice  ›  Downloads

Clicking any segment navigates to that level.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QPushButton,
    QFrame, QSizePolicy, QLineEdit,
)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont


class BreadcrumbWidget(QFrame):
    """
    Clickable breadcrumb path bar.

    Signals:
        segment_clicked(str): Emitted with the full VFS path up to the
            clicked segment.
        path_edited(str): Emitted when the user finishes editing the raw
            path in edit mode.
    """

    segment_clicked = pyqtSignal(str)
    path_edited = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._current_path = "/"
        self._edit_mode = False

        self.setStyleSheet("""
            BreadcrumbWidget {
                background: #1e1e1e;
                border: 1px solid #3e3e42;
                border-radius: 2px;
            }
        """)

        self._root_layout = QHBoxLayout(self)
        self._root_layout.setContentsMargins(8, 4, 8, 4)
        self._root_layout.setSpacing(0)

        # Folder icon
        self._icon_label = QLabel("📁")
        self._icon_label.setStyleSheet("font-size: 14px; padding-right: 4px;")
        self._root_layout.addWidget(self._icon_label)

        # Container for breadcrumb buttons (swapped with QLineEdit in edit mode)
        self._breadcrumb_container = QWidget()
        self._breadcrumb_layout = QHBoxLayout(self._breadcrumb_container)
        self._breadcrumb_layout.setContentsMargins(0, 0, 0, 0)
        self._breadcrumb_layout.setSpacing(0)
        self._root_layout.addWidget(self._breadcrumb_container, 1)

        # Edit line (hidden by default)
        self._edit_line = QLineEdit()
        self._edit_line.setStyleSheet("""
            QLineEdit {
                background: transparent;
                border: none;
                color: #ffffff;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }
        """)
        self._edit_line.returnPressed.connect(self._finish_edit)
        self._edit_line.setVisible(False)
        self._root_layout.addWidget(self._edit_line, 1)

        # Edit toggle button
        self._edit_btn = QPushButton("✎")
        self._edit_btn.setFixedSize(22, 22)
        self._edit_btn.setToolTip("Edit path")
        self._edit_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: #888;
                font-size: 12px;
            }
            QPushButton:hover {
                color: #fff;
            }
        """)
        self._edit_btn.clicked.connect(self._toggle_edit_mode)
        self._root_layout.addWidget(self._edit_btn)

        # Initial state
        self.set_path("/")

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def set_path(self, path: str) -> None:
        """Update the breadcrumb to display *path*."""
        self._current_path = path or "/"
        if not self._edit_mode:
            self._rebuild_breadcrumbs()

    def set_icon(self, icon: str) -> None:
        """Change the leading icon."""
        self._icon_label.setText(icon)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rebuild_breadcrumbs(self):
        """Rebuild the clickable segment buttons from the current path."""
        # Clear existing
        while self._breadcrumb_layout.count():
            item = self._breadcrumb_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        parts = self._current_path.strip("/").split("/")
        if not parts or parts == [""]:
            parts = []

        # Always show root ("This PC" or "/")
        segments = [("This PC", "/")]
        accumulated = ""
        for part in parts:
            if part.lower() == "this pc":
                continue
            accumulated += f"/{part}"
            segments.append((part, accumulated))

        for i, (label_text, seg_path) in enumerate(segments):
            # Separator
            if i > 0:
                sep = QLabel("›")
                sep.setStyleSheet("color: #666; padding: 0 4px; font-size: 12px;")
                self._breadcrumb_layout.addWidget(sep)

            # Display path using Windows-style for drive letters
            display = label_text
            if ":" in display and len(display) <= 3:
                display = f"{display}\\"  # C: → C:\

            btn = QPushButton(display)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    border: none;
                    color: #e0e0e0;
                    padding: 2px 4px;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background: #333;
                    border-radius: 3px;
                    color: #ffffff;
                }
            """)
            btn.setToolTip(seg_path)

            # Capture seg_path in closure
            def _make_handler(p):
                return lambda: self.segment_clicked.emit(p)

            btn.clicked.connect(_make_handler(seg_path))
            self._breadcrumb_layout.addWidget(btn)

        # Stretch at end
        self._breadcrumb_layout.addStretch()

    def _toggle_edit_mode(self):
        """Switch between breadcrumb and raw-edit mode."""
        self._edit_mode = not self._edit_mode
        if self._edit_mode:
            # Switch to edit
            self._breadcrumb_container.setVisible(False)
            self._edit_line.setVisible(True)
            # Convert internal path to display path
            display = self._to_display_path(self._current_path)
            self._edit_line.setText(display)
            self._edit_line.setFocus()
            self._edit_line.selectAll()
            self._edit_btn.setText("✓")
        else:
            self._finish_edit()

    def _finish_edit(self):
        """Accept the typed path and switch back to breadcrumb mode."""
        self._edit_mode = False
        self._breadcrumb_container.setVisible(True)
        self._edit_line.setVisible(False)
        self._edit_btn.setText("✎")

        raw = self._edit_line.text().strip()
        if raw:
            converted = self._from_display_path(raw)
            self.path_edited.emit(converted)

    # ------------------------------------------------------------------
    # Path conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_display_path(vfs_path: str) -> str:
        """Convert VFS path to Windows-style display: /This PC/C:/Users → C:\\Users"""
        parts = vfs_path.strip("/").split("/")
        if not parts:
            return "This PC"
        # Skip "This PC" prefix
        if parts[0].lower() == "this pc":
            parts = parts[1:]
        if not parts:
            return "This PC"
        # Drive letter
        if ":" in parts[0]:
            if len(parts) == 1:
                return parts[0] + "\\"
            return parts[0] + "\\" + "\\".join(parts[1:])
        return "\\".join(parts)

    @staticmethod
    def _from_display_path(display: str) -> str:
        """Convert Windows-style display path back to VFS path."""
        # Replace backslashes
        path = display.replace("\\", "/").strip("/")
        parts = path.split("/")
        if not parts:
            return "/"
        # Prepend This PC if not present
        if parts[0].lower() != "this pc":
            return "/This PC/" + "/".join(parts)
        return "/" + "/".join(parts)

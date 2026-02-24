"""
FEPD Progress Indicators - Non-Blocking UI Feedback
====================================================

Provides visual feedback during long forensic operations without
blocking the UI thread.

Components:
- ForensicProgressDialog: Modal progress with cancel option
- ForensicSpinner: Non-blocking spinner overlay
- ProgressBanner: Status bar integration

This is part of the architecture that keeps FEPD responsive
while processing large evidence images.

Copyright (c) 2026 FEPD Development Team
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QWidget, QFrame, QApplication, QGraphicsOpacityEffect
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve,
    pyqtSignal, pyqtSlot, QSize
)
from PyQt6.QtGui import QMovie, QFont, QPainter, QColor, QPen
from typing import Optional, Callable
import math


# ============================================================================
# FORENSIC PROGRESS DIALOG
# ============================================================================

class ForensicProgressDialog(QDialog):
    """
    Modal progress dialog for long-running forensic operations.
    
    Features:
    - Progress bar with percentage
    - Current operation message
    - Cancel button with confirmation
    - Time elapsed/remaining
    - Read-only mode indicator
    
    Usage:
        dialog = ForensicProgressDialog(self, "Mounting Evidence")
        dialog.show()
        
        # Update progress
        dialog.set_progress(50, "Scanning partitions...")
        
        # Check for cancel
        if dialog.was_cancelled():
            abort_operation()
    """
    
    cancel_requested = pyqtSignal()
    
    def __init__(
        self,
        parent=None,
        title: str = "Processing Evidence",
        show_cancel: bool = True,
        show_time: bool = True
    ):
        super().__init__(parent)
        
        self._cancelled = False
        self._start_time = None
        
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(450)
        self.setMaximumWidth(600)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.CustomizeWindowHint |
            Qt.WindowType.WindowTitleHint
        )
        
        self._setup_ui(title, show_cancel, show_time)
        self._apply_style()
    
    def _setup_ui(self, title: str, show_cancel: bool, show_time: bool):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Title with icon
        title_layout = QHBoxLayout()
        
        self.icon_label = QLabel("🔍")
        self.icon_label.setStyleSheet("font-size: 32px;")
        title_layout.addWidget(self.icon_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #e0e0e0;
        """)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        layout.addLayout(title_layout)
        
        # Read-only indicator
        readonly_frame = QFrame()
        readonly_frame.setStyleSheet("""
            QFrame {
                background: #1a3a1a;
                border: 1px solid #2a5a2a;
                border-radius: 4px;
                padding: 4px 8px;
            }
        """)
        readonly_layout = QHBoxLayout(readonly_frame)
        readonly_layout.setContentsMargins(8, 4, 8, 4)
        readonly_label = QLabel("🔒 Read-Only Mode Active — Evidence Integrity Protected")
        readonly_label.setStyleSheet("color: #4ade80; font-size: 11px;")
        readonly_layout.addWidget(readonly_label)
        layout.addWidget(readonly_frame)
        
        # Status message
        self.status_label = QLabel("Initializing...")
        self.status_label.setStyleSheet("""
            color: #cccccc;
            font-size: 12px;
        """)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3e3e42;
                border-radius: 4px;
                background: #1e1e1e;
                height: 24px;
                text-align: center;
                color: #ffffff;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 #0078d4,
                    stop: 1 #106ebe
                );
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Current item
        self.item_label = QLabel("")
        self.item_label.setStyleSheet("color: #888888; font-size: 10px;")
        self.item_label.setWordWrap(True)
        layout.addWidget(self.item_label)
        
        # Time info (optional)
        if show_time:
            time_layout = QHBoxLayout()
            
            self.elapsed_label = QLabel("Elapsed: 0:00")
            self.elapsed_label.setStyleSheet("color: #888888; font-size: 11px;")
            time_layout.addWidget(self.elapsed_label)
            
            time_layout.addStretch()
            
            self.eta_label = QLabel("")
            self.eta_label.setStyleSheet("color: #888888; font-size: 11px;")
            time_layout.addWidget(self.eta_label)
            
            layout.addLayout(time_layout)
            
            # Timer for elapsed time updates
            self._elapsed_timer = QTimer(self)
            self._elapsed_timer.timeout.connect(self._update_elapsed)
        else:
            self._elapsed_timer = None
            self.elapsed_label = None
            self.eta_label = None
        
        # Button row
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        if show_cancel:
            self.cancel_btn = QPushButton("Cancel")
            self.cancel_btn.setMinimumWidth(100)
            self.cancel_btn.setStyleSheet("""
                QPushButton {
                    background: #3e3e42;
                    border: 1px solid #555;
                    border-radius: 4px;
                    padding: 8px 16px;
                    color: #cccccc;
                }
                QPushButton:hover {
                    background: #4e4e52;
                    border-color: #666;
                }
                QPushButton:pressed {
                    background: #2e2e32;
                }
            """)
            self.cancel_btn.clicked.connect(self._on_cancel)
            button_layout.addWidget(self.cancel_btn)
        else:
            self.cancel_btn = None
        
        layout.addLayout(button_layout)
    
    def _apply_style(self):
        """Apply dark theme styling."""
        self.setStyleSheet("""
            QDialog {
                background: #252526;
                border: 1px solid #3e3e42;
            }
        """)
    
    def showEvent(self, event):
        """Called when dialog is shown."""
        super().showEvent(event)
        import time
        self._start_time = time.time()
        if self._elapsed_timer:
            self._elapsed_timer.start(1000)
    
    def closeEvent(self, event):
        """Called when dialog is closed."""
        if self._elapsed_timer:
            self._elapsed_timer.stop()
        super().closeEvent(event)
    
    def _update_elapsed(self):
        """Update elapsed time display."""
        if not self._start_time or not self.elapsed_label:
            return
        
        import time
        elapsed = int(time.time() - self._start_time)
        minutes = elapsed // 60
        seconds = elapsed % 60
        self.elapsed_label.setText(f"Elapsed: {minutes}:{seconds:02d}")
    
    def _on_cancel(self):
        """Handle cancel button click."""
        from PyQt6.QtWidgets import QMessageBox
        
        reply = QMessageBox.question(
            self,
            "Cancel Operation?",
            "Are you sure you want to cancel?\n\n"
            "This may leave the operation in an incomplete state.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._cancelled = True
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.setText("Cancelling...")
            self.status_label.setText("Cancelling operation...")
            self.cancel_requested.emit()
    
    @pyqtSlot(int, str, str)
    def set_progress(self, percent: int, message: str = "", current_item: str = ""):
        """Update progress display."""
        self.progress_bar.setValue(percent)
        
        if message:
            self.status_label.setText(message)
        
        if current_item:
            # Truncate long paths
            if len(current_item) > 60:
                current_item = "..." + current_item[-57:]
            self.item_label.setText(current_item)
        
        # Update ETA
        if self._start_time and percent > 0 and self.eta_label:
            import time
            elapsed = time.time() - self._start_time
            if percent < 100:
                remaining = elapsed / percent * (100 - percent)
                minutes = int(remaining) // 60
                seconds = int(remaining) % 60
                self.eta_label.setText(f"ETA: ~{minutes}:{seconds:02d}")
            else:
                self.eta_label.setText("Complete!")
        
        # Process events to keep UI responsive
        QApplication.processEvents()
    
    def set_icon(self, icon: str):
        """Set the icon emoji."""
        self.icon_label.setText(icon)
    
    def was_cancelled(self) -> bool:
        """Check if user requested cancel."""
        return self._cancelled
    
    def finish(self, success: bool = True, message: str = ""):
        """Mark operation as complete."""
        if self._elapsed_timer:
            self._elapsed_timer.stop()
        
        if success:
            self.progress_bar.setValue(100)
            self.status_label.setText(message or "Operation completed successfully!")
            self.icon_label.setText("✅")
        else:
            self.status_label.setText(message or "Operation failed.")
            self.icon_label.setText("❌")
        
        if self.cancel_btn:
            self.cancel_btn.setText("Close")
            self.cancel_btn.setEnabled(True)
            self.cancel_btn.clicked.disconnect()
            self.cancel_btn.clicked.connect(self.accept)


# ============================================================================
# SPINNER WIDGET
# ============================================================================

class SpinnerWidget(QWidget):
    """
    Animated spinner for indicating activity.
    """
    
    def __init__(self, parent=None, size: int = 32, color: str = "#0078d4"):
        super().__init__(parent)
        
        self._size = size
        self._color = QColor(color)
        self._angle = 0
        self._line_count = 12
        
        self.setFixedSize(size, size)
        
        # Animation timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._rotate)
        self._timer.setInterval(80)
    
    def start(self):
        """Start the spinner animation."""
        self._timer.start()
        self.show()
    
    def stop(self):
        """Stop the spinner animation."""
        self._timer.stop()
        self.hide()
    
    def _rotate(self):
        """Rotate the spinner."""
        self._angle = (self._angle + 30) % 360
        self.update()
    
    def paintEvent(self, event):
        """Draw the spinner."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        width = self.width()
        height = self.height()
        
        painter.translate(width / 2, height / 2)
        painter.rotate(self._angle)
        
        for i in range(self._line_count):
            painter.rotate(360 / self._line_count)
            
            # Fade based on position
            alpha = int(255 * (i / self._line_count))
            color = QColor(self._color)
            color.setAlpha(alpha)
            
            pen = QPen(color)
            pen.setWidth(2)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            
            inner = self._size * 0.35
            outer = self._size * 0.45
            painter.drawLine(int(inner), 0, int(outer), 0)


# ============================================================================
# PROGRESS OVERLAY
# ============================================================================

class ProgressOverlay(QWidget):
    """
    Semi-transparent overlay with spinner for non-modal progress.
    
    Usage:
        overlay = ProgressOverlay(main_window)
        overlay.show_with_message("Loading evidence...")
        # ... do work ...
        overlay.hide()
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        self._setup_ui()
        self.hide()
    
    def _setup_ui(self):
        """Set up the overlay UI."""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Container with background
        container = QFrame()
        container.setStyleSheet("""
            QFrame {
                background: rgba(30, 30, 30, 230);
                border: 1px solid #3e3e42;
                border-radius: 8px;
                padding: 20px;
            }
        """)
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(16)
        container_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Spinner
        self.spinner = SpinnerWidget(size=48)
        self.spinner.setFixedSize(48, 48)
        container_layout.addWidget(self.spinner, 0, Qt.AlignmentFlag.AlignCenter)
        
        # Message
        self.message_label = QLabel("Loading...")
        self.message_label.setStyleSheet("""
            color: #e0e0e0;
            font-size: 14px;
            font-weight: bold;
        """)
        self.message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self.message_label)
        
        # Sub-message
        self.sub_message_label = QLabel("")
        self.sub_message_label.setStyleSheet("color: #888888; font-size: 11px;")
        self.sub_message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(self.sub_message_label)
        
        layout.addWidget(container)
    
    def show_with_message(self, message: str, sub_message: str = ""):
        """Show overlay with message."""
        self.message_label.setText(message)
        self.sub_message_label.setText(sub_message)
        
        # Resize to parent
        if self.parent():
            self.setGeometry(self.parent().rect())
        
        self.spinner.start()
        self.show()
        self.raise_()
    
    def update_message(self, message: str, sub_message: str = ""):
        """Update the displayed message."""
        self.message_label.setText(message)
        if sub_message:
            self.sub_message_label.setText(sub_message)
        QApplication.processEvents()
    
    def hideEvent(self, event):
        """Stop spinner when hidden."""
        self.spinner.stop()
        super().hideEvent(event)
    
    def paintEvent(self, event):
        """Draw semi-transparent background."""
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 128))


# ============================================================================
# STATUS BAR PROGRESS
# ============================================================================

class StatusBarProgress(QWidget):
    """
    Progress indicator for status bar integration.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Spinner
        self.spinner = SpinnerWidget(size=16)
        layout.addWidget(self.spinner)
        
        # Message
        self.message_label = QLabel("")
        self.message_label.setStyleSheet("color: #cccccc; font-size: 11px;")
        layout.addWidget(self.message_label)
        
        # Progress text
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #888888; font-size: 11px;")
        layout.addWidget(self.progress_label)
        
        self.hide()
    
    def start(self, message: str = "Processing..."):
        """Start showing progress."""
        self.message_label.setText(message)
        self.progress_label.setText("")
        self.spinner.start()
        self.show()
    
    def update(self, message: str = "", percent: int = -1):
        """Update progress display."""
        if message:
            self.message_label.setText(message)
        if percent >= 0:
            self.progress_label.setText(f"({percent}%)")
        QApplication.processEvents()
    
    def finish(self):
        """Hide progress indicator."""
        self.spinner.stop()
        self.hide()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def show_progress_dialog(
    parent,
    title: str,
    task_func: Callable,
    show_cancel: bool = True
) -> tuple:
    """
    Show progress dialog while running a task.
    
    Args:
        parent: Parent widget
        title: Dialog title
        task_func: Function that accepts (progress_callback) and returns result
        show_cancel: Whether to show cancel button
        
    Returns:
        (success: bool, result: Any)
    """
    dialog = ForensicProgressDialog(parent, title, show_cancel)
    dialog.show()
    
    result = None
    success = False
    
    try:
        def progress_callback(percent, message="", current=""):
            dialog.set_progress(percent, message, current)
            if dialog.was_cancelled():
                raise InterruptedError("User cancelled")
            QApplication.processEvents()
        
        result = task_func(progress_callback)
        success = True
        dialog.finish(True)
        
    except InterruptedError:
        dialog.finish(False, "Operation cancelled by user")
        
    except Exception as e:
        dialog.finish(False, f"Error: {str(e)}")
    
    dialog.exec()
    return success, result


# ============================================================================
# TEST
# ============================================================================

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    
    # Test progress dialog
    dialog = ForensicProgressDialog(None, "Mounting Evidence Image")
    dialog.show()
    
    # Simulate progress
    for i in range(101):
        dialog.set_progress(i, f"Processing... ({i}%)", f"C:\\Windows\\System32\\file{i}.dll")
        QApplication.processEvents()
        import time
        time.sleep(0.05)
    
    dialog.finish(True, "Evidence mounted successfully!")
    app.exec()

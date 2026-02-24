"""
Video Viewer
============

Read-only video/media player for forensic evidence.
Uses Qt Multimedia if available.
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout,
    QPushButton, QSlider, QStyle, QSizePolicy
)
from PyQt6.QtCore import Qt, QUrl, QTimer
from typing import Optional
from pathlib import Path
import tempfile
import os

from .base_viewer import BaseViewer

# Try to import Qt Multimedia
try:
    from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
    from PyQt6.QtMultimediaWidgets import QVideoWidget
    QTMULTIMEDIA_AVAILABLE = True
except ImportError:
    QTMULTIMEDIA_AVAILABLE = False


class VideoViewer(BaseViewer):
    """
    Video/Media player for forensic evidence.
    
    Features:
    - Play/Pause/Stop controls
    - Seek slider
    - Volume control
    - Time display
    """
    
    SUPPORTED_EXTENSIONS = [
        '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv',
        '.webm', '.m4v', '.mpeg', '.mpg', '.3gp',
        '.mp3', '.wav', '.flac', '.ogg', '.m4a', '.wma', '.aac'
    ]
    
    def __init__(self, parent: Optional[QWidget] = None, read_file_func=None):
        # Initialize attributes BEFORE super().__init__() since it calls _create_content_widget()
        self._temp_file: Optional[str] = None
        
        super().__init__(parent, title="Media Player", read_file_func=read_file_func)
        self.title_icon.setText("🎬")
        self._media_player = None
        self._audio_output = None
    
    def _create_content_widget(self) -> QWidget:
        """Create video display widget."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        
        if not QTMULTIMEDIA_AVAILABLE:
            # Fallback label
            self.fallback_label = QLabel(
                "Video playback requires Qt Multimedia\n\n"
                "Install with: pip install PyQt6-Qt6\n\n"
                "This includes the multimedia components."
            )
            self.fallback_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.fallback_label.setStyleSheet("""
                QLabel {
                    color: #888;
                    font-size: 14px;
                    background: #1e1e1e;
                }
            """)
            layout.addWidget(self.fallback_label)
            return container
        
        # Video widget
        self.video_widget = QVideoWidget()
        self.video_widget.setStyleSheet("background: black;")
        layout.addWidget(self.video_widget)
        
        # Create media player
        self._media_player = QMediaPlayer()
        self._audio_output = QAudioOutput()
        self._media_player.setAudioOutput(self._audio_output)
        self._media_player.setVideoOutput(self.video_widget)
        
        # Connect signals
        self._media_player.positionChanged.connect(self._position_changed)
        self._media_player.durationChanged.connect(self._duration_changed)
        self._media_player.playbackStateChanged.connect(self._state_changed)
        
        # Control bar
        control_bar = QWidget()
        control_layout = QHBoxLayout(control_bar)
        control_layout.setContentsMargins(8, 4, 8, 4)
        
        btn_style = """
            QPushButton {
                background: #3d3d3d;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 3px;
                padding: 6px 12px;
                font-size: 14px;
            }
            QPushButton:hover { background: #4d4d4d; }
            QPushButton:pressed { background: #2d2d2d; }
        """
        
        # Play/Pause button
        self.play_btn = QPushButton("▶")
        self.play_btn.setFixedWidth(50)
        self.play_btn.clicked.connect(self._toggle_play)
        self.play_btn.setStyleSheet(btn_style)
        control_layout.addWidget(self.play_btn)
        
        # Stop button
        stop_btn = QPushButton("⏹")
        stop_btn.setFixedWidth(50)
        stop_btn.clicked.connect(self._stop)
        stop_btn.setStyleSheet(btn_style)
        control_layout.addWidget(stop_btn)
        
        # Time display
        self.time_label = QLabel("00:00 / 00:00")
        self.time_label.setStyleSheet("color: #e0e0e0; min-width: 100px;")
        control_layout.addWidget(self.time_label)
        
        # Seek slider
        self.seek_slider = QSlider(Qt.Orientation.Horizontal)
        self.seek_slider.setRange(0, 0)
        self.seek_slider.sliderMoved.connect(self._seek)
        self.seek_slider.setStyleSheet("""
            QSlider::groove:horizontal {
                background: #3d3d3d;
                height: 6px;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: #0078d4;
                width: 14px;
                margin: -4px 0;
                border-radius: 7px;
            }
            QSlider::sub-page:horizontal {
                background: #0078d4;
                border-radius: 3px;
            }
        """)
        control_layout.addWidget(self.seek_slider)
        
        # Volume
        control_layout.addWidget(QLabel("🔊"))
        self.volume_slider = QSlider(Qt.Orientation.Horizontal)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(70)
        self.volume_slider.setFixedWidth(80)
        self.volume_slider.valueChanged.connect(self._set_volume)
        self.volume_slider.setStyleSheet(self.seek_slider.styleSheet())
        control_layout.addWidget(self.volume_slider)
        
        control_bar.setStyleSheet("background: #252525; border-top: 1px solid #3d3d3d;")
        layout.addWidget(control_bar)
        
        return container
    
    def load_file(self, path: str, data: Optional[bytes] = None) -> bool:
        """Load media file."""
        try:
            name = Path(path).name
            self.set_file_info(path, name)
            
            # Get file data
            if data is None and self.read_file_func:
                data = self.read_file_func(path, 0, -1)
            
            if data is None:
                if hasattr(self, 'fallback_label'):
                    self.fallback_label.setText("Error: Could not read file")
                return False
            
            if not QTMULTIMEDIA_AVAILABLE:
                self.fallback_label.setText(
                    f"File: {name}\n"
                    f"Size: {self._format_size(len(data))}\n\n"
                    "Qt Multimedia not available for playback"
                )
                self.set_status(f"Size: {self._format_size(len(data))}")
                return True
            
            # Write to temp file (QMediaPlayer needs file path)
            ext = Path(path).suffix
            fd, temp_path = tempfile.mkstemp(suffix=ext)
            os.write(fd, data)
            os.close(fd)
            
            self._temp_file = temp_path
            
            # Load in media player
            self._media_player.setSource(QUrl.fromLocalFile(temp_path))
            self._audio_output.setVolume(self.volume_slider.value() / 100)
            
            self.set_status(f"Size: {self._format_size(len(data))}")
            
            return True
            
        except Exception as e:
            if hasattr(self, 'fallback_label'):
                self.fallback_label.setText(f"Error loading media: {e}")
            return False
    
    def _toggle_play(self):
        """Toggle play/pause."""
        if not self._media_player:
            return
        
        if self._media_player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self._media_player.pause()
        else:
            self._media_player.play()
    
    def _stop(self):
        """Stop playback."""
        if self._media_player:
            self._media_player.stop()
    
    def _seek(self, position: int):
        """Seek to position."""
        if self._media_player:
            self._media_player.setPosition(position)
    
    def _set_volume(self, volume: int):
        """Set volume level."""
        if self._audio_output:
            self._audio_output.setVolume(volume / 100)
    
    def _position_changed(self, position: int):
        """Handle position change."""
        self.seek_slider.setValue(position)
        self._update_time_label()
    
    def _duration_changed(self, duration: int):
        """Handle duration change."""
        self.seek_slider.setRange(0, duration)
        self._update_time_label()
    
    def _state_changed(self, state):
        """Handle playback state change."""
        if state == QMediaPlayer.PlaybackState.PlayingState:
            self.play_btn.setText("⏸")
        else:
            self.play_btn.setText("▶")
    
    def _update_time_label(self):
        """Update time display."""
        if not self._media_player:
            return
        
        position = self._media_player.position()
        duration = self._media_player.duration()
        
        self.time_label.setText(
            f"{self._format_time(position)} / {self._format_time(duration)}"
        )
    
    def _format_time(self, ms: int) -> str:
        """Format milliseconds as mm:ss."""
        s = ms // 1000
        m = s // 60
        s = s % 60
        return f"{m:02d}:{s:02d}"
    
    def _format_size(self, size: int) -> str:
        """Format byte size."""
        size_f = float(size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_f < 1024:
                return f"{size_f:.1f} {unit}"
            size_f /= 1024
        return f"{size_f:.1f} TB"
    
    def get_supported_extensions(self) -> list:
        return self.SUPPORTED_EXTENSIONS
    
    def close(self):
        """Clean up resources."""
        if self._media_player:
            self._media_player.stop()
        
        # Clean up temp file
        if self._temp_file and os.path.exists(self._temp_file):
            try:
                os.remove(self._temp_file)
            except:
                pass
        
        super().close()

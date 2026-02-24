"""
FEPD - Forensic Chatbot Tab
RAG-powered AI assistant for forensic case analysis.

Provides a conversational interface where investigators can ask questions
about the currently loaded case.  Backed by ForensicRAGEngine.

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import threading
from pathlib import Path
from typing import Optional, Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QGroupBox, QSplitter, QScrollArea,
    QProgressBar, QFrame, QToolButton,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor, QIcon

logger = logging.getLogger(__name__)


class ChatBubble(QFrame):
    """A single chat message bubble."""

    def __init__(self, text: str, role: str = "user", sources: str = "", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)

        is_user = role == "user"
        bg = "#1b3a5c" if is_user else "#1e1e2e"
        border_color = "#3a7bd5" if is_user else "#4a4a6a"
        label_color = "#3a7bd5" if is_user else "#50c878"
        role_label = "🧑‍💻 You" if is_user else "🤖 FEPD Assistant"

        self.setStyleSheet(f"""
            ChatBubble {{
                background-color: {bg};
                border: 1px solid {border_color};
                border-radius: 10px;
                padding: 8px;
                margin: 4px {'40px 4px 4px' if not is_user else '4px 4px 40px'};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(4)

        # Role header
        header = QLabel(role_label)
        header.setStyleSheet(f"color: {label_color}; font-weight: bold; font-size: 11px; border: none;")
        layout.addWidget(header)

        # Message body
        body = QLabel(text)
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.setStyleSheet("color: #e0e0e0; font-size: 13px; border: none; padding: 2px 0;")
        layout.addWidget(body)

        # Sources (for assistant messages)
        if sources and not is_user:
            src_label = QLabel(sources)
            src_label.setWordWrap(True)
            src_label.setStyleSheet(
                "color: #888; font-size: 10px; font-style: italic; border: none; "
                "padding-top: 4px; border-top: 1px solid #333;"
            )
            layout.addWidget(src_label)


class ChatbotTab(QWidget):
    """
    Chatbot tab for the FEPD main window.
    
    Features:
    - Chat interface with message bubbles
    - RAG-powered answers from case data
    - Auto-indexing on case load
    - Stats panel showing engine info
    - Chat history with clear option
    """

    # Signals for thread-safe UI updates
    _append_message_signal = pyqtSignal(str, str, str)  # text, role, sources
    _indexing_done_signal = pyqtSignal(int)  # chunk_count
    _update_status_signal = pyqtSignal(str)  # status text
    _update_progress_signal = pyqtSignal(int, str)  # pct, msg

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rag_engine = None
        self._case_path: Optional[Path] = None
        self._case_metadata: Optional[Dict] = None
        self._is_indexing = False

        self._init_ui()
        self._connect_signals()

        logger.info("ChatbotTab initialized")

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- Left: Chat area ----
        chat_container = QWidget()
        chat_layout = QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(8, 8, 4, 8)

        # Header
        header = QLabel("💬 FEPD Forensic Chatbot")
        header.setStyleSheet(
            "font-size: 16px; font-weight: bold; color: #3a7bd5; padding: 6px 0;"
        )
        chat_layout.addWidget(header)

        subtitle = QLabel(
            "Ask questions about the current forensic case. "
            "The AI retrieves relevant evidence to answer."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #999; font-size: 11px; padding-bottom: 4px;")
        chat_layout.addWidget(subtitle)

        # Chat scroll area
        self._chat_scroll = QScrollArea()
        self._chat_scroll.setWidgetResizable(True)
        self._chat_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._chat_scroll.setStyleSheet(
            "QScrollArea { background-color: #141422; border: 1px solid #2a2a3a; border-radius: 8px; }"
        )

        self._chat_widget = QWidget()
        self._chat_layout = QVBoxLayout(self._chat_widget)
        self._chat_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._chat_layout.setSpacing(6)
        self._chat_layout.setContentsMargins(6, 6, 6, 6)

        # Welcome message
        welcome = QLabel(
            "👋 Welcome! Load a case and I'll index the evidence automatically.\n"
            "Then ask me anything about the case — artifacts, timelines, files, anomalies…"
        )
        welcome.setWordWrap(True)
        welcome.setStyleSheet(
            "color: #aaa; font-size: 12px; padding: 20px; "
            "background: #1a1a2e; border: 1px dashed #333; border-radius: 8px;"
        )
        welcome.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._welcome_label = welcome
        self._chat_layout.addWidget(welcome)

        self._chat_scroll.setWidget(self._chat_widget)
        chat_layout.addWidget(self._chat_scroll, stretch=1)

        # Progress bar (hidden by default)
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setVisible(False)
        self._progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #333;
                border-radius: 4px;
                text-align: center;
                color: #eee;
                background: #1e1e2e;
                height: 20px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3a7bd5, stop:1 #50c878);
                border-radius: 3px;
            }
        """)
        chat_layout.addWidget(self._progress_bar)

        # Input area
        input_frame = QFrame()
        input_frame.setStyleSheet(
            "QFrame { background: #1e1e2e; border: 1px solid #333; border-radius: 8px; padding: 4px; }"
        )
        input_layout = QHBoxLayout(input_frame)
        input_layout.setContentsMargins(8, 4, 8, 4)

        self._input_field = QLineEdit()
        self._input_field.setPlaceholderText("Ask a question about the case…")
        self._input_field.setStyleSheet(
            "QLineEdit { background: #252535; color: #eee; border: 1px solid #444; "
            "border-radius: 6px; padding: 8px 12px; font-size: 13px; }"
            "QLineEdit:focus { border-color: #3a7bd5; }"
        )
        input_layout.addWidget(self._input_field, stretch=1)

        self._send_btn = QPushButton("Send ➤")
        self._send_btn.setStyleSheet(
            "QPushButton { background: #3a7bd5; color: white; border: none; "
            "border-radius: 6px; padding: 8px 18px; font-weight: bold; font-size: 13px; }"
            "QPushButton:hover { background: #4a8be5; }"
            "QPushButton:pressed { background: #2a6bc5; }"
            "QPushButton:disabled { background: #555; color: #999; }"
        )
        input_layout.addWidget(self._send_btn)

        chat_layout.addWidget(input_frame)

        splitter.addWidget(chat_container)

        # ---- Right: Sidebar ----
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(4, 8, 8, 8)

        # Engine Status card
        status_group = QGroupBox("🔧 Engine Status")
        status_group.setStyleSheet(
            "QGroupBox { color: #3a7bd5; font-weight: bold; border: 1px solid #333; "
            "border-radius: 8px; margin-top: 10px; padding-top: 14px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }"
        )
        sg_layout = QVBoxLayout(status_group)
        sg_layout.setSpacing(6)

        self._status_label = QLabel("⏳ Waiting for case…")
        self._status_label.setWordWrap(True)
        self._status_label.setStyleSheet("color: #ccc; font-size: 12px;")
        sg_layout.addWidget(self._status_label)

        self._stats_label = QLabel("")
        self._stats_label.setWordWrap(True)
        self._stats_label.setStyleSheet("color: #888; font-size: 11px;")
        sg_layout.addWidget(self._stats_label)

        sidebar_layout.addWidget(status_group)

        # Quick Prompts card
        prompts_group = QGroupBox("⚡ Quick Prompts")
        prompts_group.setStyleSheet(
            "QGroupBox { color: #50c878; font-weight: bold; border: 1px solid #333; "
            "border-radius: 8px; margin-top: 10px; padding-top: 14px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }"
        )
        pg_layout = QVBoxLayout(prompts_group)
        pg_layout.setSpacing(4)

        quick_prompts = [
            ("📋 Summarize this case", "Provide a comprehensive summary of this forensic case including key findings."),
            ("🔍 Suspicious files", "What suspicious or potentially malicious files were found in this case?"),
            ("📅 Timeline overview", "Give me a timeline overview of key events found in the evidence."),
            ("🌐 Network activity", "What network activity, IPs, or URLs were found in the evidence?"),
            ("👤 User activity", "What user activity or accounts were identified in the evidence?"),
            ("⚠️ Anomalies", "What anomalies or indicators of compromise were detected?"),
            ("🗂️ Artifact summary", "Summarize the main artifacts (registry, event logs, browser history, etc)."),
            ("📊 Evidence stats", "What are the statistics of the indexed evidence? File types, counts, etc."),
        ]

        btn_style = (
            "QPushButton { background: #252535; color: #ccc; border: 1px solid #3a3a4a; "
            "border-radius: 6px; padding: 6px 10px; text-align: left; font-size: 11px; }"
            "QPushButton:hover { background: #2a2a4a; border-color: #3a7bd5; color: #fff; }"
        )

        for label, prompt in quick_prompts:
            btn = QPushButton(label)
            btn.setStyleSheet(btn_style)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, p=prompt: self._send_prompt(p))
            pg_layout.addWidget(btn)

        sidebar_layout.addWidget(prompts_group)

        # API Key status card (auto-loads from .env)
        api_group = QGroupBox("🔑 LLM Status")
        api_group.setStyleSheet(
            "QGroupBox { color: #e07bea; font-weight: bold; border: 1px solid #333; "
            "border-radius: 8px; margin-top: 10px; padding-top: 14px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }"
        )
        api_layout = QVBoxLayout(api_group)
        api_layout.setSpacing(6)

        self._api_status_label = QLabel("Detecting LLM backend…")
        self._api_status_label.setWordWrap(True)
        self._api_status_label.setStyleSheet("color: #888; font-size: 10px;")
        api_layout.addWidget(self._api_status_label)

        env_hint = QLabel(
            "💡 Set GOOGLE_API_KEY or OPENAI_API_KEY\n"
            "in the .env file at the project root."
        )
        env_hint.setWordWrap(True)
        env_hint.setStyleSheet("color: #666; font-size: 10px; padding-top: 4px;")
        api_layout.addWidget(env_hint)

        self._refresh_llm_btn = QPushButton("🔄 Refresh LLM")
        self._refresh_llm_btn.setStyleSheet(
            "QPushButton { background: #252535; color: #ccc; border: 1px solid #3a3a4a; "
            "border-radius: 6px; padding: 6px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #2a2a4a; border-color: #e07bea; color: #fff; }"
        )
        self._refresh_llm_btn.clicked.connect(self._refresh_llm_backend)
        api_layout.addWidget(self._refresh_llm_btn)

        sidebar_layout.addWidget(api_group)

        # Auto-detect LLM backend on startup
        QTimer.singleShot(500, self._refresh_llm_backend)

        # Actions
        actions_group = QGroupBox("🛠 Actions")
        actions_group.setStyleSheet(
            "QGroupBox { color: #e8a838; font-weight: bold; border: 1px solid #333; "
            "border-radius: 8px; margin-top: 10px; padding-top: 14px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }"
        )
        ag_layout = QVBoxLayout(actions_group)

        action_btn_style = (
            "QPushButton { background: #252535; color: #ccc; border: 1px solid #3a3a4a; "
            "border-radius: 6px; padding: 6px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #2a2a4a; border-color: #e8a838; color: #fff; }"
        )

        self._reindex_btn = QPushButton("🔄 Re-index Case")
        self._reindex_btn.setStyleSheet(action_btn_style)
        self._reindex_btn.clicked.connect(self._reindex_case)
        ag_layout.addWidget(self._reindex_btn)

        self._clear_btn = QPushButton("🗑 Clear Chat")
        self._clear_btn.setStyleSheet(action_btn_style)
        self._clear_btn.clicked.connect(self._clear_chat)
        ag_layout.addWidget(self._clear_btn)

        sidebar_layout.addWidget(actions_group)
        sidebar_layout.addStretch()

        splitter.addWidget(sidebar)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        root.addWidget(splitter)

    def _connect_signals(self):
        self._send_btn.clicked.connect(self._on_send)
        self._input_field.returnPressed.connect(self._on_send)
        self._append_message_signal.connect(self._add_bubble)
        self._indexing_done_signal.connect(self._on_indexing_done)
        self._update_status_signal.connect(self._set_status)
        self._update_progress_signal.connect(self._on_progress)

    # ------------------------------------------------------------------
    # Public API — called by MainWindow
    # ------------------------------------------------------------------

    def set_case_context(self, case_path: Path, case_metadata: Dict[str, Any]):
        """
        Called by MainWindow.load_case() to set the case and start indexing.
        """
        self._case_path = case_path
        self._case_metadata = case_metadata

        # Lazy-import to keep startup fast
        from src.modules.rag_engine import ForensicRAGEngine

        if self._rag_engine is None:
            self._rag_engine = ForensicRAGEngine()

        self._start_indexing()

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def _start_indexing(self):
        if self._is_indexing:
            return
        self._is_indexing = True
        self._send_btn.setEnabled(False)
        self._reindex_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._update_status_signal.emit("⏳ Indexing case data…")

        t = threading.Thread(target=self._index_worker, daemon=True)
        t.start()

    def _index_worker(self):
        try:
            count = self._rag_engine.index_case(
                self._case_path,
                self._case_metadata,
                progress_callback=self._progress_cb,
            )
            self._indexing_done_signal.emit(count)
        except Exception as exc:
            logger.error(f"Indexing failed: {exc}", exc_info=True)
            self._update_status_signal.emit(f"❌ Indexing failed: {exc}")
            self._indexing_done_signal.emit(0)

    def _progress_cb(self, pct: int, msg: str):
        self._update_progress_signal.emit(pct, msg)

    def _on_progress(self, pct: int, msg: str):
        self._progress_bar.setValue(pct)
        self._progress_bar.setFormat(f"{pct}% — {msg}")

    def _on_indexing_done(self, chunk_count: int):
        self._is_indexing = False
        self._send_btn.setEnabled(True)
        self._reindex_btn.setEnabled(True)
        self._progress_bar.setVisible(False)

        if chunk_count > 0:
            stats = self._rag_engine.get_stats()
            self._set_status(f"✅ Ready — {chunk_count} chunks indexed")
            self._stats_label.setText(
                f"📦 Chunks: {stats['total_chunks']}\n"
                f"🧠 LLM: {stats['llm_backend']} ({stats['llm_model'] or 'n/a'})\n"
                f"📐 Embeddings: {stats['embedding_backend']}\n"
                f"📂 Case: {stats['case_id']}"
            )
            # Hide welcome and show ready message
            if self._welcome_label.isVisible():
                self._welcome_label.setText(
                    f"✅ Case indexed! {chunk_count} chunks ready.\n"
                    "Ask me anything about the evidence."
                )
                self._welcome_label.setStyleSheet(
                    "color: #50c878; font-size: 12px; padding: 20px; "
                    "background: #1a2e1a; border: 1px dashed #50c878; border-radius: 8px;"
                )
        else:
            self._set_status("⚠️ No data indexed — is the case directory empty?")

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------

    def _on_send(self):
        text = self._input_field.text().strip()
        if not text:
            return
        self._send_prompt(text)

    def _send_prompt(self, text: str):
        self._input_field.clear()

        # Hide welcome label once first message is sent
        if self._welcome_label.isVisible():
            self._welcome_label.setVisible(False)

        # Show user bubble
        self._add_bubble(text, "user", "")

        # Disable input while generating
        self._send_btn.setEnabled(False)
        self._input_field.setEnabled(False)

        # Run query in background thread
        t = threading.Thread(target=self._query_worker, args=(text,), daemon=True)
        t.start()

    def _query_worker(self, question: str):
        try:
            if self._rag_engine is None:
                self._append_message_signal.emit(
                    "⚠️ No case loaded. Please load a case first.", "assistant", ""
                )
                return

            result = self._rag_engine.ask(question)

            # Format sources
            sources = ""
            if result["context"]:
                src_parts = []
                seen = set()
                for c in result["context"]:
                    s = c["metadata"].get("source", "unknown")
                    if s not in seen:
                        seen.add(s)
                        src_parts.append(f"📎 {s} (score: {c['score']:.2f})")
                sources = "Sources: " + " | ".join(src_parts[:4])

            self._append_message_signal.emit(result["answer"], "assistant", sources)

        except Exception as exc:
            logger.error(f"Query failed: {exc}", exc_info=True)
            self._append_message_signal.emit(
                f"❌ Error: {exc}", "assistant", ""
            )
        finally:
            # Re-enable input on main thread
            QTimer.singleShot(0, self._enable_input)

    def _enable_input(self):
        self._send_btn.setEnabled(True)
        self._input_field.setEnabled(True)
        self._input_field.setFocus()

    # ------------------------------------------------------------------
    # UI Helpers
    # ------------------------------------------------------------------

    def _add_bubble(self, text: str, role: str, sources: str):
        bubble = ChatBubble(text, role, sources)
        self._chat_layout.addWidget(bubble)
        # Auto-scroll to bottom
        QTimer.singleShot(50, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        sb = self._chat_scroll.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _set_status(self, text: str):
        self._status_label.setText(text)

    def _clear_chat(self):
        # Remove all bubbles
        while self._chat_layout.count():
            item = self._chat_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        if self._rag_engine:
            self._rag_engine.clear_history()

        # Re-add welcome
        self._welcome_label = QLabel(
            "💬 Chat cleared. Ask a new question about the case."
        )
        self._welcome_label.setWordWrap(True)
        self._welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._welcome_label.setStyleSheet(
            "color: #aaa; font-size: 12px; padding: 20px; "
            "background: #1a1a2e; border: 1px dashed #333; border-radius: 8px;"
        )
        self._chat_layout.addWidget(self._welcome_label)

    def _reindex_case(self):
        if self._case_path and self._case_metadata:
            self._start_indexing()
        else:
            self._set_status("⚠️ No case loaded to re-index.")

    def _refresh_llm_backend(self):
        """Re-detect LLM backend from environment variables (.env file)."""
        from src.modules.rag_engine import ForensicRAGEngine, LLMProvider

        # Debounce: skip if already refreshing or refreshed very recently
        import time
        now = time.time()
        if hasattr(self, '_last_llm_refresh') and (now - self._last_llm_refresh) < 2.0:
            return
        self._last_llm_refresh = now

        # Re-load .env so fresh keys are picked up
        try:
            from dotenv import load_dotenv
            load_dotenv(override=True)
        except ImportError:
            pass

        # Reuse existing RAG engine; only re-detect backend (no new LLMProvider)
        if self._rag_engine is None:
            self._rag_engine = ForensicRAGEngine()
        else:
            # Re-detect on the existing provider instead of creating a new one
            self._rag_engine.llm.backend = "offline"
            self._rag_engine.llm._client = None
            self._rag_engine.llm._model_name = ""
            self._rag_engine.llm._detect_backend()

        backend = self._rag_engine.llm.backend
        model = self._rag_engine.llm._model_name

        if backend != "offline":
            self._api_status_label.setText(f"✅ Connected: {backend} ({model})")
            self._api_status_label.setStyleSheet("color: #50c878; font-size: 10px;")
            self._set_status(f"✅ LLM: {backend} ({model})")
        else:
            self._api_status_label.setText(
                "⚠️ Offline mode — no API key found.\n"
                "Add GOOGLE_API_KEY or OPENAI_API_KEY to .env"
            )
            self._api_status_label.setStyleSheet("color: #e8a838; font-size: 10px;")
            self._set_status("⚠️ LLM: offline mode")

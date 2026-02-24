"""
FEPD - RAG (Retrieval-Augmented Generation) Engine
Forensic Evidence Chatbot Backend

Indexes case data (artifacts, evidence files, metadata, logs) into a
vector store and provides retrieval-augmented answers using an LLM.

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import json
import logging
import os
import hashlib
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

import numpy as np

logger = logging.getLogger(__name__)

# Load .env from project root at module import time
# This ensures GOOGLE_API_KEY / OPENAI_API_KEY are available
# before any LLMProvider or ForensicRAGEngine is created.
try:
    from dotenv import load_dotenv as _load_dotenv
    _env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    _load_dotenv(_env_path, override=True)
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Lightweight in-process vector store (no external DB dependency)
# ---------------------------------------------------------------------------

class MiniVectorStore:
    """
    Simple NumPy-backed vector store.  Good enough for per-case forensic
    document collections (typically < 50 000 chunks) without requiring
    ChromaDB / FAISS as a hard dependency.

    Maintains a pre-normalised embedding matrix so queries are a single
    matrix-vector multiply with no per-query allocation.
    """

    def __init__(self):
        self.embeddings: List[np.ndarray] = []
        self.documents: List[str] = []
        self.metadatas: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        # Cached / pre-normalised matrix — rebuilt on add()/clear()
        self._mat: Optional[np.ndarray] = None
        self._norms: Optional[np.ndarray] = None

    # ----- internal -----
    def _rebuild_cache(self):
        """Pre-stack and pre-normalise embeddings for fast cosine queries."""
        if not self.embeddings:
            self._mat = None
            self._norms = None
            return
        self._mat = np.stack(self.embeddings)                       # (N, D)
        self._norms = np.linalg.norm(self._mat, axis=1, keepdims=True)  # (N, 1)
        self._norms[self._norms == 0] = 1e-10

    # ----- mutate -----
    def add(self, texts: List[str], embeddings: List[np.ndarray],
            metadatas: Optional[List[Dict]] = None):
        with self._lock:
            for i, (txt, emb) in enumerate(zip(texts, embeddings)):
                self.embeddings.append(np.asarray(emb, dtype=np.float32))
                self.documents.append(txt)
                self.metadatas.append(metadatas[i] if metadatas else {})
            self._rebuild_cache()

    def clear(self):
        with self._lock:
            self.embeddings.clear()
            self.documents.clear()
            self.metadatas.clear()
            self._mat = None
            self._norms = None

    # ----- query -----
    def query(self, query_emb: np.ndarray, top_k: int = 5) -> List[Dict]:
        """Return top_k most similar documents by cosine similarity."""
        with self._lock:
            if self._mat is None or len(self.embeddings) == 0:
                return []
            q = np.asarray(query_emb, dtype=np.float32)
            q_norm = np.linalg.norm(q)
            if q_norm == 0:
                q_norm = 1e-10
            # Cosine similarity via pre-normalised matrix
            sims = (self._mat @ q) / (self._norms.ravel() * q_norm)
            # Partial sort is faster than full argsort for large N
            k = min(top_k, len(sims))
            idxs = np.argpartition(-sims, k)[:k]
            idxs = idxs[np.argsort(-sims[idxs])]  # sort the top-k
            results = []
            for idx in idxs:
                results.append({
                    "text": self.documents[idx],
                    "metadata": self.metadatas[idx],
                    "score": float(sims[idx]),
                })
            return results

    @property
    def size(self) -> int:
        return len(self.documents)


# ---------------------------------------------------------------------------
# Embedding helpers
# ---------------------------------------------------------------------------

def _simple_hash_embedding(text: str, dim: int = 384) -> np.ndarray:
    """
    Deterministic pseudo-embedding using SHA-256 expansion.
    Works offline — no model download needed.  Quality is obviously
    lower than a real transformer model, but enables the feature to
    work out-of-the-box.
    """
    h = hashlib.sha256(text.lower().encode("utf-8")).digest()
    rng = np.random.RandomState(int.from_bytes(h[:4], "big"))
    vec = rng.randn(dim).astype(np.float32)
    vec /= np.linalg.norm(vec) + 1e-10
    return vec


class EmbeddingProvider:
    """Generates embeddings — tries sentence-transformers, falls back to hash."""

    def __init__(self):
        self._model = None
        self._backend = "hash"
        self._try_load_model()

    def _try_load_model(self):
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._backend = "sentence-transformers"
            logger.info("EmbeddingProvider: using sentence-transformers (all-MiniLM-L6-v2)")
        except Exception:
            logger.info("EmbeddingProvider: sentence-transformers not available, using hash embeddings")

    def embed(self, texts: List[str]) -> List[np.ndarray]:
        if self._backend == "sentence-transformers" and self._model is not None:
            vecs = self._model.encode(texts, show_progress_bar=False, convert_to_numpy=True)
            return [v for v in vecs]
        return [_simple_hash_embedding(t) for t in texts]

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]


# ---------------------------------------------------------------------------
# LLM Provider
# ---------------------------------------------------------------------------

class LLMProvider:
    """
    Calls an LLM to generate an answer given context + question.
    Supports:
      1. OpenAI API  (needs OPENAI_API_KEY env var)
      2. Google Gemini API (needs GOOGLE_API_KEY env var)
      3. Ollama local (needs ollama running)
      4. Offline fallback — returns retrieved context as-is
    """

    def __init__(self):
        self.backend = "offline"
        self._client = None
        self._model_name = ""
        self._detect_backend()

    def _detect_backend(self):
        # 1. OpenAI
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if api_key:
            try:
                import openai
                self._client = openai.OpenAI(api_key=api_key)
                self.backend = "openai"
                self._model_name = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
                logger.info(f"LLMProvider: using OpenAI ({self._model_name})")
                return
            except Exception as exc:
                logger.warning(f"OpenAI init failed: {exc}")

        # 2. Google Gemini
        google_key = os.environ.get("GOOGLE_API_KEY", "")
        if google_key:
            self._configure_gemini(google_key)
            if self.backend == "gemini":
                return

        # 3. Ollama (local)
        try:  # noqa
            import requests
            r = requests.get("http://localhost:11434/api/tags", timeout=2)
            if r.status_code == 200:
                models = r.json().get("models", [])
                if models:
                    self._model_name = models[0]["name"]
                    self.backend = "ollama"
                    logger.info(f"LLMProvider: using Ollama ({self._model_name})")
                    return
        except Exception:
            pass

        logger.info("LLMProvider: no LLM backend found — using offline mode (context-only)")

    # ---- dynamic API key configuration ----

    def _configure_gemini(self, api_key: str):
        """Configure Google Gemini backend with the given API key."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self._client = genai.GenerativeModel("gemini-3-flash-preview")
            self.backend = "gemini"
            self._model_name = "gemini-3-flash-preview"
            logger.info(f"LLMProvider: using Google Gemini ({self._model_name})")
        except Exception as exc:
            logger.warning(f"Gemini init failed: {exc}")

    def set_api_key(self, provider: str, api_key: str) -> bool:
        """
        Dynamically set an API key and reconfigure the backend.

        Args:
            provider: 'gemini' or 'openai'
            api_key: The API key string

        Returns:
            True if backend was configured successfully.
        """
        if not api_key or not api_key.strip():
            return False
        api_key = api_key.strip()

        if provider == "gemini":
            os.environ["GOOGLE_API_KEY"] = api_key
            self._configure_gemini(api_key)
            return self.backend == "gemini"
        elif provider == "openai":
            os.environ["OPENAI_API_KEY"] = api_key
            try:
                import openai
                self._client = openai.OpenAI(api_key=api_key)
                self.backend = "openai"
                self._model_name = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
                logger.info(f"LLMProvider: using OpenAI ({self._model_name})")
                return True
            except Exception as exc:
                logger.warning(f"OpenAI init failed: {exc}")
                return False
        return False

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate a response from the LLM."""

        if self.backend == "openai":
            return self._call_openai(system_prompt, user_prompt)
        elif self.backend == "gemini":
            return self._call_gemini(system_prompt, user_prompt)
        elif self.backend == "ollama":
            return self._call_ollama(system_prompt, user_prompt)
        else:
            return self._offline_response(user_prompt)

    # --- backends ---
    def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        try:
            resp = self._client.chat.completions.create(
                model=self._model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.3,
                max_tokens=1024,
            )
            return resp.choices[0].message.content.strip()
        except Exception as exc:
            logger.error(f"OpenAI call failed: {exc}")
            return f"⚠️ OpenAI error: {exc}"

    def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        try:
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            resp = self._client.generate_content(
                full_prompt,
                generation_config={
                    "temperature": 0.3,
                    "max_output_tokens": 1024,
                },
            )
            return resp.text.strip()
        except Exception as exc:
            logger.error(f"Gemini call failed: {exc}")
            return f"⚠️ Gemini error: {exc}"

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        try:
            import requests
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self._model_name,
                    "prompt": user_prompt,
                    "system": system_prompt,
                    "stream": False,
                },
                timeout=120,
            )
            return resp.json().get("response", "").strip()
        except Exception as exc:
            logger.error(f"Ollama call failed: {exc}")
            return f"⚠️ Ollama error: {exc}"

    def _offline_response(self, user_prompt: str) -> str:
        return (
            "🔒 **Offline Mode** — No LLM backend configured.\n\n"
            "The retrieved context is shown above. To enable AI-generated "
            "answers, set one of:\n"
            "• `OPENAI_API_KEY` environment variable (OpenAI)\n"
            "• `GOOGLE_API_KEY` environment variable (Google Gemini)\n"
            "• Run Ollama locally (`ollama serve`)\n"
        )


# ---------------------------------------------------------------------------
# Document Chunker / Indexer
# ---------------------------------------------------------------------------

def _chunk_text(text: str, chunk_size: int = 512, overlap: int = 64) -> List[str]:
    """Split text into overlapping chunks."""
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i : i + chunk_size])
        if chunk.strip():
            chunks.append(chunk)
        i += chunk_size - overlap
    return chunks or [text[:2000]]


# ---------------------------------------------------------------------------
# RAG Engine (main class)
# ---------------------------------------------------------------------------

class ForensicRAGEngine:
    """
    Retrieval-Augmented Generation engine for forensic case data.

    Usage:
        engine = ForensicRAGEngine()
        engine.index_case(case_path, case_metadata)
        answer = engine.ask("What suspicious files were found?")
    """

    SYSTEM_PROMPT = (
        "You are FEPD Forensic Assistant, an expert digital forensics AI. "
        "You help investigators analyse evidence by answering questions about "
        "the current case. Base your answers ONLY on the provided context "
        "from the case data. If the context does not contain enough "
        "information, say so clearly. Always cite the source file or "
        "artifact when possible. Be precise, factual, and professional."
    )

    def __init__(self):
        self.store = MiniVectorStore()
        self.embedder = EmbeddingProvider()
        self.llm = LLMProvider()
        self.case_id: Optional[str] = None
        self._indexed = False
        self._index_lock = threading.Lock()
        self._chat_history: List[Dict[str, str]] = []
        logger.info("ForensicRAGEngine initialized")

    # ------------------------------------------------------------------
    #  Indexing
    # ------------------------------------------------------------------

    def index_case(self, case_path: Path, case_metadata: Optional[Dict] = None,
                   progress_callback=None) -> int:
        """
        Walk the case directory, read supported files, chunk them, embed,
        and store in the vector store.

        Args:
            case_path: Path to the case directory
            case_metadata: Optional case metadata dict to index
            progress_callback: Optional callable(int, str) for progress updates

        Returns:
            Number of chunks indexed
        """
        with self._index_lock:
            self.store.clear()
            self._chat_history.clear()
            self.case_id = case_metadata.get("case_id") if case_metadata else case_path.name
            total_chunks = 0

            if progress_callback:
                progress_callback(0, "Starting case indexing…")

            # 1. Index case metadata
            if case_metadata:
                meta_text = self._metadata_to_text(case_metadata)
                chunks = _chunk_text(meta_text)
                embs = self.embedder.embed(chunks)
                metas = [{"source": "case_metadata", "type": "metadata"}] * len(chunks)
                self.store.add(chunks, embs, metas)
                total_chunks += len(chunks)

            # 2. Collect files to index
            supported_ext = {
                ".txt", ".log", ".csv", ".json", ".xml", ".html",
                ".md", ".yaml", ".yml", ".ini", ".cfg", ".conf",
                ".py", ".ps1", ".bat", ".sh", ".reg", ".evtx",
            }

            files_to_index: List[Path] = []
            if case_path.exists():
                for f in case_path.rglob("*"):
                    if f.is_file() and f.suffix.lower() in supported_ext:
                        # skip very large files (>2 MB)
                        try:
                            if f.stat().st_size <= 2 * 1024 * 1024:
                                files_to_index.append(f)
                        except OSError:
                            pass

            total_files = len(files_to_index)
            logger.info(f"RAG: found {total_files} indexable files in {case_path}")

            # 3. Index each file
            for idx, fpath in enumerate(files_to_index):
                if progress_callback:
                    pct = int((idx + 1) / max(total_files, 1) * 100)
                    progress_callback(pct, f"Indexing {fpath.name} ({idx+1}/{total_files})")

                try:
                    text = self._read_file(fpath)
                    if not text or len(text.strip()) < 20:
                        continue
                    chunks = _chunk_text(text)
                    embs = self.embedder.embed(chunks)
                    rel_path = str(fpath.relative_to(case_path))
                    metas = [{"source": rel_path, "type": fpath.suffix}] * len(chunks)
                    self.store.add(chunks, embs, metas)
                    total_chunks += len(chunks)
                except Exception as exc:
                    logger.debug(f"RAG: skipping {fpath}: {exc}")

            self._indexed = True
            logger.info(f"RAG: indexed {total_chunks} chunks from {total_files} files")
            if progress_callback:
                progress_callback(100, f"Indexing complete — {total_chunks} chunks from {total_files} files")
            return total_chunks

    # ------------------------------------------------------------------
    #  Query / Chat
    # ------------------------------------------------------------------

    def ask(self, question: str, top_k: int = 6) -> Dict[str, Any]:
        """
        Ask a question about the current case.

        Returns:
            {
                "answer": str,
                "context": [{"text": ..., "source": ..., "score": ...}, ...],
                "backend": str,            # openai | gemini | ollama | offline
                "indexed": bool,
            }
        """
        if not self._indexed or self.store.size == 0:
            return {
                "answer": (
                    "⚠️ No case data has been indexed yet. Please load a case "
                    "first — the chatbot will automatically index the case data."
                ),
                "context": [],
                "backend": self.llm.backend,
                "indexed": False,
            }

        # 1. Retrieve relevant context
        q_emb = self.embedder.embed_one(question)
        results = self.store.query(q_emb, top_k=top_k)

        # Build context block — trim each chunk to avoid bloated prompts
        ctx_parts = []
        for i, r in enumerate(results, 1):
            src = r["metadata"].get("source", "unknown")
            text_snippet = r['text'][:600]  # cap each chunk
            ctx_parts.append(f"[{i}] Source: {src}\n{text_snippet}")
        context_block = "\n---\n".join(ctx_parts)

        # 2. Build prompt with chat history (last 3 turns, trimmed)
        history_text = ""
        if self._chat_history:
            recent = self._chat_history[-3:]
            history_lines = []
            for turn in recent:
                history_lines.append(f"User: {turn['user'][:200]}")
                history_lines.append(f"Assistant: {turn['assistant'][:200]}")
            history_text = "\n".join(history_lines) + "\n\n"

        user_prompt = (
            f"### Context\n{context_block}\n\n"
            f"### History\n{history_text}"
            f"### Question\n{question}"
        )

        # 3. Generate answer
        answer = self.llm.generate(self.SYSTEM_PROMPT, user_prompt)

        # 4. Save to chat history
        self._chat_history.append({"user": question, "assistant": answer})

        return {
            "answer": answer,
            "context": results,
            "backend": self.llm.backend,
            "indexed": True,
        }

    # ------------------------------------------------------------------
    #  Helpers
    # ------------------------------------------------------------------

    @property
    def is_indexed(self) -> bool:
        return self._indexed

    @property
    def chunk_count(self) -> int:
        return self.store.size

    @property
    def chat_history(self) -> List[Dict[str, str]]:
        return list(self._chat_history)

    def clear_history(self):
        self._chat_history.clear()

    def set_api_key(self, provider: str, api_key: str) -> bool:
        """Set API key on the LLM provider and return success."""
        return self.llm.set_api_key(provider, api_key)

    @staticmethod
    def _metadata_to_text(meta: Dict) -> str:
        lines = ["=== Case Metadata ==="]
        for k, v in meta.items():
            lines.append(f"{k}: {v}")
        return "\n".join(lines)

    @staticmethod
    def _read_file(fpath: Path) -> str:
        """Read a text file, with encoding fallback."""
        for enc in ("utf-8", "utf-16", "latin-1"):
            try:
                return fpath.read_text(encoding=enc, errors="replace")
            except Exception:
                continue
        return ""

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics."""
        return {
            "case_id": self.case_id,
            "indexed": self._indexed,
            "total_chunks": self.store.size,
            "llm_backend": self.llm.backend,
            "llm_model": self.llm._model_name,
            "embedding_backend": self.embedder._backend,
            "chat_turns": len(self._chat_history),
        }

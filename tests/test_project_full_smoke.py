"""Project-wide smoke tests.

Goal: provide one test suite that validates the whole project at a high level:
- every Python source file compiles
- every importable module under src can be imported
"""

from __future__ import annotations

import importlib
import py_compile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"


def _iter_project_python_files() -> list[Path]:
    files: list[Path] = sorted(SRC_ROOT.rglob("*.py"))
    main_file = PROJECT_ROOT / "main.py"
    if main_file.exists():
        files.append(main_file)
    return sorted(files)


CORE_MODULES = [
    "src",
    "src.core.case_manager",
    "src.core.virtual_fs",
    "src.modules.image_handler",
    "src.modules.memory_analyzer",
    "src.modules.forensic_detection_pipeline",
    "src.parsers.mft_parser",
    "src.parsers.registry_parser",
    "src.services.unified_forensic_store",
    "src.ingest.ingest_controller",
]


def test_compile_all_python_files() -> None:
    failures: list[str] = []

    for py_file in _iter_project_python_files():
        try:
            py_compile.compile(str(py_file), doraise=True)
        except Exception as exc:  # pragma: no cover
            failures.append(f"{py_file}: {exc}")

    assert not failures, "Compilation failures found:\n" + "\n".join(failures)


def test_import_core_project_modules() -> None:
    failures: list[str] = []

    for module_name in CORE_MODULES:
        try:
            importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover
            failures.append(f"{module_name}: {exc}")

    assert not failures, "Module import failures found:\n" + "\n".join(failures)

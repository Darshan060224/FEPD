"""
FEPD Terminal Commands
=======================
Individual command modules (ls, cd, cat, hash, etc.).
Each module implements a single command.
"""

from .ls import handle_ls
from .cd import handle_cd
from .pwd import handle_pwd
from .cat import handle_cat
from .tree import handle_tree
from .hash import handle_hash
from .hexdump import handle_hexdump
from .strings import handle_strings
from .find import handle_find
from .grep import handle_grep
from .timeline import handle_timeline
from .score import handle_score
from .explain import handle_explain
from .artifacts import handle_artifacts
from .connections import handle_connections

__all__ = [
    "handle_ls",
    "handle_cd",
    "handle_pwd",
    "handle_cat",
    "handle_tree",
    "handle_hash",
    "handle_hexdump",
    "handle_strings",
    "handle_find",
    "handle_grep",
    "handle_timeline",
    "handle_score",
    "handle_explain",
    "handle_artifacts",
    "handle_connections",
]

import os
import sqlite3
import hashlib
from typing import Dict, Optional


class EvidenceIndexer:
    """Build a unified artifact index (read-only for evidence)"""

    def __init__(self, case_db_path: str):
        self.db = case_db_path
        if not os.path.exists(self.db):
            raise FileNotFoundError("Index DB not found; create case first")

    def add_file_record(self, path: str, origin: str = None, owner: str = None):
        # path should be a readable file path (we don't modify evidence)
        size = None
        created = None
        modified = None
        h = None
        if os.path.exists(path):
            stat = os.stat(path)
            size = stat.st_size
            created = str(stat.st_ctime)
            modified = str(stat.st_mtime)
            # compute sha256 deterministically (read-only)
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                while True:
                    b = f.read(8192)
                    if not b:
                        break
                    h.update(b)
            h = h.hexdigest()
        conn = sqlite3.connect(self.db)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO files (path, origin, owner, size, created, modified, hash) VALUES (?,?,?,?,?,?,?)",
            (path, origin or '', owner or '', size, created, modified, h),
        )
        conn.commit()
        conn.close()

    def list_files(self, prefix: Optional[str] = None):
        conn = sqlite3.connect(self.db)
        cur = conn.cursor()
        if prefix:
            cur.execute("SELECT path,owner,ml_score FROM files WHERE path LIKE ?", (prefix + '%',))
        else:
            cur.execute("SELECT path,owner,ml_score FROM files")
        rows = cur.fetchall()
        conn.close()
        return rows

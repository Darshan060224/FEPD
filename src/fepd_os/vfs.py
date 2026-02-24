import os
from typing import Dict, List


class VNode:
    def __init__(self, name: str, is_dir: bool = True, meta: dict = None):
        self.name = name
        self.is_dir = is_dir
        self.children: Dict[str, VNode] = {}
        self.meta = meta or {}


class VirtualFilesystem:
    """Expose an evidence-mapped tree backed by the index DB."""

    def __init__(self, db_path: str):
        import sqlite3

        self.db_path = db_path
        self.root = VNode('/', True)
        self._build_tree()

    def _build_tree(self):
        import sqlite3

        if not os.path.exists(self.db_path):
            return
        
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            
            # Check if files table exists
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
            if not cur.fetchone():
                conn.close()
                return  # No files table yet
            
            cur.execute("SELECT path, owner, size, hash, ml_score FROM files")
            for row in cur.fetchall():
                path, owner, size, h, score = row
                if not path:
                    continue
                parts = [p for p in path.replace('\\', '/').split('/') if p]
                node = self.root
                for i, part in enumerate(parts):
                    if part not in node.children:
                        is_dir = i != len(parts) - 1
                        node.children[part] = VNode(part, is_dir=is_dir)
                    node = node.children[part]
                node.is_dir = False
                node.meta.update({'path': path, 'owner': owner, 'size': size, 'hash': h, 'ml_score': score})
            conn.close()
        except sqlite3.OperationalError:
            # Database exists but tables not yet created
            pass

    def _walk(self, node: VNode, prefix: str = '') -> List[str]:
        results = []
        for name, child in sorted(node.children.items()):
            p = os.path.join(prefix, name)
            results.append(p)
            if child.is_dir:
                results += self._walk(child, p)
        return results

    def list_dir(self, path: str):
        node = self._node_at(path)
        if not node or not node.is_dir:
            raise FileNotFoundError(path)
        return list(node.children.keys())

    def stat(self, path: str):
        node = self._node_at(path)
        if not node:
            raise FileNotFoundError(path)
        return node.meta

    def _node_at(self, path: str) -> VNode:
        if not path or path in ['/', '.']:
            return self.root
        parts = [p for p in path.replace('\\', '/').split('/') if p]
        node = self.root
        for part in parts:
            if part not in node.children:
                return None
            node = node.children[part]
        return node

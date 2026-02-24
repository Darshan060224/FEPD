import sqlite3
from pathlib import Path

# Check VFS
conn = sqlite3.connect('data/workspace/vfs.db')
cur = conn.cursor()

# Count
cur.execute('SELECT COUNT(*) FROM virtual_fs')
print(f'Total VFS nodes: {cur.fetchone()[0]}')

# Root nodes
cur.execute("SELECT path, name, node_type, parent_path FROM virtual_fs WHERE parent_path = '/' OR parent_path = '' OR parent_path IS NULL ORDER BY name LIMIT 15")
print('\nRoot nodes (parent_path = "/" or "" or NULL):')
for row in cur.fetchall():
    print(f'  {row}')

# All unique parent_paths
cur.execute("SELECT DISTINCT parent_path FROM virtual_fs ORDER BY parent_path LIMIT 20")
print('\nUnique parent_paths:')
for row in cur.fetchall():
    print(f'  "{row[0]}"')

conn.close()

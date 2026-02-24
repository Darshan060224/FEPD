import sqlite3
import hashlib
import datetime


class AuditLogger:
    def __init__(self, case_db_path: str):
        self.db = case_db_path
        self._ensure_table()
    
    def _ensure_table(self):
        """Ensure audit_logs table exists."""
        try:
            conn = sqlite3.connect(self.db)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY, 
                    ts TEXT, 
                    case_name TEXT, 
                    user_context TEXT, 
                    command TEXT, 
                    args TEXT, 
                    result_hash TEXT
                )
            """)
            conn.commit()
            conn.close()
        except sqlite3.Error:
            pass  # Database might not be writable

    def log(self, case_name: str, user_context: str, command: str, args: str, result_text: str):
        try:
            conn = sqlite3.connect(self.db)
            cur = conn.cursor()
            ts = datetime.datetime.utcnow().isoformat() + 'Z'
            result_hash = hashlib.sha256(result_text.encode('utf-8')).hexdigest() if result_text else ''
            cur.execute("INSERT INTO audit_logs (ts, case_name, user_context, command, args, result_hash) VALUES (?,?,?,?,?,?)",
                        (ts, case_name, user_context or '', command, args or '', result_hash))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            # Table doesn't exist or database issue, fail silently
            pass

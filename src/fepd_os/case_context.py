import os
import json
import sqlite3
from typing import Optional, Dict, List, Any
from datetime import datetime


class CaseContextManager:
    """
    Manage case contexts and bind shell to a case (read-only).
    
    Constitutional Architecture:
    - Single source of truth: cases/index.json
    - UI and Terminal share the same case registry
    - Cases are stored in cases/<case_id>/
    - Optional DB indexes in data/indexes/ for file indexing
    """

    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        self.cases_root = os.path.join(workspace_root, "cases")
        self.index_root = os.path.join(workspace_root, "data", "indexes")
        self.registry_path = os.path.join(self.cases_root, "index.json")
        
        # Ensure directories exist
        os.makedirs(self.cases_root, exist_ok=True)
        os.makedirs(self.index_root, exist_ok=True)
        
        self.current_case: Optional[str] = None
        self.current_case_path: Optional[str] = None
        self.active_user: Optional[str] = None
        
        # Sync the registry on startup
        self._sync_registry()

    def _load_registry(self) -> Dict[str, Any]:
        """Load the shared case registry."""
        if os.path.exists(self.registry_path):
            try:
                with open(self.registry_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"version": "1.0", "cases": {}}

    def _save_registry(self, registry: Dict[str, Any]) -> None:
        """Save the shared case registry."""
        registry["last_updated"] = datetime.now().isoformat()
        with open(self.registry_path, 'w', encoding='utf-8') as f:
            json.dump(registry, f, indent=2)

    def _sync_registry(self) -> None:
        """
        Sync the case registry with actual case folders.
        Discovers cases created by UI (case.json) and adds them to registry.
        """
        registry = self._load_registry()
        modified = False
        
        # Scan cases/ folder for case.json files (UI-created cases)
        if os.path.exists(self.cases_root):
            for item in os.listdir(self.cases_root):
                case_dir = os.path.join(self.cases_root, item)
                case_json = os.path.join(case_dir, "case.json")
                
                if os.path.isdir(case_dir) and os.path.exists(case_json):
                    case_id = item
                    if case_id not in registry.get("cases", {}):
                        # Load case metadata
                        try:
                            with open(case_json, 'r', encoding='utf-8') as f:
                                metadata = json.load(f)
                            
                            registry.setdefault("cases", {})[case_id] = {
                                "name": metadata.get("case_name", case_id),
                                "created": metadata.get("created_date", datetime.now().isoformat()),
                                "path": case_dir,
                                "investigator": metadata.get("investigator", "unknown"),
                                "status": metadata.get("status", "open")
                            }
                            modified = True
                        except (json.JSONDecodeError, IOError):
                            pass
        
        # Also check for legacy .db files in data/indexes/
        if os.path.exists(self.index_root):
            for f in os.listdir(self.index_root):
                if f.endswith('.db'):
                    case_id = f[:-3]
                    if case_id not in registry.get("cases", {}):
                        registry.setdefault("cases", {})[case_id] = {
                            "name": case_id,
                            "created": datetime.now().isoformat(),
                            "path": os.path.join(self.cases_root, case_id),
                            "db_path": os.path.join(self.index_root, f),
                            "status": "open"
                        }
                        modified = True
        
        if modified:
            self._save_registry(registry)

    def case_db_path(self, case_name: str) -> str:
        """Get the database path for a case's file index."""
        return os.path.join(self.index_root, f"{case_name}.db")
    
    def case_dir(self, case_name: str) -> str:
        """Return the case directory path for evidence storage."""
        case_path = os.path.join(self.cases_root, case_name)
        os.makedirs(case_path, exist_ok=True)
        return case_path
    
    def get_case_path(self, case_name: str) -> str:
        """Get absolute path to case directory - for chain of custody."""
        return self.case_dir(case_name)

    def list_cases(self) -> List[str]:
        """
        List all available cases from the shared registry.
        Returns case IDs that both UI and terminal can access.
        """
        # Sync first to catch any new cases
        self._sync_registry()
        
        registry = self._load_registry()
        cases = list(registry.get("cases", {}).keys())
        
        # Sort by creation date if available
        def get_created(case_id):
            case_info = registry.get("cases", {}).get(case_id, {})
            return case_info.get("created", "")
        
        cases.sort(key=get_created, reverse=True)
        return cases

    def get_case_info(self, case_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a case."""
        registry = self._load_registry()
        return registry.get("cases", {}).get(case_name)

    def create_case(self, case_name: str) -> str:
        """
        Create a new case with proper directory structure and registry entry.
        """
        # Create case directory
        case_dir = self.case_dir(case_name)
        
        # Create case.json if it doesn't exist
        case_json_path = os.path.join(case_dir, "case.json")
        if not os.path.exists(case_json_path):
            metadata = {
                "case_id": case_name,
                "case_name": case_name,
                "investigator": "system",
                "created_date": datetime.now().isoformat(),
                "status": "open",
                "version": "1.0"
            }
            with open(case_json_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
        
        # Create database for file indexing
        db_path = self.case_db_path(case_name)
        if not os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.executescript("""
            CREATE TABLE files (
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE,
                origin TEXT,
                owner TEXT,
                size INTEGER,
                created TEXT,
                modified TEXT,
                hash TEXT,
                ml_score REAL,
                ml_explain TEXT
            );
            CREATE TABLE users (name TEXT PRIMARY KEY);
            CREATE TABLE events (id INTEGER PRIMARY KEY, ts TEXT, type TEXT, details TEXT);
            CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, ts TEXT, case_name TEXT, user_context TEXT, command TEXT, args TEXT, result_hash TEXT);
            """)
            conn.commit()
            conn.close()
        
        # Update registry
        registry = self._load_registry()
        registry.setdefault("cases", {})[case_name] = {
            "name": case_name,
            "created": datetime.now().isoformat(),
            "path": case_dir,
            "db_path": db_path,
            "status": "open"
        }
        self._save_registry(registry)
        
        return db_path

    def use_case(self, case_name: str) -> Dict[str, Any]:
        """
        Select a case as the active context.
        
        Returns:
            Case info dict with path, users, etc.
            
        Raises:
            FileNotFoundError: If case doesn't exist
        """
        # Sync registry first
        self._sync_registry()
        
        registry = self._load_registry()
        case_info = registry.get("cases", {}).get(case_name)
        
        if not case_info:
            # Build helpful error message
            available = list(registry.get("cases", {}).keys())
            hint = f"\n[HINT] Available cases: {', '.join(available)}" if available else "\n[HINT] No cases found. Create one first."
            raise FileNotFoundError(f"Case not found: {case_name}{hint}")
        
        # Verify case directory exists - create if database exists
        case_path = case_info.get("path", os.path.join(self.cases_root, case_name))
        
        # Normalize path
        if case_path.startswith('.\\') or case_path.startswith('./'):
            case_path = os.path.join(self.workspace_root, case_path[2:])
        
        if not os.path.exists(case_path):
            # Try standard location
            alt_path = os.path.join(self.cases_root, case_name)
            if os.path.exists(alt_path):
                case_path = alt_path
            else:
                # If we have a database but no directory, create the directory
                db_path = self.case_db_path(case_name)
                if os.path.exists(db_path):
                    os.makedirs(alt_path, exist_ok=True)
                    case_path = alt_path
                else:
                    raise FileNotFoundError(f"Case directory not found: {case_path}")
        
        self.current_case = case_name
        self.current_case_path = case_path
        
        # Clear user context - Evidence OS will set it based on detection
        self.active_user = None
        
        return case_info
    
    def _detect_default_user(self, case_name: str) -> str:
        """
        Detect the default user from evidence artifacts.
        
        Looks for:
        - Windows: C:\\Users\\ folders
        - Linux: /home/ folders
        - macOS: /Users/ folders
        """
        # Check the database for user information
        db_path = self.case_db_path(case_name)
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                
                # Look for Windows user paths
                cur.execute("""
                    SELECT DISTINCT owner FROM files 
                    WHERE owner != '' AND owner IS NOT NULL
                    LIMIT 1
                """)
                result = cur.fetchone()
                if result and result[0]:
                    conn.close()
                    return result[0]
                
                # Look for paths that indicate users
                cur.execute("""
                    SELECT path FROM files 
                    WHERE path LIKE '%/Users/%' OR path LIKE '%\\Users\\%'
                    LIMIT 10
                """)
                paths = [row[0] for row in cur.fetchall()]
                conn.close()
                
                for path in paths:
                    # Extract username from path
                    import re
                    match = re.search(r'[/\\]Users[/\\]([^/\\]+)', path, re.IGNORECASE)
                    if match:
                        user = match.group(1)
                        if user.lower() not in ('public', 'default', 'all users'):
                            return user
            except:
                pass
        
        # Default to 'root' as the forensic examiner perspective
        return "root"

    def use_user(self, user_name: str):
        if not self.current_case:
            raise RuntimeError("No case selected")
        # just set active user; presence in DB optional
        self.active_user = user_name

    def exit_user(self):
        """Exit user context, return to root (administrator)."""
        # Clear user context - returns to root (administrator mode)
        self.active_user = None

    def get_db(self) -> sqlite3.Connection:
        if not self.current_case:
            raise RuntimeError("No case selected")
        return sqlite3.connect(self.case_db_path(self.current_case))

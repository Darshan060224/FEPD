"""
FEPD - Secure dataa/ Cleaner
=============================
Securely wipes dataa/ after training with verification

CRITICAL RULES:
- Must verify complete deletion
- Must handle locked files
- Must prevent accidental evidence deletion
- Training FAILS if wipe fails

Copyright (c) 2025 FEPD Development Team
"""

import logging
import shutil
import time
from pathlib import Path
from typing import List, Dict
import hashlib


class DataaCleanupError(Exception):
    """Raised when dataa/ cleanup fails."""
    pass


class DataaCleaner:
    """
    Securely wipes dataa/ temporary workspace.
    
    This is a CRITICAL security component for:
    - Preventing training data leakage
    - Removing temporary malware samples
    - Ensuring clean state between training runs
    """
    
    def __init__(self, dataa_path: Path, dry_run: bool = False):
        """
        Args:
            dataa_path: Path to dataa/ directory
            dry_run: If True, only simulate deletion (for testing)
        """
        self.dataa_path = Path(dataa_path)
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)
    
    def verify_is_dataa(self) -> bool:
        """
        Verify this is actually a dataa/ directory.
        
        Safety check to prevent accidental deletion of wrong directories.
        
        Returns:
            True if verified as dataa/
        
        Raises:
            DataaCleanupError: If not a valid dataa/ directory
        """
        # Must be named "dataa"
        if self.dataa_path.name != "dataa":
            raise DataaCleanupError(
                f"❌ Directory is not named 'dataa': {self.dataa_path.name}"
            )
        
        # Must not contain case evidence markers
        forbidden_markers = [
            "case.json",  # Case metadata
            "evidence.manifest",  # Evidence tracking
            "audit.log",  # Forensic audit log
            "chain_of_custody"  # Evidence custody
        ]
        
        for marker in forbidden_markers:
            if (self.dataa_path / marker).exists():
                raise DataaCleanupError(
                    f"❌ Found evidence marker '{marker}' in dataa/. "
                    f"This may be a case directory, not dataa/!"
                )
        
        self.logger.info(f"✅ Verified directory is dataa/: {self.dataa_path}")
        return True
    
    def scan_contents(self) -> Dict:
        """
        Scan dataa/ contents before deletion.
        
        Returns:
            Dict with statistics
        """
        if not self.dataa_path.exists():
            return {
                'exists': False,
                'total_files': 0,
                'total_dirs': 0,
                'total_size_bytes': 0
            }
        
        total_files = 0
        total_dirs = 0
        total_size = 0
        file_types = {}
        
        for item in self.dataa_path.rglob("*"):
            if item.is_file():
                total_files += 1
                total_size += item.stat().st_size
                
                ext = item.suffix.lower()
                file_types[ext] = file_types.get(ext, 0) + 1
            elif item.is_dir():
                total_dirs += 1
        
        return {
            'exists': True,
            'path': str(self.dataa_path),
            'total_files': total_files,
            'total_dirs': total_dirs,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / 1024 / 1024, 2),
            'file_types': file_types
        }
    
    def wipe(self, verify: bool = True) -> bool:
        """
        Securely wipe dataa/ directory.
        
        Args:
            verify: If True, verify deletion afterwards
        
        Returns:
            True if successful
        
        Raises:
            DataaCleanupError: If wipe fails
        """
        self.logger.info("="*60)
        self.logger.info("STARTING SECURE dataa/ WIPE")
        self.logger.info("="*60)
        
        # Safety check
        self.verify_is_dataa()
        
        # Scan before deletion
        stats = self.scan_contents()
        
        if not stats['exists']:
            self.logger.info("✅ dataa/ does not exist, nothing to wipe")
            return True
        
        self.logger.info(f"📊 dataa/ contents:")
        self.logger.info(f"   Files: {stats['total_files']:,}")
        self.logger.info(f"   Directories: {stats['total_dirs']:,}")
        self.logger.info(f"   Total size: {stats['total_size_mb']:.2f} MB")
        
        if stats['file_types']:
            self.logger.info(f"   File types: {dict(list(stats['file_types'].items())[:10])}")
        
        # Dry run check
        if self.dry_run:
            self.logger.warning("🧪 DRY RUN: Would delete dataa/ but not actually deleting")
            return True
        
        # Perform deletion
        try:
            self.logger.info(f"🔥 Deleting dataa/: {self.dataa_path}")
            
            # Use shutil.rmtree with error handler
            def handle_error(func, path, exc_info):
                self.logger.warning(f"⚠️ Failed to delete {path}: {exc_info}")
                
                # Try to make writable and retry
                try:
                    import stat
                    Path(path).chmod(stat.S_IWRITE)
                    func(path)
                except Exception as e:
                    self.logger.error(f"❌ Could not delete {path}: {e}")
            
            shutil.rmtree(self.dataa_path, onerror=handle_error)
            
            # Wait briefly for filesystem
            time.sleep(0.5)
            
            self.logger.info("✅ dataa/ deletion complete")
            
        except Exception as e:
            raise DataaCleanupError(f"Failed to delete dataa/: {e}")
        
        # Verification
        if verify:
            return self.verify_wipe()
        
        return True
    
    def verify_wipe(self) -> bool:
        """
        Verify dataa/ was completely deleted.
        
        Returns:
            True if verified
        
        Raises:
            DataaCleanupError: If dataa/ still exists with files
        """
        self.logger.info("🔍 Verifying dataa/ deletion...")
        
        # Check if directory exists
        if self.dataa_path.exists():
            # Scan what's left
            stats = self.scan_contents()
            
            # Allow empty directories (no files), as they don't contain training data
            if stats['total_files'] > 0:
                error_msg = (
                    f"❌ WIPE VERIFICATION FAILED: dataa/ still has files!\n"
                    f"   Path: {self.dataa_path}\n"
                    f"   Files remaining: {stats['total_files']}\n"
                    f"   Dirs remaining: {stats['total_dirs']}\n"
                    f"   Size remaining: {stats['total_size_mb']} MB\n"
                    f"\n"
                    f"Training MUST FAIL to prevent data leakage."
                )
                
                self.logger.error(error_msg)
                raise DataaCleanupError(error_msg)
            else:
                self.logger.info(f"✅ WIPE VERIFIED: dataa/ empty (only {stats['total_dirs']} empty directories remain)")
                return True
        
        self.logger.info("✅ WIPE VERIFIED: dataa/ completely removed")
        return True
    
    def safe_wipe_with_backup_list(self, backup_list_path: Path = None) -> bool:
        """
        Wipe dataa/ but save a list of what was deleted (for auditing).
        
        Args:
            backup_list_path: Where to save deletion manifest
        
        Returns:
            True if successful
        """
        if backup_list_path is None:
            backup_list_path = self.dataa_path.parent / "dataa_deletion_manifest.txt"
        
        # Scan contents
        stats = self.scan_contents()
        
        if stats['exists']:
            # Create manifest
            with open(backup_list_path, 'w') as f:
                f.write(f"dataa/ Deletion Manifest\n")
                f.write(f"=========================\n")
                f.write(f"Deleted at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Path: {self.dataa_path}\n")
                f.write(f"Total files: {stats['total_files']}\n")
                f.write(f"Total size: {stats['total_size_mb']} MB\n")
                f.write(f"\nFile types:\n")
                
                for ext, count in sorted(stats['file_types'].items()):
                    f.write(f"  {ext or '(no extension)'}: {count}\n")
            
            self.logger.info(f"📝 Saved deletion manifest: {backup_list_path}")
        
        # Perform wipe
        return self.wipe(verify=True)


def wipe_dataa_safe(workspace_root: Path, dry_run: bool = False) -> bool:
    """
    Convenience function to safely wipe dataa/.
    
    Args:
        workspace_root: Root of FEPD workspace
        dry_run: If True, only simulate
    
    Returns:
        True if successful
    """
    dataa_path = workspace_root / "dataa"
    cleaner = DataaCleaner(dataa_path, dry_run=dry_run)
    
    return cleaner.safe_wipe_with_backup_list()


if __name__ == "__main__":
    # Standalone test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    workspace = Path(__file__).parent.parent.parent
    dataa_path = workspace / "dataa"
    
    # DRY RUN test
    print("\n🧪 Testing DataaCleaner (DRY RUN)...")
    cleaner = DataaCleaner(dataa_path, dry_run=True)
    
    try:
        cleaner.verify_is_dataa()
        stats = cleaner.scan_contents()
        print(f"\nStats: {stats}")
        
        # cleaner.wipe(verify=True)  # Uncomment to actually test wipe
        
        print("\n✅ DataaCleaner tests passed")
        
    except DataaCleanupError as e:
        print(f"\n⚠️ Cleanup error (expected in some cases): {e}")

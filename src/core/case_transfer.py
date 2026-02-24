"""
Sealed Case Transfer System

Export and import cases as tamper-evident .fepdpack bundles.
Verifies hash integrity and chain of custody on import.
"""

import json
import hashlib
import zipfile
import os
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timezone

from .chain_of_custody import ChainLogger, CoC_Actions, ChainOfCustodyError


class CaseTransferError(Exception):
    """Case transfer operation error"""
    pass


class CaseExporter:
    """Export a case as a sealed .fepdpack bundle"""
    
    def __init__(self, case_path: Union[str, Path]):
        """
        Initialize case exporter.
        
        Args:
            case_path: Absolute path to case directory
        """
        self.case_path = Path(case_path)
        self.case_name = self.case_path.name
        
        if not self.case_path.exists():
            raise CaseTransferError(f"Case not found: {case_path}")
    
    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _build_manifest(self) -> Dict[str, Any]:
        """
        Build manifest of all files and their hashes.
        
        Returns:
            {
                "case_name": str,
                "export_timestamp": str,
                "export_user": str,
                "files": {
                    "relative/path/file.ext": {
                        "size": int,
                        "sha256": str
                    }
                },
                "chain_hash": str
            }
        """
        manifest = {
            "case_name": self.case_name,
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "export_user": os.getenv("USERNAME", "unknown"),
            "files": {},
            "chain_hash": ""
        }
        
        # Hash all files in case directory
        for file_path in self.case_path.rglob('*'):
            if file_path.is_file():
                rel_path = file_path.relative_to(self.case_path)
                
                # Skip manifest.json itself
                if rel_path.name == 'manifest.json':
                    continue
                
                manifest["files"][str(rel_path)] = {
                    "size": file_path.stat().st_size,
                    "sha256": self._compute_file_hash(file_path)
                }
        
        # Hash chain of custody
        chain_logger = ChainLogger(str(self.case_path))
        manifest["chain_hash"] = chain_logger.export_chain_hash()
        
        return manifest
    
    def export(self, target_user: str, output_dir: Optional[Union[str, Path]] = None) -> Path:
        """
        Export case as sealed .fepdpack bundle.
        
        Steps:
        1. Verify chain of custody
        2. Compute hashes of all files
        3. Create manifest.json
        4. Append CASE_EXPORTED to chain
        5. Create .fepdpack archive
        
        Args:
            target_user: Username of intended recipient
            output_dir: Directory to save .fepdpack (default: parent of case dir)
        
        Returns:
            Path to created .fepdpack file
        
        Raises:
            CaseTransferError: If chain is broken or export fails
        """
        # Verify chain integrity
        chain_logger = ChainLogger(str(self.case_path))
        verification = chain_logger.verify_chain()
        
        if not verification["valid"]:
            raise CaseTransferError(
                f"Cannot export case with broken chain: {verification['error']}"
            )
        
        print(f"✓ Chain verified ({verification['total_entries']} entries)")
        
        # Log export action BEFORE hashing so manifest reflects final chain state
        current_user = os.getenv("USERNAME", "unknown")
        chain_logger.append(
            user=current_user,
            action=CoC_Actions.CASE_EXPORTED,
            details=f"Case exported for transfer to {target_user}"
        )
        print("✓ Logged CASE_EXPORTED")

        # Build manifest AFTER logging export so chain hash matches archived log
        print("Computing file hashes...")
        manifest = self._build_manifest()
        print(f"✓ Hashed {len(manifest['files'])} files")

        # Write manifest (this file itself is excluded from hashing)
        manifest_path = self.case_path / "manifest.json"
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)
        
        # Create .fepdpack archive
        output_base = Path(output_dir) if output_dir else self.case_path.parent
        output_file = output_base / f"{self.case_name}.fepdpack"
        
        print(f"Creating archive: {output_file}")
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self.case_path.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(self.case_path.parent)
                    zipf.write(file_path, arcname)
        
        file_size_mb = output_file.stat().st_size / (1024 * 1024)
        print(f"✓ Created {output_file.name} ({file_size_mb:.2f} MB)")
        
        return output_file


class CaseImporter:
    """Import and verify a sealed .fepdpack bundle"""
    
    def __init__(self, bundle_path: Union[str, Path]):
        """
        Initialize case importer.
        
        Args:
            bundle_path: Path to .fepdpack file
        """
        self.bundle_path = Path(bundle_path)
        
        if not self.bundle_path.exists():
            raise CaseTransferError(f"Bundle not found: {bundle_path}")
        
        if not self.bundle_path.suffix == '.fepdpack':
            raise CaseTransferError(f"Invalid bundle format: expected .fepdpack")
    
    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def verify_bundle(self, extract_path: Path) -> Dict[str, Any]:
        """
        Verify integrity of extracted bundle.
        
        Returns:
            {
                "valid": bool,
                "errors": List[str],
                "manifest": Dict or None
            }
        """
        errors = []
        
        # Check manifest exists
        manifest_path = extract_path / "manifest.json"
        if not manifest_path.exists():
            return {
                "valid": False,
                "errors": ["manifest.json not found in bundle"],
                "manifest": None
            }
        
        # Load manifest
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        
        # Verify all files exist and match hashes
        for rel_path, file_info in manifest["files"].items():
            file_path = extract_path / rel_path
            
            if not file_path.exists():
                errors.append(f"Missing file: {rel_path}")
                continue
            
            # Verify size
            actual_size = file_path.stat().st_size
            if actual_size != file_info["size"]:
                errors.append(
                    f"Size mismatch: {rel_path} "
                    f"(expected {file_info['size']}, found {actual_size})"
                )
            
            # Verify hash
            actual_hash = self._compute_file_hash(file_path)
            if actual_hash != file_info["sha256"]:
                errors.append(
                    f"Hash mismatch: {rel_path} "
                    f"(expected {file_info['sha256'][:16]}..., found {actual_hash[:16]}...)"
                )
        
        # Verify chain of custody
        chain_logger = ChainLogger(str(extract_path))
        chain_verification = chain_logger.verify_chain()
        
        if not chain_verification["valid"]:
            errors.append(f"Chain broken: {chain_verification['error']}")
        
        # Verify chain hash
        actual_chain_hash = chain_logger.export_chain_hash()
        if actual_chain_hash != manifest["chain_hash"]:
            errors.append(
                f"Chain hash mismatch: "
                f"expected {manifest['chain_hash'][:16]}..., "
                f"found {actual_chain_hash[:16]}..."
            )
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "manifest": manifest
        }
    
    def import_case(self, cases_dir: Union[str, Path]) -> Path:
        """
        Import and verify .fepdpack bundle.
        
        Steps:
        1. Extract bundle
        2. Verify all file hashes
        3. Verify chain of custody
        4. Append CASE_IMPORTED entry
        5. Move to cases directory
        
        Args:
            cases_dir: Directory where cases are stored
        
        Returns:
            Path to imported case directory
        
        Raises:
            CaseTransferError: If verification fails
        """
        cases_path = Path(cases_dir)
        cases_path.mkdir(parents=True, exist_ok=True)
        
        # Create temp extraction directory
        temp_dir = cases_path / f".temp_import_{self.bundle_path.stem}"
        
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        
        temp_dir.mkdir()
        
        try:
            # Extract bundle
            print(f"Extracting {self.bundle_path.name}...")
            with zipfile.ZipFile(self.bundle_path, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Find case directory (should be only subdirectory)
            case_dirs = [d for d in temp_dir.iterdir() if d.is_dir()]
            if len(case_dirs) != 1:
                raise CaseTransferError(
                    f"Invalid bundle structure: expected 1 case directory, found {len(case_dirs)}"
                )
            
            extracted_case = case_dirs[0]
            case_name = extracted_case.name
            
            print(f"✓ Extracted case: {case_name}")
            
            # Verify bundle
            print("Verifying integrity...")
            verification = self.verify_bundle(extracted_case)
            
            if not verification["valid"]:
                error_msg = "\n".join(verification["errors"])
                raise CaseTransferError(f"Verification failed:\n{error_msg}")
            
            print(f"✓ All hashes verified")
            print(f"✓ Chain intact ({verification['manifest']['case_name']})")
            
            # Append CASE_IMPORTED entry
            current_user = os.getenv("USERNAME", "unknown")
            chain_logger = ChainLogger(str(extracted_case))
            chain_logger.append(
                user=current_user,
                action=CoC_Actions.CASE_IMPORTED,
                details=f"Case imported by {current_user} from {self.bundle_path.name}"
            )
            
            print(f"✓ Logged CASE_IMPORTED")
            
            # Move to cases directory
            final_path = cases_path / case_name
            
            if final_path.exists():
                # Create timestamped name to avoid collision
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                final_path = cases_path / f"{case_name}_{timestamp}"
            
            shutil.move(str(extracted_case), str(final_path))
            shutil.rmtree(temp_dir)
            
            print(f"✓ Case imported to: {final_path}")
            
            return final_path
        
        except Exception as e:
            # Cleanup on failure
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            raise


def export_case(case_path: str, target_user: str, output_dir: Optional[str] = None) -> Path:
    """
    Export a case as a sealed .fepdpack bundle.
    
    Args:
        case_path: Path to case directory
        target_user: Username of intended recipient
        output_dir: Directory to save bundle (default: parent of case)
    
    Returns:
        Path to created .fepdpack file
    """
    exporter = CaseExporter(case_path)
    return exporter.export(target_user, output_dir)


def import_case(bundle_path: str, cases_dir: str) -> Path:
    """
    Import and verify a .fepdpack bundle.
    
    Args:
        bundle_path: Path to .fepdpack file
        cases_dir: Directory where cases are stored
    
    Returns:
        Path to imported case directory
    """
    importer = CaseImporter(bundle_path)
    return importer.import_case(cases_dir)

"""
Forensic Hashing Utility Module
SHA-256 implementation for evidence integrity
"""

import hashlib
from pathlib import Path
from typing import Optional, BinaryIO
import logging


class ForensicHasher:
    """
    Forensic-grade hashing utility.
    
    Uses SHA-256 exclusively for NIST compliance.
    Supports incremental hashing for large files.
    """
    
    # Buffer size for reading large files (8MB)
    BUFFER_SIZE = 8 * 1024 * 1024
    
    def __init__(self):
        """Initialize forensic hasher."""
        self.logger = logging.getLogger(__name__)
        self.algorithm = 'sha256'  # NIST standard
    
    def hash_file(self, file_path: Path, callback: Optional[callable] = None) -> str:
        """
        Compute SHA-256 hash of a file.
        
        Args:
            file_path: Path to file
            callback: Optional progress callback(bytes_processed, total_bytes)
            
        Returns:
            SHA-256 hash (hex string)
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = file_path.stat().st_size
        bytes_processed = 0
        
        hasher = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.BUFFER_SIZE)
                    if not chunk:
                        break
                    
                    hasher.update(chunk)
                    bytes_processed += len(chunk)
                    
                    if callback:
                        callback(bytes_processed, file_size)
            
            hash_value = hasher.hexdigest()
            self.logger.debug(f"Hashed {file_path.name}: {hash_value}")
            return hash_value
            
        except Exception as e:
            self.logger.error(f"Failed to hash file {file_path}: {e}")
            raise
    
    def hash_bytes(self, data: bytes) -> str:
        """
        Compute SHA-256 hash of byte data.
        
        Args:
            data: Byte data
            
        Returns:
            SHA-256 hash (hex string)
        """
        return hashlib.sha256(data).hexdigest()
    
    def hash_string(self, text: str, encoding: str = 'utf-8') -> str:
        """
        Compute SHA-256 hash of string.
        
        Args:
            text: Text string
            encoding: Character encoding
            
        Returns:
            SHA-256 hash (hex string)
        """
        return self.hash_bytes(text.encode(encoding))
    
    def hash_stream(self, stream: BinaryIO, size: Optional[int] = None, 
                    callback: Optional[callable] = None) -> str:
        """
        Compute SHA-256 hash of a stream.
        
        Args:
            stream: Binary stream
            size: Total size (for progress reporting)
            callback: Optional progress callback(bytes_processed, total_bytes)
            
        Returns:
            SHA-256 hash (hex string)
        """
        hasher = hashlib.sha256()
        bytes_processed = 0
        
        while True:
            chunk = stream.read(self.BUFFER_SIZE)
            if not chunk:
                break
            
            hasher.update(chunk)
            bytes_processed += len(chunk)
            
            if callback and size:
                callback(bytes_processed, size)
        
        return hasher.hexdigest()
    
    def verify_hash(self, file_path: Path, expected_hash: str) -> bool:
        """
        Verify file hash matches expected value.
        
        Args:
            file_path: Path to file
            expected_hash: Expected SHA-256 hash
            
        Returns:
            True if hash matches, False otherwise
        """
        try:
            actual_hash = self.hash_file(file_path)
            match = actual_hash.lower() == expected_hash.lower()
            
            if not match:
                self.logger.warning(
                    f"Hash mismatch for {file_path.name}: "
                    f"expected {expected_hash}, got {actual_hash}"
                )
            
            return match
            
        except Exception as e:
            self.logger.error(f"Hash verification failed: {e}")
            return False
    
    def hash_directory(self, dir_path: Path, pattern: str = "*") -> dict:
        """
        Compute hashes of all files in directory.
        
        Args:
            dir_path: Directory path
            pattern: File pattern (glob)
            
        Returns:
            Dictionary mapping file paths to hashes
        """
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")
        
        hashes = {}
        
        for file_path in dir_path.rglob(pattern):
            if file_path.is_file():
                try:
                    hash_value = self.hash_file(file_path)
                    relative_path = file_path.relative_to(dir_path)
                    hashes[str(relative_path)] = hash_value
                except Exception as e:
                    self.logger.error(f"Failed to hash {file_path}: {e}")
        
        return hashes


def format_hash(hash_value: str, format_type: str = 'standard') -> str:
    """
    Format hash value for display.
    
    Args:
        hash_value: SHA-256 hash
        format_type: Format type ('standard', 'grouped', 'truncated')
        
    Returns:
        Formatted hash string
    """
    if format_type == 'grouped':
        # Group in 4-character blocks
        return ' '.join([hash_value[i:i+4] for i in range(0, len(hash_value), 4)])
    elif format_type == 'truncated':
        # Show first 16 and last 8 characters
        return f"{hash_value[:16]}...{hash_value[-8:]}"
    else:
        return hash_value


def compare_hashes(hash1: str, hash2: str) -> bool:
    """
    Compare two hash values (case-insensitive).
    
    Args:
        hash1: First hash
        hash2: Second hash
        
    Returns:
        True if hashes match
    """
    return hash1.lower() == hash2.lower()

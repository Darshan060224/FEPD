"""
Configuration Management Module
Handles loading and accessing application configuration
"""

import os
from pathlib import Path
from typing import Any, Optional
from dotenv import load_dotenv
import yaml
import logging


class Config:
    """Configuration manager for FEPD application."""
    
    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            env_file: Path to .env file (defaults to .env in project root)
        """
        self.logger = logging.getLogger(__name__)
        self.config_dir = Path(__file__).parent.parent.parent / "config"
        
        # Load environment variables
        if env_file:
            load_dotenv(env_file)
        else:
            # Try to load .env from project root
            env_path = Path(__file__).parent.parent.parent / ".env"
            if env_path.exists():
                load_dotenv(env_path)
            else:
                # Load from .env.example as fallback
                example_env = Path(__file__).parent.parent.parent / ".env.example"
                if example_env.exists():
                    self.logger.warning("Using .env.example - create .env for production")
                    load_dotenv(example_env)
        
        # Load YAML configurations
        self.yaml_configs = {}
        self._load_yaml_configs()
    
    def _load_yaml_configs(self):
        """Load all YAML configuration files."""
        if not self.config_dir.exists():
            return
        
        for yaml_file in self.config_dir.glob("**/*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    config_name = yaml_file.stem
                    self.yaml_configs[config_name] = yaml.safe_load(f)
                    self.logger.debug(f"Loaded config: {config_name}")
            except Exception as e:
                self.logger.error(f"Failed to load {yaml_file}: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        # First try runtime config (set via set() method)
        if hasattr(self, '_runtime_config') and key in self._runtime_config:
            return self._runtime_config[key]
        
        # Then try environment variables
        value = os.getenv(key)
        if value is not None:
            return self._convert_type(value)
        
        # Then try YAML configs
        for config in self.yaml_configs.values():
            if key in config:
                return config[key]
        
        return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a runtime configuration value.
        
        Args:
            key: Configuration key
            value: Value to set
        """
        # Store in a runtime config dict
        if not hasattr(self, '_runtime_config'):
            self._runtime_config = {}
        self._runtime_config[key] = value
    
    def copy(self) -> 'Config':
        """
        Create a shallow copy of the config.
        
        Returns:
            New Config instance with same settings
        """
        new_config = Config.__new__(Config)
        new_config.logger = self.logger
        new_config.config_dir = self.config_dir
        new_config.yaml_configs = self.yaml_configs.copy()
        new_config._runtime_config = getattr(self, '_runtime_config', {}).copy()
        return new_config
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean configuration value."""
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)
    
    def get_int(self, key: str, default: int = 0) -> int:
        """Get integer configuration value."""
        try:
            return int(self.get(key, default))
        except (ValueError, TypeError):
            return default
    
    def get_list(self, key: str, default: list = None) -> list:
        """Get list configuration value (comma-separated string or list)."""
        if default is None:
            default = []
        
        value = self.get(key, default)
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [item.strip() for item in value.split(',') if item.strip()]
        return default
    
    def _convert_type(self, value: str) -> Any:
        """Convert string value to appropriate type."""
        # Boolean conversion
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Integer conversion
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float conversion
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def get_path(self, key: str, default: Optional[Path] = None) -> Path:
        """Get path configuration value."""
        value = self.get(key)
        if value:
            path = Path(value)
            if not path.is_absolute():
                # Make relative to project root
                path = Path(__file__).parent.parent.parent / path
            return path
        return default or Path()
    
    def get_yaml_config(self, config_name: str) -> dict:
        """Get entire YAML configuration by name."""
        return self.yaml_configs.get(config_name, {})
    
    def validate(self) -> bool:
        """
        Validate critical configuration settings.
        
        Returns:
            True if configuration is valid
        """
        required_settings = [
            'APP_NAME',
            'APP_VERSION',
            'HASH_ALGORITHM',
        ]
        
        for setting in required_settings:
            if not self.get(setting):
                self.logger.error(f"Missing required configuration: {setting}")
                return False
        
        # Validate hash algorithm
        if self.get('HASH_ALGORITHM') != 'SHA256':
            self.logger.error("HASH_ALGORITHM must be SHA256 for forensic compliance")
            return False
        
        # Validate read-only enforcement
        if not self.get_bool('READONLY_ENFORCEMENT', True):
            self.logger.warning("Read-only enforcement is disabled - forensic integrity at risk")
        
        return True

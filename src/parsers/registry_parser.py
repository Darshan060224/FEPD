"""
FEPD - Forensic Evidence Parser Dashboard
Registry Parser Module

Parses Windows Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT) using python-registry.
Extracts keys, values, modification timestamps for forensic analysis.

Implements FR-11: Parse Registry hives (SYSTEM/SOFTWARE/SAM/NTUSER.DAT)

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable

try:
    from Registry import Registry
except ImportError:
    Registry = None


class RegistryParser:
    """
    Parser for Windows Registry hive files.
    
    Uses python-registry library to extract keys, values, and modification timestamps.
    Focuses on forensically relevant keys (Run, RunOnce, MRU, Services, etc.)
    """
    
    # Forensically interesting key paths
    INTERESTING_PATHS = [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        r"Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
        r"Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        r"ControlSet001\Services",
        r"ControlSet001\Control\Session Manager",
    ]

    TARGETED_EXTRACTION_MAP = {
        "SOFTWARE": {
            "os_information": {
                "path": r"Microsoft\Windows NT\CurrentVersion",
                "fields": [
                    "ProductName",
                    "CurrentVersion",
                    "InstallDate",
                    "BuildLab",
                    "CurrentBuildNumber",
                    "RegisteredOwner",
                    "RegisteredOrganization",
                    "ProductId",
                    "DisplayVersion",
                ],
            },
            "installed_software": {
                "path": r"Microsoft\Windows\CurrentVersion\Uninstall",
                "subkey_fields": ["DisplayName", "DisplayVersion", "Publisher", "InstallDate"],
            },
            "security_config": {
                "paths": [
                    r"Microsoft\Windows Defender",
                    r"Microsoft\Windows Defender\Real-Time Protection",
                    r"Policies\Microsoft\WindowsFirewall",
                    r"Policies\Microsoft\WindowsFirewall\DomainProfile",
                    r"Policies\Microsoft\WindowsFirewall\StandardProfile",
                ],
            },
            "uac_policy": {
                "path": r"Microsoft\Windows\CurrentVersion\Policies\System",
                "fields": ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"],
            },
        },
        "SYSTEM": {
            "hardware_cpu": {
                "path": r"HARDWARE\DESCRIPTION\System\CentralProcessor",
            },
            "hardware_system": {
                "path": r"ControlSet001\Control\SystemInformation",
                "fallback_paths": [r"CurrentControlSet\Control\SystemInformation"],
                "fields": ["BIOSVersion", "SystemManufacturer", "SystemProductName"],
            },
            "hardware_bios": {
                "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                "fields": [
                    "BIOSVendor",
                    "BIOSVersion",
                    "BaseBoardManufacturer",
                    "BaseBoardProduct",
                    "SystemManufacturer",
                    "SystemProductName",
                ],
            },
            "computer_name": {
                "paths": [
                    r"ControlSet001\Control\ComputerName\ComputerName",
                    r"ControlSet001\Control\ComputerName\ActiveComputerName",
                    r"CurrentControlSet\Control\ComputerName\ComputerName",
                    r"CurrentControlSet\Control\ComputerName\ActiveComputerName",
                ],
                "fields": ["ComputerName"],
            },
            "time_information": {
                "paths": [
                    r"ControlSet001\Control\TimeZoneInformation",
                    r"CurrentControlSet\Control\TimeZoneInformation",
                ],
                "fields": ["TimeZoneKeyName", "StandardName", "Bias", "ActiveTimeBias", "DynamicDaylightTimeDisabled"],
            },
            "shutdown_state": {
                "paths": [
                    r"ControlSet001\Control\Windows",
                    r"CurrentControlSet\Control\Windows",
                ],
                "fields": ["ShutdownTime"],
            },
            "network_interfaces": {
                "path": r"ControlSet001\Services\Tcpip\Parameters\Interfaces",
                "fallback_paths": [r"CurrentControlSet\Services\Tcpip\Parameters\Interfaces"],
                "fields": [
                    "IPAddress",
                    "DhcpIPAddress",
                    "SubnetMask",
                    "DefaultGateway",
                    "NameServer",
                    "DhcpServer",
                    "Domain",
                    "DhcpDomain",
                    "NetworkAddress",
                    "Description",
                ],
            },
            "services": {
                "path": r"ControlSet001\Services",
                "fallback_paths": [r"CurrentControlSet\Services"],
                "fields": ["ImagePath", "Start", "DisplayName"],
            },
            "usb_history": {
                "path": r"ControlSet001\Enum\USBSTOR",
                "fallback_paths": [r"CurrentControlSet\Enum\USBSTOR"],
            },
        },
    }
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Registry Parser.
        
        Args:
            logger: Optional logger instance for audit trail
        """
        self.logger = logger or logging.getLogger(__name__)
        
        if Registry is None:
            self.logger.error("python-registry library not installed. Install: pip install python-registry")
            raise ImportError("python-registry library required for Registry parsing")
    
    def parse_file(self, hive_path: Path, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[Dict[str, Any]]:
        """Alias for parse method to match pipeline interface."""
        return self.parse(hive_path, progress_callback)
    
    def parse(
        self, 
        hive_path: Path, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse a Registry hive file and extract forensically relevant keys.
        
        Args:
            hive_path: Path to Registry hive file
            progress_callback: Optional callback(current, total) for progress tracking
            
        Returns:
            List of parsed registry event dictionaries
            
        Raises:
            FileNotFoundError: If hive file doesn't exist
            ValueError: If file is not valid Registry format
        """
        hive_path = Path(hive_path)
        
        if not hive_path.exists():
            raise FileNotFoundError(f"Registry hive not found: {hive_path}")
        
        self.logger.info(f"Parsing Registry hive: {hive_path}")
        
        parsed_events = []
        
        try:
            reg = Registry.Registry(str(hive_path))
            root = reg.root()
            
            self.logger.info(f"Registry hive root: {root.name()}")
            
            # Parse interesting paths
            for idx, interesting_path in enumerate(self.INTERESTING_PATHS):
                try:
                    events = self._parse_key_path(root, interesting_path, hive_path)
                    parsed_events.extend(events)
                    
                    if progress_callback:
                        progress_callback(idx + 1, len(self.INTERESTING_PATHS))
                
                except Registry.RegistryKeyNotFoundException:
                    self.logger.debug(f"Key not found: {interesting_path}")
                    continue
                except Exception as e:
                    self.logger.warning(f"Failed to parse key {interesting_path}: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to open Registry hive {hive_path}: {e}")
            raise ValueError(f"Invalid or corrupted Registry hive: {e}")
        
        self.logger.info(f"Successfully parsed {len(parsed_events)} registry entries from {hive_path.name}")
        return parsed_events
    
    def _parse_key_path(self, root, key_path: str, hive_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a specific registry key path and all its values.
        
        Args:
            root: Registry root key
            key_path: Path to key (relative to root)
            hive_path: Path to source hive file
            
        Returns:
            List of event dictionaries for this key
        """
        events = []
        
        try:
            key = root.find_key(key_path)
        except Registry.RegistryKeyNotFoundException:
            return events
        
        # Get key modification timestamp
        try:
            ts_utc = key.timestamp().isoformat()
        except:
            ts_utc = datetime.now(timezone.utc).isoformat()
        
        # Parse all values in this key
        for value in key.values():
            try:
                event = {
                    'artifact_source': 'Registry',
                    'artifact_path': str(hive_path),
                    'event_type': 'RegKeyModified',
                    'ts_utc': ts_utc,
                    'ts_local': None,
                    'key_path': key.path(),
                    'value_name': value.name(),
                    'value_type': value.value_type_str(),
                    'value_data': self._sanitize_value(value.value()),
                    'description': f"Registry: {key.path()} | {value.name()}",
                    'raw_data_ref': f"{key.path()}\\{value.name()}"
                }
                events.append(event)
            
            except Exception as e:
                self.logger.warning(f"Failed to parse value in {key.path()}: {e}")
                continue
        
        # Also check subkeys (one level deep for services, etc.)
        if "Services" in key_path or "Run" in key_path:
            for subkey in key.subkeys():
                try:
                    subkey_ts = subkey.timestamp().isoformat()
                    
                    event = {
                        'artifact_source': 'Registry',
                        'artifact_path': str(hive_path),
                        'event_type': 'RegKeyCreated',
                        'ts_utc': subkey_ts,
                        'ts_local': None,
                        'key_path': subkey.path(),
                        'value_name': "(KeyCreated)",
                        'value_type': "KEY",
                        'value_data': subkey.name(),
                        'description': f"Registry Key Created: {subkey.path()}",
                        'raw_data_ref': subkey.path()
                    }
                    events.append(event)
                
                except Exception as e:
                    self.logger.warning(f"Failed to parse subkey {subkey.name()}: {e}")
                    continue
        
        return events
    
    def _sanitize_value(self, value: Any) -> str:
        """
        Convert registry value to string safely.
        
        Args:
            value: Registry value (can be binary, string, int, etc.)
            
        Returns:
            String representation
        """
        if value is None:
            return "(none)"
        
        if isinstance(value, bytes):
            # Convert binary to hex string (truncate if too long)
            hex_str = value.hex()
            return hex_str[:200] + "..." if len(hex_str) > 200 else hex_str
        
        if isinstance(value, list):
            return " | ".join(str(v) for v in value[:10])  # Max 10 items
        
        return str(value)[:500]  # Truncate long strings

    def parse_structured_artifacts(self, hive_path: Path, hive_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse targeted forensic fields from SYSTEM/SOFTWARE hives.

        Args:
            hive_path: Path to hive file
            hive_name: Optional hive type override (SYSTEM/SOFTWARE)

        Returns:
            Dictionary with structured artifact groups.
        """
        hive_path = Path(hive_path)
        inferred_hive = (hive_name or hive_path.name).upper()

        if "SOFTWARE" in inferred_hive:
            hive_type = "SOFTWARE"
        elif "SYSTEM" in inferred_hive:
            hive_type = "SYSTEM"
        else:
            return {"hive": inferred_hive, "supported": False, "artifacts": {}}

        reg = Registry.Registry(str(hive_path))
        root = reg.root()
        artifacts: Dict[str, Any] = {}

        if hive_type == "SOFTWARE":
            artifacts["os_information"] = self._extract_fixed_fields(
                root,
                self.TARGETED_EXTRACTION_MAP["SOFTWARE"]["os_information"]["path"],
                self.TARGETED_EXTRACTION_MAP["SOFTWARE"]["os_information"]["fields"],
            )
            artifacts["installed_software"] = self._extract_subkey_table(
                root,
                self.TARGETED_EXTRACTION_MAP["SOFTWARE"]["installed_software"]["path"],
                self.TARGETED_EXTRACTION_MAP["SOFTWARE"]["installed_software"]["subkey_fields"],
                name_field="DisplayName",
            )
            artifacts["security_config"] = self._extract_multi_paths(
                root,
                self.TARGETED_EXTRACTION_MAP["SOFTWARE"]["security_config"]["paths"],
            )
            artifacts["uac_policy"] = self._extract_fixed_fields(
                root,
                self.TARGETED_EXTRACTION_MAP["SOFTWARE"]["uac_policy"]["path"],
                self.TARGETED_EXTRACTION_MAP["SOFTWARE"]["uac_policy"]["fields"],
            )

        if hive_type == "SYSTEM":
            cpu_base = self._find_first_existing_key(
                root,
                [self.TARGETED_EXTRACTION_MAP["SYSTEM"]["hardware_cpu"]["path"]],
            )
            artifacts["hardware_cpu"] = self._extract_child_value_map(root, cpu_base)

            sysinfo_paths = [self.TARGETED_EXTRACTION_MAP["SYSTEM"]["hardware_system"]["path"]]
            sysinfo_paths.extend(self.TARGETED_EXTRACTION_MAP["SYSTEM"]["hardware_system"]["fallback_paths"])
            sysinfo_base = self._find_first_existing_key(root, sysinfo_paths)
            artifacts["hardware_system"] = self._extract_fixed_fields(
                root,
                sysinfo_base,
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["hardware_system"]["fields"],
            )

            artifacts["hardware_bios"] = self._extract_fixed_fields(
                root,
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["hardware_bios"]["path"],
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["hardware_bios"]["fields"],
            )

            artifacts["computer_name"] = self._extract_first_existing_fields(
                root,
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["computer_name"]["paths"],
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["computer_name"]["fields"],
            )

            artifacts["time_information"] = self._extract_first_existing_fields(
                root,
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["time_information"]["paths"],
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["time_information"]["fields"],
            )

            shutdown_state = self._extract_first_existing_fields(
                root,
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["shutdown_state"]["paths"],
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["shutdown_state"]["fields"],
            )
            shutdown_state["LastShutdownTime"] = self._normalize_shutdown_time(shutdown_state.get("ShutdownTime"))
            artifacts["shutdown_state"] = shutdown_state

            iface_paths = [self.TARGETED_EXTRACTION_MAP["SYSTEM"]["network_interfaces"]["path"]]
            iface_paths.extend(self.TARGETED_EXTRACTION_MAP["SYSTEM"]["network_interfaces"]["fallback_paths"])
            iface_base = self._find_first_existing_key(root, iface_paths)
            artifacts["network_interfaces"] = self._extract_subkey_table(
                root,
                iface_base,
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["network_interfaces"]["fields"],
                name_field=None,
            )

            services_paths = [self.TARGETED_EXTRACTION_MAP["SYSTEM"]["services"]["path"]]
            services_paths.extend(self.TARGETED_EXTRACTION_MAP["SYSTEM"]["services"]["fallback_paths"])
            services_base = self._find_first_existing_key(root, services_paths)
            artifacts["services"] = self._extract_subkey_table(
                root,
                services_base,
                self.TARGETED_EXTRACTION_MAP["SYSTEM"]["services"]["fields"],
                name_field=None,
            )

            usbstor_paths = [self.TARGETED_EXTRACTION_MAP["SYSTEM"]["usb_history"]["path"]]
            usbstor_paths.extend(self.TARGETED_EXTRACTION_MAP["SYSTEM"]["usb_history"]["fallback_paths"])
            usbstor_base = self._find_first_existing_key(root, usbstor_paths)
            artifacts["usb_history"] = self._extract_usb_history(root, usbstor_base)

        return {
            "hive": hive_type,
            "supported": True,
            "source": str(hive_path),
            "artifacts": artifacts,
        }

    def _find_first_existing_key(self, root: Any, candidate_paths: List[str]) -> str:
        for p in candidate_paths:
            if not p:
                continue
            try:
                root.find_key(p)
                return p
            except Exception:
                continue
        return candidate_paths[0] if candidate_paths else ""

    def _extract_fixed_fields(self, root: Any, key_path: str, fields: List[str]) -> Dict[str, Any]:
        data: Dict[str, Any] = {"key_path": key_path}
        if not key_path:
            return data
        try:
            key = root.find_key(key_path)
        except Exception:
            data["missing"] = True
            return data

        for field in fields:
            data[field] = self._read_value(key, field)
        return data

    def _extract_multi_paths(self, root: Any, key_paths: List[str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for p in key_paths:
            try:
                key = root.find_key(p)
                out[p] = {
                    v.name(): self._normalize_registry_value(v.value())
                    for v in key.values()
                }
            except Exception:
                out[p] = {"missing": True}
        return out

    def _extract_first_existing_fields(self, root: Any, key_paths: List[str], fields: List[str]) -> Dict[str, Any]:
        selected = self._find_first_existing_key(root, key_paths)
        return self._extract_fixed_fields(root, selected, fields)

    def _extract_subkey_table(
        self,
        root: Any,
        key_path: str,
        fields: List[str],
        name_field: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if not key_path:
            return []
        try:
            key = root.find_key(key_path)
        except Exception:
            return []

        rows: List[Dict[str, Any]] = []
        for sub in key.subkeys():
            row: Dict[str, Any] = {
                "key_name": sub.name(),
                "key_path": sub.path(),
            }
            for f in fields:
                row[f] = self._read_value(sub, f)
            if name_field and not row.get(name_field):
                continue
            rows.append(row)
        return rows

    def _extract_child_value_map(self, root: Any, key_path: str) -> List[Dict[str, Any]]:
        if not key_path:
            return []
        try:
            key = root.find_key(key_path)
        except Exception:
            return []

        rows: List[Dict[str, Any]] = []
        for sub in key.subkeys():
            value_map = {
                v.name(): self._normalize_registry_value(v.value())
                for v in sub.values()
            }
            value_map["key_name"] = sub.name()
            value_map["key_path"] = sub.path()
            rows.append(value_map)
        return rows

    def _extract_usb_history(self, root: Any, key_path: str) -> List[Dict[str, Any]]:
        if not key_path:
            return []
        try:
            usbstor = root.find_key(key_path)
        except Exception:
            return []

        devices: List[Dict[str, Any]] = []
        for device_class in usbstor.subkeys():
            for instance in device_class.subkeys():
                devices.append(
                    {
                        "device_name": device_class.name(),
                        "serial": instance.name(),
                        "key_path": instance.path(),
                    }
                )
        return devices

    def _read_value(self, key: Any, value_name: str) -> Any:
        try:
            value = key.value(value_name).value()
            return self._normalize_registry_value(value)
        except Exception:
            return None

    def _normalize_registry_value(self, value: Any) -> Any:
        if isinstance(value, bytes):
            return value.hex()[:1024]
        if isinstance(value, list):
            return [self._normalize_registry_value(v) for v in value[:50]]
        if isinstance(value, int):
            return value
        return str(value) if value is not None else None

    def _normalize_shutdown_time(self, value: Any) -> Optional[str]:
        """Convert Windows FILETIME shutdown marker to ISO UTC when possible."""
        if value in (None, "", []):
            return None

        try:
            raw: Optional[bytes] = None
            if isinstance(value, bytes) and len(value) >= 8:
                raw = value[:8]
            elif isinstance(value, str):
                text = value.strip().lower()
                if text and all(c in "0123456789abcdef" for c in text) and len(text) >= 16:
                    raw = bytes.fromhex(text[:16])

            if not raw:
                return None

            ft = int.from_bytes(raw, byteorder="little", signed=False)
            if ft <= 0:
                return None

            unix_seconds = (ft - 116444736000000000) / 10000000
            return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).isoformat()
        except Exception:
            return None

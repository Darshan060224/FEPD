"""
FEPD - Forensic Evidence Parser Dashboard
System Configuration Extractor

Extracts host profile / system configuration from forensic evidence:
  - System Information (OS, hostname, build, timezone, etc.)
  - Hardware Information (CPU, RAM, disk, BIOS)
  - Network Configuration (IP, MAC, DNS, gateway, adapters)
  - Installed Software (from Uninstall registry keys)
  - Running Services (from SYSTEM hive)
  - Security Configuration (firewall, defender, UAC)

Sources: Windows Registry hives (SYSTEM, SOFTWARE), WMI artifacts, system files.

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from Registry import Registry
except ImportError:
    Registry = None

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SystemInfo:
    os_name: str = "Unknown"
    hostname: str = "Unknown"
    build_number: str = "Unknown"
    system_version: str = "Unknown"
    install_date: str = "Unknown"
    time_zone: str = "Unknown"
    last_boot: str = "Unknown"
    registered_owner: str = "Unknown"
    registered_org: str = "Unknown"
    product_id: str = "Unknown"

    def to_dict(self) -> Dict[str, str]:
        return {
            "Operating System": self.os_name,
            "Hostname": self.hostname,
            "Build Number": self.build_number,
            "System Version": self.system_version,
            "Install Date": self.install_date,
            "Time Zone": self.time_zone,
            "Last Boot Time": self.last_boot,
            "Registered Owner": self.registered_owner,
            "Registered Organization": self.registered_org,
            "Product ID": self.product_id,
        }


@dataclass
class HardwareInfo:
    cpu_model: str = "Unknown"
    cpu_cores: str = "Unknown"
    total_ram: str = "Unknown"
    disk_size: str = "Unknown"
    disk_model: str = "Unknown"
    bios_version: str = "Unknown"
    motherboard: str = "Unknown"
    system_manufacturer: str = "Unknown"
    system_model: str = "Unknown"

    def to_dict(self) -> Dict[str, str]:
        return {
            "CPU Model": self.cpu_model,
            "CPU Cores": self.cpu_cores,
            "Total RAM": self.total_ram,
            "Disk Size": self.disk_size,
            "Disk Model": self.disk_model,
            "BIOS Version": self.bios_version,
            "Motherboard": self.motherboard,
            "System Manufacturer": self.system_manufacturer,
            "System Model": self.system_model,
        }


@dataclass
class NetworkAdapter:
    name: str = ""
    ip_address: str = ""
    mac_address: str = ""
    dns_servers: str = ""
    gateway: str = ""
    dhcp_enabled: str = ""
    dhcp_server: str = ""
    domain: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "Adapter": self.name,
            "IP Address": self.ip_address,
            "MAC Address": self.mac_address,
            "DNS Servers": self.dns_servers,
            "Gateway": self.gateway,
            "DHCP Enabled": self.dhcp_enabled,
            "DHCP Server": self.dhcp_server,
            "Domain": self.domain,
        }


@dataclass
class InstalledSoftware:
    name: str = ""
    version: str = ""
    publisher: str = ""
    install_date: str = ""
    install_location: str = ""

    def to_list(self) -> List[str]:
        return [self.name, self.version, self.publisher, self.install_date, self.install_location]


@dataclass
class ServiceEntry:
    service_name: str = ""
    display_name: str = ""
    startup_type: str = ""
    image_path: str = ""
    service_type: str = ""

    def to_list(self) -> List[str]:
        return [self.service_name, self.display_name, self.startup_type, self.image_path]


@dataclass
class SecurityConfig:
    firewall_enabled: str = "Unknown"
    defender_status: str = "Unknown"
    uac_enabled: str = "Unknown"
    audit_policy: str = "Unknown"
    antivirus: str = "Unknown"

    def to_dict(self) -> Dict[str, str]:
        return {
            "Firewall": self.firewall_enabled,
            "Windows Defender": self.defender_status,
            "UAC": self.uac_enabled,
            "Audit Policy": self.audit_policy,
            "Antivirus": self.antivirus,
        }


@dataclass
class SystemConfiguration:
    system_info: SystemInfo = field(default_factory=SystemInfo)
    hardware_info: HardwareInfo = field(default_factory=HardwareInfo)
    network_adapters: List[NetworkAdapter] = field(default_factory=list)
    installed_software: List[InstalledSoftware] = field(default_factory=list)
    services: List[ServiceEntry] = field(default_factory=list)
    security_config: SecurityConfig = field(default_factory=SecurityConfig)
    extraction_timestamp: str = ""
    evidence_source: str = ""


# ---------------------------------------------------------------------------
# Startup-type mapping
# ---------------------------------------------------------------------------

_START_TYPE_MAP = {
    0: "Boot",
    1: "System",
    2: "Automatic",
    3: "Manual",
    4: "Disabled",
}

_SERVICE_TYPE_MAP = {
    1: "Kernel Driver",
    2: "File System Driver",
    4: "Adapter",
    16: "Win32 Own Process",
    32: "Win32 Share Process",
    256: "Interactive",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_value(key, value_name: str, default: str = "Unknown") -> str:
    """Safely read a registry value, returning *default* on any error."""
    try:
        return str(key.value(value_name).value())
    except Exception:
        return default


def _open_hive(path: Path):
    """Open a registry hive; returns None when the library is missing or the file is bad."""
    if Registry is None:
        logger.warning("python-registry not installed – skipping hive %s", path)
        return None
    try:
        return Registry.Registry(str(path))
    except Exception as exc:
        logger.warning("Could not open hive %s: %s", path, exc)
        return None


def _open_key(reg, path: str):
    """Open a subkey; returns None on failure."""
    try:
        return reg.open(path)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Extractors  (each returns a section of SystemConfiguration)
# ---------------------------------------------------------------------------

def extract_system_info(software_hive: Path, system_hive: Path) -> SystemInfo:
    """Extract OS / hostname / build from SOFTWARE + SYSTEM hives."""
    info = SystemInfo()

    sw = _open_hive(software_hive)
    if sw:
        nt_key = _open_key(sw, r"Microsoft\Windows NT\CurrentVersion")
        if nt_key:
            product = _safe_value(nt_key, "ProductName")
            build = _safe_value(nt_key, "CurrentBuildNumber")
            info.os_name = product
            info.build_number = build
            info.system_version = _safe_value(nt_key, "DisplayVersion",
                                              _safe_value(nt_key, "ReleaseId", build))
            info.registered_owner = _safe_value(nt_key, "RegisteredOwner")
            info.registered_org = _safe_value(nt_key, "RegisteredOrganization")
            info.product_id = _safe_value(nt_key, "ProductId")

            raw_install = _safe_value(nt_key, "InstallDate", "")
            if raw_install.isdigit():
                try:
                    info.install_date = datetime.fromtimestamp(
                        int(raw_install), tz=timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S UTC")
                except (ValueError, OSError):
                    info.install_date = raw_install
            else:
                info.install_date = raw_install if raw_install else "Unknown"

    sy = _open_hive(system_hive)
    if sy:
        # Hostname
        hostname_key = _open_key(sy, r"ControlSet001\Control\ComputerName\ComputerName")
        if hostname_key:
            info.hostname = _safe_value(hostname_key, "ComputerName")

        # Time zone
        tz_key = _open_key(sy, r"ControlSet001\Control\TimeZoneInformation")
        if tz_key:
            info.time_zone = _safe_value(tz_key, "TimeZoneKeyName",
                                         _safe_value(tz_key, "StandardName"))

        # Last boot (ShutdownTime in SYSTEM hive – 64-bit FILETIME)
        shutdown_key = _open_key(sy, r"ControlSet001\Control\Windows")
        if shutdown_key:
            try:
                raw = shutdown_key.value("ShutdownTime").raw_data()
                if len(raw) >= 8:
                    ft = struct.unpack("<Q", raw[:8])[0]
                    # FILETIME → Unix epoch
                    ts = (ft - 116444736000000000) / 10000000
                    info.last_boot = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
            except Exception:
                pass

    return info


def extract_hardware_info(system_hive: Path, software_hive: Path) -> HardwareInfo:
    """Extract CPU, RAM, disk, BIOS from SYSTEM + SOFTWARE hives."""
    hw = HardwareInfo()

    sy = _open_hive(system_hive)
    if sy:
        # CPU
        cpu_key = _open_key(sy, r"ControlSet001\Hardware Description\System\CentralProcessor\0")
        if cpu_key:
            hw.cpu_model = _safe_value(cpu_key, "ProcessorNameString")

        # Count cores (subkeys under CentralProcessor)
        cpus_key = _open_key(sy, r"ControlSet001\Hardware Description\System\CentralProcessor")
        if cpus_key:
            try:
                hw.cpu_cores = str(len(cpus_key.subkeys()))
            except Exception:
                pass

        # BIOS
        bios_key = _open_key(sy, r"ControlSet001\Hardware Description\System\BIOS")
        if bios_key:
            hw.bios_version = _safe_value(bios_key, "BIOSVersion",
                                          _safe_value(bios_key, "BIOSReleaseDate"))
            hw.system_manufacturer = _safe_value(bios_key, "SystemManufacturer")
            hw.system_model = _safe_value(bios_key, "SystemProductName")
            hw.motherboard = _safe_value(bios_key, "BaseBoardProduct")

        # Disk
        disk_key = _open_key(sy, r"ControlSet001\Services\disk\Enum")
        if disk_key:
            hw.disk_model = _safe_value(disk_key, "0")

    sw = _open_hive(software_hive)
    if sw:
        # RAM (PhysicalMemory from WMI cache or SMBIOS – best-effort)
        mem_key = _open_key(sw, r"Microsoft\Windows NT\CurrentVersion")
        if mem_key:
            raw_ram = _safe_value(mem_key, "InstallationType", "")
            # InstalledPhysicalMemory sometimes in SYSTEM
        # Try SYSTEM for memory
        if sy:
            mem_key2 = _open_key(sy, r"ControlSet001\Control\Session Manager\Memory Management")
            if mem_key2:
                paging = _safe_value(mem_key2, "PagingFiles", "")
                if paging:
                    hw.total_ram = "(see paging config: %s)" % paging

    return hw


def extract_network_config(system_hive: Path) -> List[NetworkAdapter]:
    """Extract network adapter configuration from SYSTEM hive."""
    adapters: List[NetworkAdapter] = []
    sy = _open_hive(system_hive)
    if not sy:
        return adapters

    interfaces_key = _open_key(
        sy, r"ControlSet001\Services\Tcpip\Parameters\Interfaces"
    )
    if not interfaces_key:
        return adapters

    for sub in interfaces_key.subkeys():
        adapter = NetworkAdapter()
        adapter.name = sub.name()[:40]
        adapter.ip_address = _safe_value(sub, "IPAddress",
                                         _safe_value(sub, "DhcpIPAddress"))
        adapter.mac_address = ""  # MACs not stored in Tcpip params
        adapter.gateway = _safe_value(sub, "DefaultGateway",
                                      _safe_value(sub, "DhcpDefaultGateway"))
        adapter.dns_servers = _safe_value(sub, "NameServer",
                                          _safe_value(sub, "DhcpNameServer"))
        adapter.dhcp_enabled = _safe_value(sub, "EnableDHCP")
        adapter.dhcp_server = _safe_value(sub, "DhcpServer")
        adapter.domain = _safe_value(sub, "Domain")

        # Skip empty adapters (loopback, etc.)
        if adapter.ip_address not in ("Unknown", "", "0.0.0.0"):
            adapters.append(adapter)

    # Domain membership
    domain_key = _open_key(sy, r"ControlSet001\Services\Tcpip\Parameters")
    if domain_key:
        domain_name = _safe_value(domain_key, "Domain", "")
        if domain_name and adapters:
            adapters[0].domain = domain_name

    return adapters


def extract_installed_software(software_hive: Path) -> List[InstalledSoftware]:
    """Extract installed programs from SOFTWARE\\…\\Uninstall."""
    programs: List[InstalledSoftware] = []
    sw = _open_hive(software_hive)
    if not sw:
        return programs

    for uninstall_path in (
        r"Microsoft\Windows\CurrentVersion\Uninstall",
        r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ):
        parent = _open_key(sw, uninstall_path)
        if not parent:
            continue
        for sub in parent.subkeys():
            name = _safe_value(sub, "DisplayName", "")
            if not name:
                continue
            prog = InstalledSoftware(
                name=name,
                version=_safe_value(sub, "DisplayVersion", ""),
                publisher=_safe_value(sub, "Publisher", ""),
                install_date=_safe_value(sub, "InstallDate", ""),
                install_location=_safe_value(sub, "InstallLocation", ""),
            )
            programs.append(prog)

    programs.sort(key=lambda p: p.name.lower())
    return programs


def extract_services(system_hive: Path) -> List[ServiceEntry]:
    """Extract services from SYSTEM\\ControlSet001\\Services."""
    services: List[ServiceEntry] = []
    sy = _open_hive(system_hive)
    if not sy:
        return services

    svc_root = _open_key(sy, r"ControlSet001\Services")
    if not svc_root:
        return services

    for sub in svc_root.subkeys():
        start_raw = _safe_value(sub, "Start", "")
        # Only include services (not drivers unless they have a display name)
        display = _safe_value(sub, "DisplayName", "")
        image = _safe_value(sub, "ImagePath", "")

        stype_raw = _safe_value(sub, "Type", "")
        stype_int = int(stype_raw) if stype_raw.isdigit() else -1
        stype_label = _SERVICE_TYPE_MAP.get(stype_int, str(stype_raw))

        # Filter: keep user-mode services + named kernel drivers
        if stype_int not in (16, 32, 256) and not display:
            continue

        start_int = int(start_raw) if start_raw.isdigit() else -1
        start_label = _START_TYPE_MAP.get(start_int, start_raw)

        entry = ServiceEntry(
            service_name=sub.name(),
            display_name=display if display else sub.name(),
            startup_type=start_label,
            image_path=image,
            service_type=stype_label,
        )
        services.append(entry)

    services.sort(key=lambda s: s.service_name.lower())
    return services


def extract_security_config(software_hive: Path, system_hive: Path) -> SecurityConfig:
    """Best-effort extraction of security-related settings."""
    sec = SecurityConfig()

    sy = _open_hive(system_hive)
    if sy:
        # Firewall (SharedAccess)
        fw_key = _open_key(sy, r"ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile")
        if fw_key:
            fw_val = _safe_value(fw_key, "EnableFirewall", "")
            sec.firewall_enabled = "Enabled" if fw_val == "1" else ("Disabled" if fw_val == "0" else fw_val)

    sw = _open_hive(software_hive)
    if sw:
        # Windows Defender
        wd_key = _open_key(sw, r"Microsoft\Windows Defender")
        if wd_key:
            sec.defender_status = "Installed"
            disable = _safe_value(wd_key, "DisableAntiSpyware", "")
            if disable == "1":
                sec.defender_status = "Disabled (AntiSpyware off)"

        # UAC
        uac_key = _open_key(sw, r"Microsoft\Windows\CurrentVersion\Policies\System")
        if uac_key:
            uac_val = _safe_value(uac_key, "EnableLUA", "")
            sec.uac_enabled = "Enabled" if uac_val == "1" else ("Disabled" if uac_val == "0" else uac_val)

        # Antivirus (registered AV)
        av_key = _open_key(sw, r"Microsoft\Security Center\Provider\Av")
        if av_key:
            try:
                for sub in av_key.subkeys():
                    av_name = _safe_value(sub, "DISPLAYNAME", "")
                    if av_name:
                        sec.antivirus = av_name
                        break
            except Exception:
                pass

    return sec


# ---------------------------------------------------------------------------
# Main extraction orchestrator
# ---------------------------------------------------------------------------

def extract_full_config(
    system_hive: Optional[Path] = None,
    software_hive: Optional[Path] = None,
    evidence_source: str = "",
) -> SystemConfiguration:
    """
    Run all extractors and return a unified SystemConfiguration.

    Args:
        system_hive: Path to the SYSTEM registry hive file.
        software_hive: Path to the SOFTWARE registry hive file.
        evidence_source: Label for the evidence source.

    Returns:
        Populated SystemConfiguration dataclass.
    """
    config = SystemConfiguration()
    config.extraction_timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    config.evidence_source = evidence_source

    sys_path = system_hive or Path()
    sw_path = software_hive or Path()

    if system_hive and system_hive.exists() or software_hive and software_hive.exists():
        logger.info("Extracting system configuration from hives…")
        config.system_info = extract_system_info(sw_path, sys_path)
        config.hardware_info = extract_hardware_info(sys_path, sw_path)
        config.network_adapters = extract_network_config(sys_path)
        config.installed_software = extract_installed_software(sw_path)
        config.services = extract_services(sys_path)
        config.security_config = extract_security_config(sw_path, sys_path)
        logger.info(
            "Extraction complete – %d adapters, %d programs, %d services",
            len(config.network_adapters),
            len(config.installed_software),
            len(config.services),
        )
    else:
        logger.warning("No valid hive paths provided – returning empty configuration")

    return config

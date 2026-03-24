"""
Forensic tab engine:
- master prompt generation per tab
- strict JSON output normalization
- section routing to tab handlers
- deterministic extraction from unified forensic store (no guessing)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .unified_forensic_store import UnifiedForensicStore


TAB_FIELDS: Dict[str, List[str]] = {
    "System Information": [
        "Operating System",
        "Hostname",
        "Build Number",
        "System Version",
        "Install Date",
        "Time Zone",
        "Last Boot Time",
        "Registered Owner",
        "Registered Organization",
        "Product ID",
    ],
    "Hardware Information": [
        "CPU Model",
        "CPU Cores",
        "Total RAM",
        "Disk Size",
        "Disk Model",
        "BIOS Version",
        "Motherboard",
        "System Manufacturer",
        "System Model",
    ],
    "Network Configuration": [
        "Adapter Name",
        "IP Address",
        "MAC Address",
        "DNS Servers",
        "Gateway",
        "DHCP Enabled",
        "DHCP Server",
        "Domain",
    ],
    "Installed Software": ["programs"],
    "Services": ["services"],
    "Security Configuration": [
        "Firewall Status",
        "Windows Defender Status",
        "UAC Level",
        "Audit Policy",
        "Antivirus",
    ],
    "Activity Timeline": ["events"],
    "Top Findings": ["findings"],
    "Anomaly Detection": ["anomalies"],
    "UEBA Profiling": ["profiles"],
    "Network Intrusion": ["events"],
    "Threat Intelligence": ["indicators"],
    "Visualization": ["buckets"],
}

SECTION_ALIASES = {
    "system info": "System Information",
    "system": "System Information",
    "hardware": "Hardware Information",
    "network": "Network Configuration",
    "software": "Installed Software",
    "installed software": "Installed Software",
    "service": "Services",
    "security": "Security Configuration",
    "timeline": "Activity Timeline",
    "findings": "Top Findings",
    "anomaly": "Anomaly Detection",
    "ueba": "UEBA Profiling",
    "intrusion": "Network Intrusion",
    "threat intel": "Threat Intelligence",
    "threat intelligence": "Threat Intelligence",
    "visualization": "Visualization",
}

MASTER_PROMPT_TEMPLATE = """You are a senior digital forensic analyst working in a certified forensic lab.

Your task is to extract and structure evidence from forensic data sources such as:
- Disk images (E01)
- Registry hives (SYSTEM, SOFTWARE, NTUSER.DAT)
- Event logs
- File system artifacts
- Memory artifacts (if present)

STRICT RULES:
- Only extract data that is explicitly present in the evidence
- Do NOT guess or infer missing values
- If a value is not found -> return null
- Prefer authoritative forensic sources (registry, logs, MFT, prefetch)
- Normalize timestamps to ISO format (YYYY-MM-DDTHH:MM:SS)
- Avoid duplicate entries
- Maintain forensic integrity (no modification or assumptions)

ANALYSIS MODE:
- Correlate multiple artifacts if needed
- Validate consistency between sources
- Flag suspicious or unusual values

TARGET SECTION: {TAB_NAME}

FIELDS TO EXTRACT:
{FIELDS_LIST}

EVIDENCE INPUT:
{EVIDENCE_JSON}

OUTPUT (STRICT JSON ONLY):
{{
  "section": "{TAB_NAME}",
  "fields": {{ ... }},
  "source": ["list of evidence sources used"],
  "confidence": 0-100,
  "notes": "brief forensic explanation if needed"
}}"""


def normalize_section_name(section_name: str) -> str:
    raw = (section_name or "").strip()
    if raw in TAB_FIELDS:
        return raw
    low = raw.lower()
    if low in SECTION_ALIASES:
        return SECTION_ALIASES[low]
    for k, v in SECTION_ALIASES.items():
        if k in low:
            return v
    return raw


def build_master_prompt(tab_name: str, evidence_json: Dict[str, Any]) -> str:
    section = normalize_section_name(tab_name)
    fields = TAB_FIELDS.get(section, [])
    return MASTER_PROMPT_TEMPLATE.format(
        TAB_NAME=section,
        FIELDS_LIST="\n".join(f"- {f}" for f in fields),
        EVIDENCE_JSON=json.dumps(evidence_json, indent=2, ensure_ascii=False),
    )


def validate_or_coerce_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    section = normalize_section_name(str(payload.get("section", "")))
    expected_fields = TAB_FIELDS.get(section, [])

    fields = payload.get("fields")
    if not isinstance(fields, dict):
        fields = {}

    # Ensure keys exist for object-style sections.
    if expected_fields and expected_fields[0] not in {"programs", "services", "events", "findings", "anomalies", "profiles", "indicators", "buckets"}:
        normalized_fields: Dict[str, Any] = {}
        for key in expected_fields:
            normalized_fields[key] = fields.get(key, None)
        fields = normalized_fields

    sources = payload.get("source")
    if not isinstance(sources, list):
        sources = []

    confidence = payload.get("confidence", 0)
    try:
        confidence = max(0, min(100, int(confidence)))
    except Exception:
        confidence = 0

    notes = payload.get("notes")
    if notes is None:
        notes = ""

    return {
        "section": section,
        "fields": fields,
        "source": sources,
        "confidence": confidence,
        "notes": notes,
    }


def route_to_tab(response: Dict[str, Any], handlers: Dict[str, Callable[[Dict[str, Any]], None]]) -> bool:
    normalized = validate_or_coerce_response(response)
    section = normalized["section"]
    handler = handlers.get(section)
    if not handler:
        return False
    handler(normalized["fields"])
    return True


class ForensicTabExtractionEngine:
    """Deterministic evidence extraction per tab from normalized store."""

    def __init__(self, store: UnifiedForensicStore):
        self.store = store
        self.case_path = Path(self.store.case_path)
        self.case_metadata = self._load_case_metadata()
        self.detection_results = self._load_latest_detection_results()
        self.has_case_metadata = bool(self.case_metadata)
        self.has_registry_data = isinstance(self.detection_results.get("registry"), dict) and bool(self.detection_results.get("registry"))
        self.has_memory_data = isinstance(self.detection_results.get("memory"), dict) and bool(self.detection_results.get("memory"))
        self.has_artifact_data = len(self.store.query_artifacts(limit=1, offset=0)) > 0
        self.has_file_data = len(self.store.query_files(limit=1, offset=0)) > 0

    def extract_section(self, section_name: str) -> Dict[str, Any]:
        section = normalize_section_name(section_name)

        if section == "System Information":
            return self._system_information_section()
        if section == "Hardware Information":
            return self._hardware_information_section()
        if section == "Network Configuration":
            return self._network_configuration_section()
        if section == "Security Configuration":
            return self._security_configuration_section()

        if section == "Installed Software":
            return self._software_section()
        if section == "Services":
            return self._services_section()
        if section == "Activity Timeline":
            return self._timeline_section()
        if section == "Top Findings":
            return self._findings_section()
        if section == "Threat Intelligence":
            return self._threat_intel_section()
        if section == "Anomaly Detection":
            return self._anomaly_section()
        if section == "UEBA Profiling":
            return self._ueba_section()
        if section == "Network Intrusion":
            return self._network_intrusion_section()
        if section == "Visualization":
            return self._visualization_section()

        # Default object section with null fields when not directly observable.
        field_obj = {k: None for k in TAB_FIELDS.get(section, [])}
        return {
            "section": section,
            "fields": field_obj,
            "source": [],
            "confidence": 0,
            "notes": "No deterministic evidence mapped for this section yet in current parser output.",
        }

    def _system_information_section(self) -> Dict[str, Any]:
        os_info = self._get_registry_object("os_information")
        computer_name = self._get_registry_object("computer_name")
        tz_info = self._get_registry_object("time_information")
        shutdown_state = self._get_registry_object("shutdown_state")

        hostname = (
            computer_name.get("ComputerName")
            or self.case_metadata.get("hostname")
            or self.case_metadata.get("case_id")
        )

        fields = {
            "Operating System": os_info.get("ProductName"),
            "Hostname": hostname,
            "Build Number": os_info.get("CurrentBuildNumber") or os_info.get("BuildLab"),
            "System Version": os_info.get("DisplayVersion") or os_info.get("CurrentVersion"),
            "Install Date": self._to_iso(os_info.get("InstallDate")),
            "Time Zone": tz_info.get("TimeZoneKeyName") or tz_info.get("StandardName") or self.case_metadata.get("timezone"),
            "Last Boot Time": self._to_iso(shutdown_state.get("LastShutdownTime")),
            "Registered Owner": os_info.get("RegisteredOwner"),
            "Registered Organization": os_info.get("RegisteredOrganization"),
            "Product ID": os_info.get("ProductId"),
        }

        populated = sum(1 for v in fields.values() if v not in (None, "", []))
        return {
            "section": "System Information",
            "fields": fields,
            "source": ["registry", "case_metadata"],
            "confidence": 80 if populated >= 3 else (50 if populated > 0 else 0),
            "notes": "System fields are sourced from SOFTWARE CurrentVersion and case metadata only.",
        }

    def _hardware_information_section(self) -> Dict[str, Any]:
        cpu_rows = self._get_registry_list("hardware_cpu")
        sys_info = self._get_registry_object("hardware_system")
        bios_info = self._get_registry_object("hardware_bios")
        image_meta = (self.detection_results.get("extraction") or {}).get("image_metadata") or {}
        mem_meta = self.detection_results.get("memory") or {}

        cpu_model = None
        cpu_cores = None
        if cpu_rows:
            cpu_model = cpu_rows[0].get("ProcessorNameString") or cpu_rows[0].get("Identifier")
            cpu_cores = len(cpu_rows)

        fields = {
            "CPU Model": cpu_model,
            "CPU Cores": cpu_cores,
            "Total RAM": mem_meta.get("size_bytes"),
            "Disk Size": image_meta.get("size"),
            "Disk Model": None,
            "BIOS Version": bios_info.get("BIOSVersion") or sys_info.get("BIOSVersion"),
            "Motherboard": bios_info.get("BaseBoardProduct") or bios_info.get("BaseBoardManufacturer"),
            "System Manufacturer": sys_info.get("SystemManufacturer") or bios_info.get("SystemManufacturer"),
            "System Model": sys_info.get("SystemProductName") or bios_info.get("SystemProductName"),
        }

        populated = sum(1 for v in fields.values() if v not in (None, "", []))
        return {
            "section": "Hardware Information",
            "fields": fields,
            "source": ["registry", "extraction", "memory"],
            "confidence": 75 if populated >= 3 else (45 if populated > 0 else 0),
            "notes": "Hardware fields are populated from SYSTEM hardware keys and evidence metadata when present.",
        }

    def _network_configuration_section(self) -> Dict[str, Any]:
        interfaces = self._get_registry_list("network_interfaces")
        iface = self._pick_best_interface(interfaces)

        ip_addr = iface.get("DhcpIPAddress") or iface.get("IPAddress")
        gateway = iface.get("DefaultGateway")
        dns = iface.get("NameServer")
        dhcp_enabled = bool(iface.get("DhcpIPAddress")) if iface else None

        fields = {
            "Adapter Name": iface.get("Description") or iface.get("key_name"),
            "IP Address": self._stringify_multi_value(ip_addr),
            "MAC Address": iface.get("NetworkAddress"),
            "DNS Servers": self._stringify_multi_value(dns),
            "Gateway": self._stringify_multi_value(gateway),
            "DHCP Enabled": dhcp_enabled,
            "DHCP Server": iface.get("DhcpServer"),
            "Domain": iface.get("Domain") or iface.get("DhcpDomain"),
        }

        populated = sum(1 for v in fields.values() if v not in (None, "", []))
        return {
            "section": "Network Configuration",
            "fields": fields,
            "source": ["registry"],
            "confidence": 75 if populated >= 3 else (45 if populated > 0 else 0),
            "notes": (
                "Network values are sourced from SYSTEM Tcpip interface keys only. "
                f"Interfaces observed: {len(interfaces)}"
            ),
        }

    def _security_configuration_section(self) -> Dict[str, Any]:
        security = self._get_registry_object("security_config")
        uac_policy = self._get_registry_object("uac_policy")

        firewall_status = None
        defender_status = None
        uac = None
        audit = None

        if isinstance(security, dict):
            fw = (
                security.get("Policies\\Microsoft\\WindowsFirewall\\DomainProfile")
                or security.get("Policies\\Microsoft\\WindowsFirewall\\StandardProfile")
                or security.get("Policies\\Microsoft\\WindowsFirewall")
                or {}
            )
            if isinstance(fw, dict):
                enabled = fw.get("EnableFirewall")
                if enabled is not None:
                    firewall_status = "Enabled" if str(enabled) in {"1", "True", "true"} else "Disabled"

            wd = security.get("Microsoft\\Windows Defender") or {}
            wd_rt = security.get("Microsoft\\Windows Defender\\Real-Time Protection") or {}
            if isinstance(wd, dict):
                disable = wd.get("DisableAntiSpyware")
                if disable is not None:
                    defender_status = "Disabled" if str(disable) in {"1", "True", "true"} else "Enabled"
            if defender_status is None and isinstance(wd_rt, dict):
                rt_disable = wd_rt.get("DisableRealtimeMonitoring")
                if rt_disable is not None:
                    defender_status = "Disabled" if str(rt_disable) in {"1", "True", "true"} else "Enabled"

            uac_raw = uac_policy.get("EnableLUA")
            if uac_raw is not None:
                uac = "Enabled" if str(uac_raw) in {"1", "True", "true"} else "Disabled"
            audit = uac_policy.get("ConsentPromptBehaviorAdmin")

        fields = {
            "Firewall Status": firewall_status,
            "Windows Defender Status": defender_status,
            "UAC Level": uac,
            "Audit Policy": audit,
            "Antivirus": "Windows Defender" if defender_status else None,
        }

        populated = sum(1 for v in fields.values() if v not in (None, "", []))
        return {
            "section": "Security Configuration",
            "fields": fields,
            "source": ["registry"],
            "confidence": 70 if populated >= 2 else (40 if populated > 0 else 0),
            "notes": "Security fields are populated from Defender/Firewall policy values when available.",
        }

    def _software_section(self) -> Dict[str, Any]:
        rows = self.store.query_artifacts(limit=5000, offset=0, type_filter="registry")
        programs: List[Dict[str, Any]] = []

        for r in rows:
            path = (r.get("path") or "").lower()
            if "uninstall" not in path and "software" not in path:
                continue
            programs.append(
                {
                    "name": r.get("name"),
                    "version": None,
                    "publisher": None,
                    "install_date": r.get("timestamp"),
                    "path": r.get("path"),
                }
            )

        # Enrich from structured registry output when present.
        for sw in self._get_registry_list("installed_software"):
            programs.append(
                {
                    "name": sw.get("DisplayName"),
                    "version": sw.get("DisplayVersion"),
                    "publisher": sw.get("Publisher"),
                    "install_date": self._to_iso(sw.get("InstallDate")),
                    "path": sw.get("key_path"),
                }
            )

        return {
            "section": "Installed Software",
            "fields": {"programs": self._dedup_list(programs, key="name")},
            "source": ["registry"],
            "confidence": 70 if programs else 0,
            "notes": "Derived from parsed registry artifacts without inferred version/publisher values.",
        }

    def _services_section(self) -> Dict[str, Any]:
        rows = self.store.query_artifacts(limit=5000, offset=0, type_filter="registry")
        services: List[Dict[str, Any]] = []
        for r in rows:
            path = (r.get("path") or "").lower()
            if "services" not in path:
                continue
            services.append(
                {
                    "name": r.get("name"),
                    "display_name": None,
                    "startup_type": None,
                    "path": r.get("path"),
                    "status": None,
                    "risk_level": "unknown",
                }
            )

        for svc in self._get_registry_list("services"):
            startup_raw = svc.get("Start")
            startup_type = None
            if startup_raw is not None:
                startup_map = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
                try:
                    startup_type = startup_map.get(int(startup_raw), str(startup_raw))
                except Exception:
                    startup_type = str(startup_raw)

            services.append(
                {
                    "name": svc.get("key_name"),
                    "display_name": svc.get("DisplayName"),
                    "startup_type": startup_type,
                    "path": svc.get("ImagePath") or svc.get("key_path"),
                    "status": None,
                    "risk_level": "unknown",
                }
            )

        return {
            "section": "Services",
            "fields": {"services": self._dedup_list(services, key="name")},
            "source": ["registry"],
            "confidence": 70 if services else 0,
            "notes": "Service entries from registry-related artifact paths; unobserved fields remain null.",
        }

    def _timeline_section(self) -> Dict[str, Any]:
        rows = self.store.query_artifacts(limit=5000, offset=0)
        events = []

        for e in (self.detection_results.get("timeline") or [])[:10000]:
            events.append(
                {
                    "time": e.get("timestamp"),
                    "event_type": e.get("type"),
                    "level": None,
                    "operation": e.get("type"),
                    "activity": e.get("detail"),
                    "user": None,
                    "program": None,
                    "pid": None,
                    "ppid": None,
                    "path": None,
                }
            )

        for r in rows:
            events.append(
                {
                    "time": r.get("timestamp"),
                    "event_type": r.get("type"),
                    "level": None,
                    "operation": r.get("type"),
                    "activity": r.get("name"),
                    "user": r.get("user"),
                    "program": r.get("name"),
                    "pid": None,
                    "ppid": None,
                    "path": r.get("path"),
                }
            )

        mem = self.detection_results.get("memory") or {}
        analysis_time = mem.get("analysis_time")
        for proc in mem.get("processes", [])[:500]:
            events.append(
                {
                    "time": analysis_time,
                    "event_type": "memory_process",
                    "level": "info",
                    "operation": "memory_observed",
                    "activity": proc.get("name"),
                    "user": "memory-observed",
                    "program": proc.get("name"),
                    "pid": proc.get("pid"),
                    "ppid": None,
                    "path": None,
                }
            )

        for conn in mem.get("network_connections", [])[:500]:
            ip = conn.get("ip")
            port = conn.get("port")
            events.append(
                {
                    "time": analysis_time,
                    "event_type": "memory_network",
                    "level": "info",
                    "operation": "network_observed",
                    "activity": f"{ip}:{port}",
                    "user": "memory-observed",
                    "program": None,
                    "pid": None,
                    "ppid": None,
                    "path": None,
                }
            )

        return {
            "section": "Activity Timeline",
            "fields": {"events": events},
            "source": ["ui_artifacts", "memory"],
            "confidence": 80 if events else 0,
            "notes": "Timeline events are normalized from artifact timestamps.",
        }

    def _findings_section(self) -> Dict[str, Any]:
        rows = self.store.query_artifacts(limit=5000, offset=0)
        findings = []
        for r in rows:
            p = (r.get("path") or "").lower()
            artifact_type = str(r.get("type") or "").lower()
            risk = 0
            reason_parts = []
            if any(x in p for x in ["\\temp\\", "/temp/", "appdata/local/temp"]):
                risk += 30
                reason_parts.append("temp-path-artifact")
            if artifact_type in {"execution", "process", "command", "detection"}:
                risk += 35
                reason_parts.append("execution-related")
            if r.get("source") == "memory":
                risk += 25
                reason_parts.append("memory-observed")
            if risk == 0:
                continue

            finding_type = "file"
            if artifact_type in {"execution", "process", "command", "detection"}:
                finding_type = "process"
            elif not r.get("path"):
                finding_type = "process"

            findings.append(
                {
                    "type": finding_type,
                    "name": r.get("name"),
                    "risk_score": min(100, risk),
                    "reason": ",".join(reason_parts),
                    "evidence": [r.get("source"), r.get("path")],
                }
            )

        mem = self.detection_results.get("memory") or {}
        for cmd in mem.get("command_history", [])[:2000]:
            text = str(cmd.get("command") or "")
            if not text:
                continue
            cmd_lower = text.lower()
            risk = 35
            reasons = ["memory-command-trace"]
            if any(k in cmd_lower for k in ["powershell", "iex", "downloadstring", "frombase64string", "regsvr32", "rundll32"]):
                risk += 30
                reasons.append("suspicious-shell-pattern")
            findings.append(
                {
                    "type": "command",
                    "name": text[:200],
                    "risk_score": min(100, risk),
                    "reason": ",".join(reasons),
                    "evidence": ["memory", cmd.get("offset")],
                }
            )

        for cred in mem.get("credential_indicators", [])[:2000]:
            indicator = cred.get("value") or cred.get("keyword") or "credential-indicator"
            findings.append(
                {
                    "type": "credential",
                    "name": str(indicator)[:200],
                    "risk_score": 85,
                    "reason": "credential-indicator-observed-in-memory",
                    "evidence": ["memory", cred.get("offset")],
                }
            )

        for det in (self.detection_results.get("detections") or [])[:500]:
            score = int(det.get("score") or 0)
            findings.append(
                {
                    "type": "detection",
                    "name": det.get("executable"),
                    "risk_score": min(100, score),
                    "reason": f"correlated-detection:{det.get('verdict')}",
                    "evidence": ["correlation_engine", det.get("evidence")],
                }
            )

        findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        return {
            "section": "Top Findings",
            "fields": {"findings": findings[:100]},
            "source": ["ui_artifacts", "memory"],
            "confidence": 85 if findings else 0,
            "notes": "Rule-based findings from explicit artifact characteristics; no speculative threat attribution.",
        }

    def _threat_intel_section(self) -> Dict[str, Any]:
        rows = self.store.query_artifacts(limit=5000, offset=0)
        indicators = []
        for r in rows:
            name = str(r.get("name") or "")
            if self._looks_like_ip(name):
                indicators.append(
                    {
                        "indicator": name,
                        "type": "ip",
                        "risk": "medium",
                        "reason": "Observed in memory/network artifacts; no external intel lookup applied.",
                    }
                )

        mem = self.detection_results.get("memory") or {}
        for conn in mem.get("network_connections", [])[:2000]:
            ip = str(conn.get("ip") or "")
            if not self._looks_like_ip(ip):
                continue
            indicators.append(
                {
                    "indicator": ip,
                    "type": "ip",
                    "risk": "medium",
                    "reason": "Observed directly in memory network connections.",
                }
            )

        for det in (self.detection_results.get("detections") or [])[:500]:
            for ip in det.get("remote_ips") or []:
                ip_text = str(ip)
                if not self._looks_like_ip(ip_text):
                    continue
                indicators.append(
                    {
                        "indicator": ip_text,
                        "type": "ip",
                        "risk": "high" if str(det.get("verdict")) in {"Critical", "High"} else "medium",
                        "reason": "Observed in high-confidence cross-source correlation finding.",
                    }
                )

        indicators = self._dedup_list(indicators, key="indicator")

        return {
            "section": "Threat Intelligence",
            "fields": {"indicators": indicators},
            "source": ["memory", "ui_artifacts"],
            "confidence": 75 if indicators else 0,
            "notes": "Indicators extracted from evidence only; unknown indicators not marked malicious by default.",
        }

    def _anomaly_section(self) -> Dict[str, Any]:
        findings = self._findings_section().get("fields", {}).get("findings", [])
        anomalies = []
        for f in findings:
            risk = int(f.get("risk_score") or 0)
            if risk < 60:
                continue
            anomalies.append(
                {
                    "name": f.get("name"),
                    "severity": "high" if risk < 90 else "critical",
                    "score": risk / 100.0,
                    "reason": f.get("reason"),
                    "evidence": f.get("evidence", []),
                }
            )

        return {
            "section": "Anomaly Detection",
            "fields": {"anomalies": anomalies},
            "source": ["ui_artifacts", "memory"],
            "confidence": 80 if anomalies else 0,
            "notes": "High-risk anomalies are deterministically derived from Top Findings risk rules.",
        }

    def _ueba_section(self) -> Dict[str, Any]:
        rows = self.store.query_artifacts(limit=5000, offset=0)
        user_map: Dict[str, Dict[str, Any]] = {}

        for r in rows:
            user = str(r.get("user") or "").strip()
            if not user:
                metadata = r.get("metadata_json")
                if isinstance(metadata, str):
                    try:
                        meta_obj = json.loads(metadata)
                    except Exception:
                        meta_obj = {}
                else:
                    meta_obj = metadata if isinstance(metadata, dict) else {}
                user = str(meta_obj.get("user") or meta_obj.get("owner") or "").strip()
            if not user:
                user = self._extract_user_from_path(str(r.get("path") or ""))
            if not user and r.get("source") == "memory":
                user = "memory-observed"
            if not user:
                user = f"source:{str(r.get('source') or 'unknown')}"
            if not user:
                continue
            profile = user_map.setdefault(
                user,
                {
                    "user": user,
                    "event_count": 0,
                    "sources": set(),
                    "risk_score": 0,
                },
            )
            profile["event_count"] += 1
            profile["sources"].add(str(r.get("source") or ""))

            path = (r.get("path") or "").lower()
            if "temp" in path:
                profile["risk_score"] += 15
            if r.get("source") == "memory":
                profile["risk_score"] += 10

        profiles = []
        for p in user_map.values():
            profiles.append(
                {
                    "user": p["user"],
                    "event_count": p["event_count"],
                    "sources": sorted(s for s in p["sources"] if s),
                    "risk_score": min(100, p["risk_score"]),
                }
            )

        profiles.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        return {
            "section": "UEBA Profiling",
            "fields": {"profiles": profiles},
            "source": ["ui_artifacts"],
            "confidence": 70 if profiles else 0,
            "notes": "Profiles are derived from observed artifact ownership and source activity only.",
        }

    def _network_intrusion_section(self) -> Dict[str, Any]:
        indicators = self._threat_intel_section().get("fields", {}).get("indicators", [])
        mem = self.detection_results.get("memory") or {}
        analysis_time = mem.get("analysis_time")
        events = []
        for ind in indicators:
            if ind.get("type") != "ip":
                continue
            events.append(
                {
                    "timestamp": analysis_time or self.detection_results.get("completed_at"),
                    "event": "network_indicator_observed",
                    "source": "memory",
                    "severity": "medium",
                    "score": 0.65,
                    "network_score": 0.65,
                    "artifact_score": 0.6,
                    "flags": f"ip:{ind.get('indicator')}",
                }
            )

        # Fallback: derive network/intrusion-like events directly from normalized artifacts.
        if not events:
            rows = self.store.query_artifacts(limit=5000, offset=0)
            for r in rows:
                t = str(r.get("type") or "").lower()
                s = str(r.get("source") or "").lower()
                n = str(r.get("name") or "")
                p = str(r.get("path") or "")
                if not any(k in f"{t} {s} {n} {p}" for k in ["network", "browser", "download", "ip", "detection", "evtx"]):
                    continue

                ts = r.get("timestamp") or analysis_time or self.detection_results.get("completed_at")
                sev = "medium"
                score = 0.6
                if "detection" in t or "detection" in s:
                    sev = "high"
                    score = 0.8

                events.append(
                    {
                        "timestamp": ts,
                        "event": "network_artifact_observed",
                        "source": r.get("source") or "ui_artifacts",
                        "severity": sev,
                        "score": score,
                        "network_score": score,
                        "artifact_score": float(r.get("confidence") or 0.6),
                        "flags": f"name:{n}" if n else f"path:{p}",
                    }
                )

        events = [e for e in events if e.get("timestamp")]
        events = events[:1000]

        return {
            "section": "Network Intrusion",
            "fields": {"events": events},
            "source": ["memory", "ui_artifacts"],
            "confidence": 70 if events else 0,
            "notes": "Network intrusion events are deterministic wrappers over observed network indicators.",
        }

    def _visualization_section(self) -> Dict[str, Any]:
        rows = self.store.query_artifacts(limit=5000, offset=0)
        counts: Dict[str, int] = {}
        for r in rows:
            t = str(r.get("type") or "unknown")
            counts[t] = counts.get(t, 0) + 1

        buckets = [
            {"label": k, "value": v}
            for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ]

        return {
            "section": "Visualization",
            "fields": {"buckets": buckets},
            "source": ["ui_artifacts"],
            "confidence": 75 if buckets else 0,
            "notes": "Visualization buckets reflect observed artifact type distribution.",
        }

    def _load_case_metadata(self) -> Dict[str, Any]:
        case_json = self.case_path / "case.json"
        if not case_json.exists():
            return {}
        try:
            return json.loads(case_json.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _load_latest_detection_results(self) -> Dict[str, Any]:
        root = self.case_path / "forensic_detection"
        if not root.exists():
            return {}

        candidates = list(root.rglob("forensic_detection_results.json"))
        if not candidates:
            return {}

        latest = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]
        try:
            return json.loads(latest.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _get_registry_object(self, artifact_key: str) -> Dict[str, Any]:
        for entry in self._iter_registry_entries(artifact_key):
            if isinstance(entry, dict):
                return entry
        return {}

    def _get_registry_list(self, artifact_key: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for entry in self._iter_registry_entries(artifact_key):
            if isinstance(entry, list):
                out.extend([x for x in entry if isinstance(x, dict)])
        return out

    def _iter_registry_entries(self, artifact_key: str):
        reg = self.detection_results.get("registry") or {}
        if not isinstance(reg, dict):
            return
        for payload in reg.values():
            if not isinstance(payload, dict):
                continue
            artifacts = payload.get("artifacts")
            if not isinstance(artifacts, dict):
                continue
            if artifact_key in artifacts:
                yield artifacts.get(artifact_key)

    def _pick_best_interface(self, interfaces: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not interfaces:
            return {}

        def _score(iface: Dict[str, Any]) -> int:
            keys = [
                "DhcpIPAddress",
                "IPAddress",
                "DefaultGateway",
                "NameServer",
                "DhcpServer",
                "Domain",
            ]
            return sum(1 for k in keys if iface.get(k) not in (None, "", []))

        return max(interfaces, key=_score)

    @staticmethod
    def _to_iso(value: Any) -> Optional[str]:
        if value in (None, "", []):
            return None
        text = str(value).strip()
        if not text:
            return None

        # Common registry install date format: YYYYMMDD
        if len(text) == 8 and text.isdigit():
            try:
                dt = datetime.strptime(text, "%Y%m%d")
                return dt.isoformat()
            except Exception:
                return text

        # Unix epoch seconds
        if text.isdigit() and len(text) in {9, 10}:
            try:
                return datetime.utcfromtimestamp(int(text)).isoformat() + "Z"
            except Exception:
                return text

        return text

    @staticmethod
    def _dedup_list(items: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
        seen = set()
        out: List[Dict[str, Any]] = []
        for item in items:
            val = item.get(key)
            if not val:
                continue
            marker = str(val).strip().lower()
            if marker in seen:
                continue
            seen.add(marker)
            out.append(item)
        return out

    @staticmethod
    def _extract_user_from_path(path: str) -> str:
        p = str(path or "").replace('\\', '/')
        marker = '/Users/'
        if marker in p:
            tail = p.split(marker, 1)[1]
            return tail.split('/', 1)[0]
        return ""

    @staticmethod
    def _looks_like_ip(text: str) -> bool:
        parts = text.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit():
                return False
            n = int(p)
            if n < 0 or n > 255:
                return False
        return True

    @staticmethod
    def _stringify_multi_value(value: Any) -> Optional[str]:
        if value in (None, "", []):
            return None
        if isinstance(value, list):
            cleaned = [str(v).strip() for v in value if str(v).strip()]
            return ", ".join(cleaned) if cleaned else None
        return str(value)


def build_case_tab_payload(case_path: str, section_name: str) -> Dict[str, Any]:
    """Convenience helper: deterministic section extraction for a case path."""
    store = UnifiedForensicStore(case_path)
    engine = ForensicTabExtractionEngine(store)
    payload = engine.extract_section(section_name)
    payload["generated_at"] = datetime.utcnow().isoformat() + "Z"
    return payload


def build_case_field_audit(case_path: str) -> Dict[str, Any]:
    """Build per-field audit report for all sections in a case.

    Report includes value presence, source list, and section-level confidence.
    """
    store = UnifiedForensicStore(case_path)
    engine = ForensicTabExtractionEngine(store)

    sections: List[Dict[str, Any]] = []
    for section, expected_fields in TAB_FIELDS.items():
        payload = validate_or_coerce_response(engine.extract_section(section))
        fields = payload.get("fields", {}) if isinstance(payload.get("fields"), dict) else {}

        audit_fields: List[Dict[str, Any]] = []
        for key in expected_fields:
            value = fields.get(key)
            if value is None and len(expected_fields) == 1:
                # list-style section fields (programs/services/events/etc.)
                value = fields.get(expected_fields[0])

            populated = False
            if isinstance(value, list):
                populated = len(value) > 0
            else:
                populated = value not in (None, "", [])

            audit_fields.append(
                {
                    "field": key,
                    "populated": populated,
                    "source_used": _infer_field_source(section, key, populated),
                    "source_candidates": payload.get("source", []),
                    "missing_reason": None if populated else _missing_reason(engine, section, key),
                    "value_preview": (value[:3] if isinstance(value, list) else value),
                }
            )

        sections.append(
            {
                "section": section,
                "confidence": payload.get("confidence", 0),
                "source": payload.get("source", []),
                "fields": audit_fields,
                "notes": payload.get("notes", ""),
            }
        )

    return {
        "case_path": str(case_path),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "evidence_availability": {
            "case_metadata": engine.has_case_metadata,
            "registry": engine.has_registry_data,
            "memory": engine.has_memory_data,
            "ui_artifacts": engine.has_artifact_data,
            "ui_files": engine.has_file_data,
        },
        "sections": sections,
    }


def export_case_field_audit(case_path: str, output_path: Optional[str] = None) -> str:
    """Generate and write field audit JSON to disk.

    Returns output file path.
    """
    report = build_case_field_audit(case_path)
    out = Path(output_path) if output_path else Path(case_path) / "forensic_detection" / "field_audit.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(out)


def build_case_mixed_evidence_status(case_path: str) -> Dict[str, Any]:
    """Build a single consolidated mixed-evidence parsing status report.

    Includes:
    - disk parts found
    - memory dump attached
    - parser coverage percentages per section
    - grouped missing extraction reasons
    """
    case_dir = Path(case_path)
    audit = build_case_field_audit(case_path)

    case_meta: Dict[str, Any] = {}
    case_json = case_dir / "case.json"
    if case_json.exists():
        try:
            case_meta = json.loads(case_json.read_text(encoding="utf-8"))
        except Exception:
            case_meta = {}

    disk_parts = _detect_disk_parts(case_meta)
    memory_info = _detect_memory_attachment(case_meta)

    section_coverage: List[Dict[str, Any]] = []
    missing_reasons: Dict[str, Dict[str, Any]] = {}

    for sec in audit.get("sections", []):
        section_name = sec.get("section")
        fields = sec.get("fields", [])
        total = len(fields)
        populated = sum(1 for f in fields if bool(f.get("populated")))
        percent = round((populated / total) * 100.0, 2) if total else 0.0
        section_coverage.append(
            {
                "section": section_name,
                "populated_fields": populated,
                "total_fields": total,
                "coverage_percent": percent,
            }
        )

        for f in fields:
            if f.get("populated"):
                continue
            reason = str(f.get("missing_reason") or "No reason provided")
            bucket = missing_reasons.setdefault(
                reason,
                {
                    "count": 0,
                    "sections": set(),
                    "fields": [],
                },
            )
            bucket["count"] += 1
            bucket["sections"].add(section_name)
            bucket["fields"].append(
                {
                    "section": section_name,
                    "field": f.get("field"),
                }
            )

    for reason, payload in missing_reasons.items():
        payload["sections"] = sorted(s for s in payload["sections"] if s)

    grouped_reasons = [
        {
            "reason": reason,
            "count": payload["count"],
            "sections": payload["sections"],
            "fields": payload["fields"],
        }
        for reason, payload in sorted(missing_reasons.items(), key=lambda x: x[1]["count"], reverse=True)
    ]

    overall_total = sum(s["total_fields"] for s in section_coverage)
    overall_populated = sum(s["populated_fields"] for s in section_coverage)
    overall_percent = round((overall_populated / overall_total) * 100.0, 2) if overall_total else 0.0

    return {
        "case_path": str(case_path),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "disk_parts_found": disk_parts,
        "memory_dump_attached": memory_info,
        "parser_coverage_percentages_per_section": section_coverage,
        "overall_coverage": {
            "populated_fields": overall_populated,
            "total_fields": overall_total,
            "coverage_percent": overall_percent,
        },
        "missing_extraction_reasons": grouped_reasons,
    }


def export_case_mixed_evidence_status(case_path: str, output_path: Optional[str] = None) -> str:
    """Write consolidated mixed-evidence status report to disk as JSON."""
    report = build_case_mixed_evidence_status(case_path)
    out = Path(output_path) if output_path else Path(case_path) / "forensic_detection" / "mixed_evidence_status.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(out)


def _detect_disk_parts(case_meta: Dict[str, Any]) -> Dict[str, Any]:
    evidence = case_meta.get("evidence_image") if isinstance(case_meta, dict) else {}
    image_path = str((evidence or {}).get("path") or "").strip()
    if not image_path:
        return {
            "base_name": None,
            "pattern": None,
            "total_parts": 0,
            "parts": [],
            "note": "No disk evidence path found in case metadata.",
        }

    p = Path(image_path)
    if not p.exists() or not p.parent.exists():
        return {
            "base_name": p.stem,
            "pattern": None,
            "total_parts": 0,
            "parts": [],
            "note": "Disk evidence path not found on current filesystem.",
        }

    name = p.name
    patterns = [
        (r"^(?P<base>.+)\.E(?P<n>\d{2,3})$", "EWF"),
        (r"^(?P<base>.+)\.L(?P<n>\d{2,3})$", "LWF"),
        (r"^(?P<base>.+)\.(?P<n>\d{3})$", "RAW_SPLIT"),
    ]

    for rgx, label in patterns:
        m = re.match(rgx, name, flags=re.IGNORECASE)
        if not m:
            continue
        base = m.group("base")
        if label == "EWF":
            part_re = re.compile(rf"^{re.escape(base)}\.E(\d{{2,3}})$", flags=re.IGNORECASE)
        elif label == "LWF":
            part_re = re.compile(rf"^{re.escape(base)}\.L(\d{{2,3}})$", flags=re.IGNORECASE)
        else:
            part_re = re.compile(rf"^{re.escape(base)}\.(\d{{3}})$", flags=re.IGNORECASE)

        parts = []
        for f in p.parent.iterdir():
            if not f.is_file():
                continue
            pm = part_re.match(f.name)
            if pm:
                parts.append({"name": f.name, "path": str(f), "seq": int(pm.group(1))})

        parts.sort(key=lambda x: x["seq"])
        return {
            "base_name": base,
            "pattern": label,
            "total_parts": len(parts),
            "parts": parts,
            "note": "",
        }

    return {
        "base_name": p.stem,
        "pattern": "SINGLE",
        "total_parts": 1,
        "parts": [{"name": p.name, "path": str(p), "seq": 1}],
        "note": "No multipart naming pattern detected; treated as single disk image file.",
    }


def _detect_memory_attachment(case_meta: Dict[str, Any]) -> Dict[str, Any]:
    mem = case_meta.get("memory_dump") if isinstance(case_meta, dict) else {}
    mem_path = str((mem or {}).get("path") or "").strip()
    if not mem_path:
        return {
            "attached": False,
            "path": "",
            "filename": "",
            "exists": False,
        }

    p = Path(mem_path)
    return {
        "attached": True,
        "path": mem_path,
        "filename": str((mem or {}).get("filename") or p.name),
        "exists": p.exists() and p.is_file(),
    }


def _infer_field_source(section: str, field: str, populated: bool) -> Optional[str]:
    if not populated:
        return None

    if field == "Hostname":
        return "case_metadata"
    if field in {"Total RAM"}:
        return "memory"
    if field in {"Disk Size"}:
        return "extraction"

    if section in {"System Information", "Hardware Information", "Network Configuration", "Security Configuration", "Installed Software", "Services"}:
        return "registry"
    if section in {"Activity Timeline", "Top Findings", "UEBA Profiling", "Visualization"}:
        return "ui_artifacts"
    if section in {"Threat Intelligence", "Network Intrusion"}:
        return "memory"
    if section == "Anomaly Detection":
        return "derived_findings"
    return "evidence"


def _missing_reason(engine: ForensicTabExtractionEngine, section: str, field: str) -> str:
    if field in {"Time Zone", "Last Boot Time"}:
        return "Field requires additional event-log/timezone extraction not present in current evidence pipeline."
    if field == "Disk Model":
        return "Disk model is not currently extracted from available evidence sources."

    registry_sections = {
        "System Information",
        "Hardware Information",
        "Network Configuration",
        "Security Configuration",
        "Installed Software",
        "Services",
    }
    memory_sections = {"Threat Intelligence", "Network Intrusion"}
    artifact_sections = {"Activity Timeline", "Top Findings", "Anomaly Detection", "UEBA Profiling", "Visualization"}

    if section in registry_sections and not engine.has_registry_data:
        return "Registry artifacts unavailable; disk extraction may be incomplete or hive files missing."
    if section in memory_sections and not engine.has_memory_data:
        return "Memory artifacts unavailable; no memory analysis results found for case."
    if section in artifact_sections and not engine.has_artifact_data:
        return "Normalized artifact records unavailable; index may need rebuild or extraction may be empty."
    if section == "System Information" and field == "Hostname" and not engine.has_case_metadata:
        return "Case metadata missing; hostname fallback unavailable."

    return "No direct evidence value found for this field in current sources."

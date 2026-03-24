# FEPD Forensic Pipeline Correlation Blueprint

Date: 2026-03-20
Status: Implementation-ready logic spec (lightweight, no heavy code)

## 1. Mission

Reconstruct attacker behavior from fragmented evidence sources by correlating disk, registry, memory, and network artifacts into one defensible chain:

User -> Process -> File -> Network

Single artifacts are weak signals. Multi-artifact correlation is high-confidence evidence.

## 2. End-to-End Pipeline

### Pipeline A: E01 -> File System + Registry Extraction

Input: E01 evidence image
Output: Structured disk and registry artifacts with provenance

Flow:
1. Mount E01 using pyewf stream + pytsk3 filesystem reader (read-only).
2. Enumerate volumes/filesystems (NTFS/FAT/exFAT/other detected types).
3. Resolve artifact target map paths.
4. Extract files/hives/events into case workspace (for parser consumption).
5. Record extraction metadata (source path, inode, hash, timestamps, extraction status).

Mandatory target map:
- /Windows/System32/config/SYSTEM
- /Windows/System32/config/SOFTWARE
- /Windows/System32/config/SAM
- /Users/*/NTUSER.DAT
- /Windows/System32/winevt/Logs/
- /Windows/Prefetch/
- /$MFT
- /$Extend/$UsnJrnl

### Pipeline B: Registry -> Structured Artifact Parsing

Input: Extracted hive files
Output: Normalized forensic fields for analytics and timeline

For each hive:
1. Open hive safely.
2. Navigate key paths.
3. Extract required values.
4. Normalize record schema.
5. Emit timeline events and entity records.

Required extraction map:

OS Information (SOFTWARE):
- Path: Microsoft\\Windows NT\\CurrentVersion
- Fields: ProductName, CurrentVersion, InstallDate, BuildLab, RegisteredOwner

Hardware (SYSTEM):
- Path: HARDWARE\\DESCRIPTION\\System\\CentralProcessor
- Fields: CPU details
- Path: CurrentControlSet\\Control\\SystemInformation
- Fields: BIOS, Manufacturer

Network Config (SYSTEM):
- Path: Services\\Tcpip\\Parameters\\Interfaces\\{GUID}
- Fields: IPAddress, DhcpIPAddress, SubnetMask, DefaultGateway, NameServer
- Requirement: iterate all interface GUID keys

Installed Software (SOFTWARE):
- Path: Microsoft\\Windows\\CurrentVersion\\Uninstall\\*
- Fields: DisplayName, DisplayVersion, Publisher, InstallDate

Services (SYSTEM):
- Path: CurrentControlSet\\Services\\*
- Fields: ServiceName, ImagePath, Start
- Priority field: ImagePath (high abuse potential)

Security Config:
- SOFTWARE\\Microsoft\\Windows Defender
- SOFTWARE\\Policies\\Microsoft\\WindowsFirewall
- Fields: Defender state, firewall policy state

### Pipeline C: Memory Dump -> Live State Reconstruction

Input: Memory dump (.mem, .dmp)
Output: Runtime process/network/credential/command artifacts

Core logic:
1. Process inventory:
   - Locate EPROCESS-like structures or process artifacts.
   - Extract PID, Name, Parent PID, start context.
   - Flag hidden/suspicious process anomalies.
2. Network extraction:
   - Parse socket/TCP artifacts.
   - Extract local IP, remote IP, port, owning PID.
3. Credential artifacts:
   - Analyze LSASS-related memory regions when available.
   - Extract credential indicators (hashes, plaintext indicators if present).
4. Command history artifacts:
   - Recover cmd.exe and PowerShell command traces.
5. Injection detection:
   - Compare memory-mapped executable regions vs expected disk image sections.
   - Flag mismatches as potential injection/tampering.

## 3. File System Artifact Logic

MFT parsing:
- Iterate records.
- Extract filename, MACB timestamps, size, state flags.

USN Journal parsing:
- Track file create, delete, rename transitions.

Prefetch parsing:
- For each .pf extract executable name, run count, last run time.

USB history:
- SYSTEM\\Enum\\USBSTOR
- Extract device name and serial.

## 4. Correlation Engine Logic

Goal: link entities into an explainable activity chain.

Core link rules:
1. Process -> File
   - Match process executable path/hash to disk artifacts.
2. Network -> Process
   - Match by PID and nearest timestamp window.
3. File -> User Activity
   - Match via user profile paths, UserAssist, LNK/Jump Lists, shell traces.
4. Registry -> Process/File context
   - Link service ImagePath, Run keys, and installed software records.

Entity graph model:
- User node
- Process node
- File node
- Network endpoint node
- Edges: executed, loaded, wrote, connected_to, spawned_by, owned_by

## 5. Critical Detection Chain (Deleted Malware + Execution + C2)

Detection objective:
File deleted, but execution happened, process existed, and external network connection occurred.

Step 1: Execution proof
- Sources: Prefetch, AmCache, ShimCache, UserAssist
- Extract exe_name, path, execution time(s)

Step 2: Disk existence check
- Search MFT for full path and filename
- If missing, check USN/deletion trace and unallocated indicators
- Mark state: Deleted or MissingOnDisk

Step 3: Memory process confirmation
- Match process name/path in memory artifacts
- Extract PID, parent PID, runtime context

Step 4: Network linkage
- Find connections by PID
- Extract remote IP/port and timing

Step 5: Timeline coherence test
- Validate temporal proximity: execution_time ~= process_time ~= network_time
- If sequence is coherent, raise confidence

Final decision rule:
IF execution_proof = true
AND disk_state in {Deleted, MissingOnDisk}
AND memory_process_present = true
AND network_connection_present = true
THEN verdict = HighConfidenceMalwareExecution

## 6. Confidence Scoring (Recommended)

Suggested additive scoring:
- Execution artifact present: +30
- File deleted/missing on disk: +20
- Process present in memory: +30
- External connection linked to process: +40

Risk bands:
- 0-39: Low
- 40-79: Medium
- 80-119: High
- 120+: Critical

## 7. Edge Case Handling

Deleted file but no memory process:
- Use Prefetch + Event Logs + USN + AmCache/ShimCache as historical chain.

Fileless attack:
- No disk executable expected.
- Use memory process + command history + suspicious network + script engine traces.

Process exited before capture:
- Fall back to timeline artifacts (Prefetch, EVTX, USN, registry execution traces).

## 8. Normalized Data Contracts

Use consistent schema so all pipelines can be correlated.

ExecutionArtifact:
- artifact_id
- source_type (Prefetch, AmCache, ShimCache, UserAssist)
- exe_name
- exe_path
- first_seen_ts
- last_seen_ts
- confidence
- source_ref

FileArtifact:
- file_id
- path
- mft_ref
- macb
- size
- hash_sha256
- state (Present, Deleted, Unknown)
- source_ref

ProcessArtifact:
- process_id
- pid
- ppid
- name
- image_path
- start_ts
- end_ts
- source_ref

NetworkArtifact:
- net_id
- pid
- local_ip
- local_port
- remote_ip
- remote_port
- protocol
- ts
- source_ref

CorrelationCase:
- correlation_id
- entity_chain (User->Process->File->Network)
- score
- verdict
- narrative
- evidence_refs

## 9. FEPD Integration Mapping

This design maps to current components:
- Registry parsing foundation: src/parsers/registry_parser.py
- Memory scanning foundation: src/modules/memory_analyzer.py
- Correlation service facade: src/services/artifact_correlator_service.py
- Core correlator logic location: src/terminal/intelligence/artifact_correlator.py

Implementation strategy:
1. Expand registry extractor path coverage and normalize outputs.
2. Upgrade memory analyzer from signature scan to structured runtime entities.
3. Add PID/time-aware correlation rules in artifact correlator.
4. Persist correlation graph + confidence score into case database.
5. Drive timeline and attack narrative generation from CorrelationCase records.

## 10. Examiner-Style Narrative Template

Example narrative output:
- Executable malware.exe was confirmed executed via Prefetch and AmCache at 10:32.
- File was not present in MFT at analysis time and deletion traces were observed.
- A memory-resident process malware.exe (PID 4321) was identified.
- PID 4321 initiated outbound connection to 185.23.44.12:443 at 10:33.
- Correlation score: 120 (Critical).
- Conclusion: high-confidence malicious execution with attempted anti-forensic deletion.

## 11. Acceptance Criteria

The pipeline is considered complete when:
- E01 ingestion reliably extracts all mandatory artifact targets.
- Registry outputs include all required fields listed in this blueprint.
- Memory outputs include process and network entities with PID linkage.
- Correlation engine produces deterministic verdicts with evidence references.
- Timeline can render the full chain from execution to network activity.
- Final report includes clear narrative and confidence score.
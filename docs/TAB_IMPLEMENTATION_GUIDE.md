# 🏗️ FEPD Complete Tab System - Implementation Guide

## Overview

This document provides **small logic segments with code** for all 6 FEPD tabs as per your blueprint specification.

---

## 🗂️ TAB 1: CASE TAB

### Purpose
Root of trust. Creates case workspace, owns Chain of Custody ledger.

### UI Components
```
┌─────────────────────────────────────────────────┐
│ 📋 Current Case                                 │
├─────────────────────────────────────────────────┤
│ Case:     LoneWolf_Investigation                │
│ ID:       9a3c7b21-...                          │
│ Operator: Darshan                               │
│ Created:  2026-01-27T10:15:00Z                  │
│ Status:   🟢 OPEN                               │
│ CoC:      ✔️ VERIFIED                           │
├─────────────────────────────────────────────────┤
│ [➕ Create] [📂 Load] [🔒 Seal] [📥 Export]    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ 🔗 Chain of Custody Log                         │
├──────────┬─────────┬────────┬──────────┬────────┤
│ Time     │ Action  │ Actor  │ Details  │ Hash   │
├──────────┼─────────┼────────┼──────────┼────────┤
│ 10:15:00 │ CREATED │ Darshan│ ...      │ a1b2.. │
│ 10:16:32 │ IMPORT  │ Darshan│ ...      │ b7c9.. │
└──────────┴─────────┴────────┴──────────┴────────┘
```

### Click Logic

#### 1. Create Case Button
```python
def _on_create_case(self):
    # Collect: case_name, operator, organization, notes
    dialog = CreateCaseDialog()
    if not dialog.exec():
        return
    
    case_id = uuid4()
    case_path = f"cases/{case_id}"
    
    # Create structure
    mkdir(f"{case_path}/evidence")
    mkdir(f"{case_path}/artifacts")
    mkdir(f"{case_path}/reports")
    
    # Write metadata.json
    metadata = {
        "case_id": case_id,
        "name": case_data['case_name'],
        "operator": case_data['operator'],
        "created_at": now(),
        "status": "OPEN"
    }
    write_json(f"{case_path}/metadata.json", metadata)
    
    # Init CoC
    coc = ChainLogger(f"{case_path}/chain_of_custody.log")
    coc.log("CASE_CREATED", operator, metadata)
    
    # Init database
    db = sqlite3.connect(f"{case_path}/case.db")
    db.execute("CREATE TABLE evidence (...)")
    db.execute("CREATE TABLE artifacts (...)")
    
    self.current_case = metadata
    self._update_display()
```

#### 2. Load Case Button
```python
def _on_load_case(self):
    case_dir = QFileDialog.getExistingDirectory()
    
    # Load metadata
    metadata = json.load(f"{case_dir}/metadata.json")
    
    # Verify CoC
    coc = ChainLogger(f"{case_dir}/chain_of_custody.log")
    if not coc.verify_chain():
        QMessageBox.critical("⚠️ CoC BROKEN - QUARANTINE MODE")
        metadata['status'] = "QUARANTINE"
    
    self.current_case = metadata
    self._update_display()
    self._load_coc_table()
```

#### 3. Seal Case Button
```python
def _on_seal_case(self):
    confirm = QMessageBox.question("⚠️ SEAL? Cannot undo!")
    if not confirm:
        return
    
    # Update metadata
    self.current_case['status'] = "SEALED"
    write_json(metadata_file, self.current_case)
    
    # Final CoC entry
    coc.log("CASE_SEALED", operator, {"case_id": case_id})
    
    # Make CoC read-only
    chmod(coc_file, 0o444)
    
    self._update_display()
```

#### 4. Export Case Button
```python
def _on_export_case(self):
    export_path = QFileDialog.getSaveFileName("Export.zip")
    
    # ZIP entire case folder
    shutil.make_archive(export_path, 'zip', case_path)
    
    # Hash export
    export_hash = sha256(export_path)
    
    # Log to CoC
    coc.log("CASE_EXPORTED", operator, {
        "path": export_path,
        "hash": export_hash
    })
```

#### 5. Verify CoC Button
```python
def _on_verify_coc(self):
    is_valid = coc.verify_chain()
    
    if is_valid:
        QMessageBox.info("✔️ CoC VERIFIED")
        self.lbl_coc_status.setText("✔️ VERIFIED")
        self.lbl_coc_status.setStyleSheet("color: green")
    else:
        QMessageBox.critical("⛔ CoC BROKEN!")
        self.lbl_coc_status.setText("⛔ BROKEN")
        self.lbl_coc_status.setStyleSheet("color: red")
```

---

## 💿 TAB 2: IMAGE INGEST TAB

### Purpose
Accept E01/DD/RAW/Memory evidence, verify integrity, build VEOS.

### UI Components
```
┌─────────────────────────────────────────────────┐
│ Evidence Selection                              │
├─────────────────────────────────────────────────┤
│ ☑ Multi-part image (E01/E02...)                │
│                                                 │
│ Files:                                          │
│   LoneWolf.E01   [Browse]                       │
│   LoneWolf.E02                                  │
│   ...                                           │
│   LoneWolf.E09                                  │
│   memdump.mem                                   │
│                                                 │
│ [Validate] [Hash] [Mount] [Build VEOS]         │
└─────────────────────────────────────────────────┘

Progress:
✔ Segments OK
✔ Hashing 9.2GB / 40GB
✔ Partitions: NTFS (C:), FAT32 (D:)
✔ Memory Profile: Win10x64
✔ VEOS Ready
```

### Click Logic

#### 1. Select Evidence Button
```python
def _on_select_evidence(self):
    files = QFileDialog.getOpenFileNames(
        filter="Evidence (*.E01 *.dd *.raw *.mem)"
    )
    
    if self.chk_multipart.isChecked():
        # Validate series
        validate_segments(files)  # Must be E01→E09
    
    self.evidence_files = files
    self._display_file_list()
```

#### 2. Validate Button
```python
def _on_validate(self):
    if multipart:
        parts = sort_by_suffix(files)
        for i, f in enumerate(parts, 1):
            if not f.endswith(f".E{str(i).zfill(2)}"):
                QMessageBox.critical("Missing E{i:02d}")
                return
    
    QMessageBox.info("✔ Validation passed")
```

#### 3. Hash Button
```python
def _on_hash(self):
    for file in self.evidence_files:
        md5 = compute_hash(file, 'md5')
        sha256 = compute_hash(file, 'sha256')
        
        self._add_to_manifest(file, md5, sha256)
        self._update_progress()
    
    # Save manifest
    manifest = {
        "files": self.file_hashes,
        "timestamp": now()
    }
    write_json(f"{case_path}/evidence/manifest.json", manifest)
    
    # Log to CoC
    coc.log("EVIDENCE_IMPORTED", operator, manifest)
```

#### 4. Mount Button
```python
def _on_mount(self):
    # Disk images
    if is_disk_image(files):
        image = ImageHandler.open(files)  # pytsk3
        partitions = image.list_partitions()
        
        for part in partitions:
            self._add_partition_info(part)
    
    # Memory
    if is_memory(files):
        mem = MemoryHandler.open(files[0])
        profile = mem.detect_profile()  # Win10x64
        
        self._show_memory_profile(profile)
```

#### 5. Build VEOS Button
```python
def _on_build_veos(self):
    veos = VirtualEvidenceOS()
    
    # Mount disk
    if disk_image:
        veos.mount_disk(image, partitions)
        # Creates: /Disk0/C:/, /Disk0/D:/
    
    # Mount memory
    if memory:
        veos.mount_memory(mem)
        # Creates: /Memory/Processes, /Memory/Network
    
    # Save VEOS index
    veos.save(f"{case_path}/veos.index")
    
    # Signal other tabs
    self.veos_ready.emit(veos)
    
    QMessageBox.info("✔ VEOS Ready - Files tab enabled")
```

---

## 🗂️ TAB 3: FILES TAB

### Purpose
Virtual file manager showing evidence-native paths ONLY.

### UI Components
```
┌─────────────────────────────────────────────────┐
│ [←] [→] C:\Users\Alice\Desktop         [Search]│
├──────────────┬──────────────────────────────────┤
│ Tree         │ Name      Size      Modified     │
│              ├──────────────────────────────────┤
│ ▸ This PC    │ note.txt  1.2KB     2015-03-09   │
│   ▸ C:       │ malware.exe 45KB    2015-03-09   │
│     ▸ Users  │ backup.zip  3.1MB   2015-03-08   │
│       ▾ Alice│                                   │
│         Desktop                                  │
│         Documents                                │
│         Downloads                                │
└──────────────┴──────────────────────────────────┘
```

### Click Logic

#### 1. Double-click Folder
```python
def on_folder_double_click(self, item):
    path = item.data(Qt.UserRole)  # Evidence path
    
    # Get from VEOS (NOT filesystem!)
    files = veos.list_directory(path)
    
    # Update table
    self.file_table.setRowCount(0)
    for file in files:
        row = self.file_table.rowCount()
        self.file_table.insertRow(row)
        
        # DISPLAY evidence path ONLY
        self.file_table.setItem(row, 0, QTableWidgetItem(file.name))
        self.file_table.setItem(row, 1, QTableWidgetItem(format_size(file.size)))
        self.file_table.setItem(row, 2, QTableWidgetItem(file.modified))
        
        # Store VEOS file object (hidden)
        self.file_table.item(row, 0).setData(Qt.UserRole, file)
    
    # Update breadcrumb
    self.breadcrumb.setText(path)  # C:\Users\Alice\Desktop
```

#### 2. Double-click File
```python
def on_file_double_click(self, item):
    veos_file = item.data(Qt.UserRole)
    path = veos_file.display_path
    
    ext = path.split('.')[-1].lower()
    
    # Route to preview
    if ext in ['txt', 'log', 'csv']:
        content = veos.read_file(path)
        self._show_text_preview(content)
    
    elif ext in ['png', 'jpg', 'jpeg']:
        content = veos.read_file(path)
        self._show_image_preview(content)
    
    elif ext == 'evtx':
        content = veos.read_file(path)
        self._show_evtx_table(parse_evtx(content))
    
    else:
        content = veos.read_file(path, max_bytes=4096)
        self._show_hex_view(content)
```

#### 3. Right-click Context Menu
```python
def on_right_click(self, event):
    item = self.file_table.itemAt(event.pos())
    veos_file = item.data(Qt.UserRole)
    
    menu = QMenu()
    menu.addAction("📄 Open", lambda: self._preview(veos_file))
    menu.addAction("🔍 Hex View", lambda: self._hex_view(veos_file))
    menu.addAction("📝 Strings", lambda: self._extract_strings(veos_file))
    menu.addAction("🔐 Hash", lambda: self._show_hash(veos_file))
    menu.addAction("💻 Open Terminal Here", lambda: self._open_terminal(veos_file.display_path))
    menu.addAction("📋 Copy Path", lambda: self._copy_path(veos_file.display_path))
    
    menu.exec(event.globalPos())
```

#### 4. Blocked Actions
```python
def on_delete_attempt(self):
    QMessageBox.critical(
        "⛔ FORENSIC BLOCK",
        "This action would MODIFY evidence.\n"
        "File deletion is BLOCKED.\n"
        "Evidence integrity preserved."
    )
    
    # Log to CoC
    coc.log("WRITE_BLOCKED", operator, {
        "action": "delete",
        "path": file.display_path
    })
```

---

## 🧬 TAB 4: ARTIFACTS TAB

### Purpose
Discover and extract forensic artifacts from VEOS.

### UI Components
```
┌──────────────┬──────────────────────────────────┐
│ Types        │ Items                            │
├──────────────┼──────────────────────────────────┤
│ ▾ Windows(12)│ System.evtx         2.1MB        │
│   EVTX (4)   │ Security.evtx       5.4MB        │
│   Registry(5)│ Application.evtx    1.8MB        │
│   Prefetch(3)│ Setup.evtx          850KB        │
│ ▸ Browser(3) │                                   │
│ ▸ Memory(1)  │ [Scan] [Extract] [Extract All]   │
└──────────────┴──────────────────────────────────┘

Status: 12 artifacts found, 4.2GB total
```

### Click Logic

#### 1. Scan Evidence Button
```python
def _on_scan(self):
    artifacts = []
    
    # Walk VEOS filesystem
    for path in veos.walk("/"):
        # EVTX
        if path.endswith('.evtx'):
            artifacts.append({
                'type': 'EVTX',
                'source_path': path,
                'size': veos.stat(path).size
            })
        
        # Registry
        if 'NTUSER.DAT' in path or 'SAM' in path:
            artifacts.append({
                'type': 'REGISTRY',
                'source_path': path,
                'size': veos.stat(path).size
            })
        
        # Prefetch
        if path.endswith('.pf'):
            artifacts.append({
                'type': 'PREFETCH',
                'source_path': path,
                'size': veos.stat(path).size
            })
    
    # Populate UI
    self._populate_artifact_tree(artifacts)
    
    self.lbl_status.setText(f"{len(artifacts)} artifacts found")
```

#### 2. Extract Selected Button
```python
def _on_extract_selected(self):
    selected = self.artifact_table.selectedItems()
    
    for item in selected:
        artifact = item.data(Qt.UserRole)
        
        # Read from VEOS
        content = veos.read_file(artifact['source_path'])
        
        # Write to case artifacts
        dest = f"{case_path}/artifacts/{artifact['type']}/{hash(content)}"
        write_file(dest, content)
        
        # Update artifact DB
        db.execute("INSERT INTO artifacts (...) VALUES (...)")
        
        # Log to CoC
        coc.log("ARTIFACT_EXTRACTED", operator, {
            "type": artifact['type'],
            "src": artifact['source_path'],
            "dst": dest,
            "hash": sha256(content)
        })
    
    QMessageBox.info(f"✔ Extracted {len(selected)} artifacts")
```

#### 3. Double-click Artifact
```python
def on_artifact_double_click(self, item):
    artifact = item.data(Qt.UserRole)
    
    # Jump to Files tab at this path
    self.files_tab.navigate_to(artifact['source_path'])
    self.main_window.tabs.setCurrentIndex(TAB_FILES)
```

---

## 🤖 TAB 5: ANALYSIS TAB

### Purpose
Correlate events, run ML, detect attack chains.

### UI Components
```
┌─────────────────────────────────────────────────┐
│ [Run Analysis] [Correlate] [Rebuild Timeline]  │
├────────────────────┬────────────────────────────┤
│ Findings           │ Details                    │
├────────────────────┼────────────────────────────┤
│ 🔴 Lateral Move    │ Evidence Summary:          │
│ 🟠 Suspicious Login│ - Source: EVTX             │
│ 🟡 Persistence Key │ - Time: 02:14 AM           │
│ 🟢 Normal Boot     │ - User: Alice              │
│                    │ - Score: 0.92              │
│                    │                            │
│                    │ Why Flagged:               │
│                    │ • Rare execution time      │
│                    │ • Unknown process          │
│                    │ • Registry persistence     │
└────────────────────┴────────────────────────────┘
```

### Click Logic

#### 1. Run Analysis Button
```python
def _on_run_analysis(self):
    # Get normalized events
    events = load_events_from_artifacts()
    
    # Run rule engine
    rule_findings = RuleEngine.analyze(events)
    
    # Run ML
    ml_results = MLEngine.analyze(events)
    
    # Run UEBA
    ueba_results = UEBA.analyze(events)
    
    # Merge findings
    findings = merge(rule_findings, ml_results, ueba_results)
    
    # Populate findings table
    self._populate_findings(findings)
    
    self.lbl_stats.setText(f"{len(findings)} findings")
```

#### 2. Double-click Finding
```python
def on_finding_double_click(self, item):
    finding = item.data(Qt.UserRole)
    
    # Show details panel
    details = f"""
╔═══════════════════════════════════════════╗
║  FINDING DETAILS                          ║
╠═══════════════════════════════════════════╣

📅 Time:    {finding['timestamp']}
👤 User:    {finding['user']}
⚡ Action:  {finding['action']}
📁 Object:  {finding['object']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 ANOMALY SCORE: {finding['score']:.3f}
🎯 SEVERITY:      {finding['severity']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 WHY THIS IS FLAGGED:
"""
    
    for reason in finding['reasons']:
        details += f"\n  • {reason}"
    
    self.details_panel.setText(details)
```

#### 3. Correlate Button
```python
def _on_correlate(self):
    # Build event chains
    chains = []
    
    for ev1 in events:
        for ev2 in events:
            # Same user within 120s
            if (ev1.user == ev2.user and 
                abs(ev1.ts - ev2.ts) < 120):
                
                link(ev1, ev2)
    
    # Find attack chains
    attack_chains = find_chains_matching([
        "Login → FileCreate → RegistryPersist → NetworkConnect"
    ])
    
    # Display
    self._show_attack_chains(attack_chains)
```

---

## 📄 TAB 6: REPORTS TAB

### Purpose
Generate court-ready forensic reports.

### UI Components
```
┌─────────────────────────────────────────────────┐
│ Report Builder                                  │
│ [Add Section] [Preview] [Generate] [Export]    │
├────────────────┬────────────────────────────────┤
│ Sections       │ Preview                        │
├────────────────┼────────────────────────────────┤
│ ☑ Executive    │  Forensic Case Report          │
│ ☑ Evidence     │  ─────────────────────         │
│ ☑ Timeline     │  Case: LoneWolf                │
│ ☑ Findings     │  Investigator: Darshan         │
│ ☑ ML Results   │  Date: 2026-01-27              │
│ ☑ Chain of     │                                │
│   Custody      │  [Rendered Preview]            │
│ ☑ Appendices   │                                │
└────────────────┴────────────────────────────────┘

Export: [PDF] [HTML] [DOCX] [JSON]
```

### Click Logic

#### 1. Generate Button
```python
def _on_generate(self):
    # Collect selected sections
    sections = []
    
    if self.chk_executive.isChecked():
        sections.append(render_executive_summary(case))
    
    if self.chk_evidence.isChecked():
        sections.append(render_evidence_inventory(case))
    
    if self.chk_timeline.isChecked():
        sections.append(render_timeline_highlights(timeline))
    
    if self.chk_findings.isChecked():
        sections.append(render_findings(analysis_results))
    
    if self.chk_ml.isChecked():
        sections.append(render_ml_results(ml_results))
    
    if self.chk_coc.isChecked():
        sections.append(render_coc(coc_log))
    
    # Merge into document
    report = Report(sections)
    
    # Preview
    self.preview_panel.setHtml(report.to_html())
```

#### 2. Export PDF Button
```python
def _on_export_pdf(self):
    path = QFileDialog.getSaveFileName("Report.pdf")
    
    # Render to PDF
    report.to_pdf(path)
    
    # Hash
    report_hash = sha256(path)
    
    # Log to CoC
    coc.log("REPORT_EXPORTED", operator, {
        "format": "PDF",
        "path": path,
        "hash": report_hash
    })
    
    QMessageBox.info(f"✔ Report exported\n{path}")
```

---

## 💻 FEPD TERMINAL

### Prompt Format
```
fepd:corp-leak[Alice]$ 
```

### Click Logic

#### User Types Command
```python
def execute_command(self, cmd_line):
    parts = cmd_line.split()
    cmd = parts[0]
    args = parts[1:]
    
    # Check if blocked
    if cmd in BLOCKED_COMMANDS:
        return self._show_blocked(cmd)
    
    # Route to handler
    if cmd == "dir" or cmd == "ls":
        return self._cmd_dir(args)
    elif cmd == "cd":
        return self._cmd_cd(args)
    elif cmd == "type" or cmd == "cat":
        return self._cmd_type(args)
    elif cmd == "hash":
        return self._cmd_hash(args)
    else:
        return f"'{cmd}' not recognized"

def _show_blocked(self, cmd):
    return """
⛔ FORENSIC BLOCK
──────────────────────────────────
Command: {cmd}
Reason: Would modify evidence
Status: BLOCKED - Evidence preserved
"""

def _cmd_dir(self, args):
    path = args[0] if args else self.cwd
    files = veos.list_directory(path)
    
    output = f"Directory of {path}\n\n"
    for f in files:
        output += f"{f.name:30} {f.size:>10}\n"
    return output
```

---

This gives you complete **small logic segments** for all tabs with **exact click handlers** and **evidence-native path enforcement**.

Each tab is now a pure forensic component that never touches analyst machine paths!

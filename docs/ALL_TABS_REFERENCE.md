# 🎯 FEPD All Tabs - Complete Quick Reference

## 📋 All Tabs at a Glance

| # | Tab | Icon | Main Function | Key Response |
|---|-----|------|---------------|--------------|
| 1 | **Case** | 📋 | Create/load/seal case | CoC ledger |
| 2 | **Ingest** | 💿 | Import E01/DD/Memory | Build VEOS |
| 3 | **Files** | 🗂️ | Evidence file explorer | Preview/navigate |
| 4 | **Artifacts** | 🧬 | Discover & extract | Scan→Extract |
| 5 | **Analysis** | 🤖 | ML + Correlation | Score + Explain |
| 6 | **Reports** | 📄 | Generate PDF/HTML | Export report |
| 7 | **Terminal** | 💻 | Evidence CMD | Execute commands |

---

## 🗂️ TAB 1: CASE - Full Logic

### Create Case Click
```python
def _on_create_case():
    # 1. Get metadata from dialog
    case_id = uuid4()
    case_name = dialog.get_name()
    operator = dialog.get_operator()
    
    # 2. Create structure
    mkdir(f"cases/{case_id}/evidence")
    mkdir(f"cases/{case_id}/artifacts")
    mkdir(f"cases/{case_id}/reports")
    
    # 3. Write metadata.json
    metadata = {
        "case_id": case_id,
        "name": case_name,
        "operator": operator,
        "created_at": now(),
        "status": "OPEN"
    }
    write_json(f"cases/{case_id}/metadata.json", metadata)
    
    # 4. Init CoC
    coc = ChainLogger(f"cases/{case_id}/chain_of_custody.log")
    coc.log("CASE_CREATED", operator, metadata)
    
    # 5. Init DB
    db = sqlite3.connect(f"cases/{case_id}/case.db")
    db.execute("CREATE TABLE evidence (...)")
    
    # 6. Update UI
    self.current_case = metadata
    self._update_display()
```

### Load Case Click
```python
def _on_load_case():
    # 1. Select directory
    case_dir = QFileDialog.getExistingDirectory()
    
    # 2. Load metadata
    metadata = json.load(f"{case_dir}/metadata.json")
    
    # 3. Verify CoC
    coc = ChainLogger(f"{case_dir}/chain_of_custody.log")
    if not coc.verify_chain():
        metadata['status'] = "QUARANTINE"
        QMessageBox.critical("⚠️ CoC BROKEN")
    
    # 4. Update UI
    self.current_case = metadata
    self._load_coc_table()
```

### Seal Case Click
```python
def _on_seal_case():
    # 1. Confirm
    if not QMessageBox.question("⚠️ SEAL? Cannot undo!"):
        return
    
    # 2. Update metadata
    self.current_case['status'] = "SEALED"
    write_json(metadata_file, self.current_case)
    
    # 3. Final CoC entry
    coc.log("CASE_SEALED", operator, {"case_id": case_id})
    
    # 4. Make read-only
    chmod(coc_file, 0o444)
```

---

## 💿 TAB 2: INGEST - Full Logic

### Select Evidence Click
```python
def _on_select_evidence():
    files = QFileDialog.getOpenFileNames(
        filter="Evidence (*.E01 *.dd *.raw *.mem)"
    )
    
    if self.chk_multipart.isChecked():
        validate_segments(files)  # E01→E09
    
    self.evidence_files = files
```

### Validate Click
```python
def _on_validate():
    parts = sort_by_suffix(files)
    for i, f in enumerate(parts, 1):
        if not f.endswith(f".E{str(i).zfill(2)}"):
            QMessageBox.critical(f"Missing E{i:02d}")
            return
    
    QMessageBox.info("✔ Validation passed")
```

### Hash Click
```python
def _on_hash():
    manifest = {"files": []}
    
    for file in self.evidence_files:
        md5 = hash_file(file, 'md5')
        sha256 = hash_file(file, 'sha256')
        
        manifest['files'].append({
            "path": file,
            "md5": md5,
            "sha256": sha256
        })
    
    write_json(f"{case_path}/evidence/manifest.json", manifest)
    coc.log("EVIDENCE_IMPORTED", operator, manifest)
```

### Build VEOS Click
```python
def _on_build_veos():
    veos = VirtualEvidenceOS()
    
    # Mount disk
    if is_disk(files):
        image = ImageHandler.open(files)  # pytsk3
        partitions = image.list_partitions()
        veos.mount_disk(image, partitions)
        # Creates: /Disk0/C:/, /Disk0/D:/
    
    # Mount memory
    if is_memory(files):
        mem = MemoryHandler.open(files[0])
        veos.mount_memory(mem)
        # Creates: /Memory/Processes, /Memory/Network
    
    # Save index
    veos.save(f"{case_path}/veos.index")
    
    # Enable Files tab
    self.veos_ready.emit(veos)
```

---

## 🗂️ TAB 3: FILES - Full Logic

### Double-click Folder
```python
def on_folder_double_click(item):
    path = item.data(Qt.UserRole)  # Evidence path
    
    # Get from VEOS (NOT filesystem!)
    files = veos.list_directory(path)
    
    # Update table
    table.setRowCount(0)
    for file in files:
        table.addRow([
            file.name,
            format_size(file.size),
            file.modified
        ])
        # Store VEOSFile object
        table.item(row, 0).setData(Qt.UserRole, file)
    
    # Update breadcrumb
    breadcrumb.setText(path)  # C:\Users\Alice\Desktop
```

### Double-click File
```python
def on_file_double_click(item):
    veos_file = item.data(Qt.UserRole)
    path = veos_file.display_path
    ext = path.split('.')[-1].lower()
    
    # Route to preview
    if ext in ['txt', 'log']:
        content = veos.read_file(path)
        show_text_preview(content.decode('utf-8'))
    
    elif ext in ['png', 'jpg']:
        content = veos.read_file(path)
        show_image_preview(Image.open(BytesIO(content)))
    
    elif ext == 'evtx':
        content = veos.read_file(path)
        show_evtx_table(parse_evtx(content))
    
    else:
        content = veos.read_file(path, max_bytes=4096)
        show_hex_view(content)
```

### Right-click Context Menu
```python
def on_right_click(event):
    item = table.itemAt(event.pos())
    file = item.data(Qt.UserRole)
    
    menu = QMenu()
    menu.addAction("📄 Open", lambda: preview(file))
    menu.addAction("🔍 Hex", lambda: hex_view(file))
    menu.addAction("🔐 Hash", lambda: show_hash(file))
    menu.addAction("💻 Terminal", lambda: open_terminal_at(file.display_path))
    menu.addAction("📋 Copy Path", lambda: clipboard.setText(file.display_path))
    
    menu.exec(event.globalPos())
```

### Delete Blocked
```python
def on_delete_attempt():
    QMessageBox.critical(
        "⛔ FORENSIC BLOCK",
        "Deletion would modify evidence"
    )
    coc.log("WRITE_BLOCKED", operator, {"action": "delete"})
```

---

## 🧬 TAB 4: ARTIFACTS - Full Logic

### Scan Evidence Click
```python
def _on_scan():
    artifacts = []
    
    # Walk VEOS
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
    
    # Populate tree
    self._populate_tree(artifacts)
    self.lbl_status.setText(f"{len(artifacts)} artifacts found")
```

### Extract Selected Click
```python
def _on_extract_selected():
    selected = artifact_table.selectedItems()
    
    for item in selected:
        artifact = item.data(Qt.UserRole)
        
        # Read from VEOS
        content = veos.read_file(artifact['source_path'])
        
        # Write to artifacts/
        dest = f"{case_path}/artifacts/{artifact['type']}/{sha256(content)}"
        write_file(dest, content)
        
        # Update DB
        db.execute("INSERT INTO artifacts VALUES (...)")
        
        # Log CoC
        coc.log("ARTIFACT_EXTRACTED", operator, {
            "type": artifact['type'],
            "src": artifact['source_path'],
            "dst": dest,
            "hash": sha256(content)
        })
```

---

## 🤖 TAB 5: ANALYSIS - Full Logic

### Run Analysis Click
```python
def _on_run_analysis():
    # Load normalized events
    events = load_from_artifacts()
    
    # Run engines
    rule_findings = RuleEngine.analyze(events)
    ml_results = MLEngine.analyze(events)
    ueba_results = UEBA.analyze(events)
    
    # Merge
    findings = merge(rule_findings, ml_results, ueba_results)
    
    # Populate table
    for finding in findings:
        table.addRow([
            finding['timestamp'],
            finding['user'],
            finding['action'],
            f"{finding['score']:.3f}",
            finding['severity']
        ])
```

### Double-click Finding
```python
def on_finding_double_click(item):
    finding = item.data(Qt.UserRole)
    
    details = f"""
╔═══════════════════════════════════════════╗
║  FINDING DETAILS                          ║
╠═══════════════════════════════════════════╣

📅 Time:    {finding['timestamp']}
👤 User:    {finding['user']}
⚡ Action:  {finding['action']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 SCORE:    {finding['score']:.3f}
🎯 SEVERITY: {finding['severity']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 WHY FLAGGED:
"""
    
    for reason in finding['reasons']:
        details += f"\n  • {reason}"
    
    details_panel.setText(details)
```

---

## 📄 TAB 6: REPORTS - Full Logic

### Generate Report Click
```python
def _on_generate():
    sections = []
    
    if chk_executive.isChecked():
        sections.append(render_executive(case))
    
    if chk_evidence.isChecked():
        sections.append(render_evidence_inventory())
    
    if chk_timeline.isChecked():
        sections.append(render_timeline(events))
    
    if chk_findings.isChecked():
        sections.append(render_findings(analysis_results))
    
    if chk_coc.isChecked():
        sections.append(render_coc(coc_log))
    
    # Merge
    report = Report(sections)
    
    # Preview
    preview_panel.setHtml(report.to_html())
```

### Export PDF Click
```python
def _on_export_pdf():
    path = QFileDialog.getSaveFileName("Report.pdf")
    
    # Render
    report.to_pdf(path)
    
    # Hash
    report_hash = sha256_file(path)
    
    # Log CoC
    coc.log("REPORT_EXPORTED", operator, {
        "format": "PDF",
        "path": path,
        "hash": report_hash
    })
    
    QMessageBox.info(f"✔ Exported\n{path}")
```

---

## 💻 TERMINAL - Full Logic

### Execute Command
```python
def execute_command(cmd_line):
    cmd, *args = cmd_line.split()
    
    # Check if blocked
    if cmd in ['del', 'rm', 'copy', 'move']:
        return """
⛔ FORENSIC BLOCK
──────────────────────────────────
Command: {cmd}
Reason: Would modify evidence
Status: BLOCKED
"""
    
    # Route to handler
    if cmd in ['dir', 'ls']:
        path = args[0] if args else cwd
        files = veos.list_directory(path)
        
        output = f"Directory of {path}\n\n"
        for f in files:
            output += f"{f.name:30} {f.size:>10}\n"
        return output
    
    elif cmd in ['type', 'cat']:
        content = veos.read_file(args[0])
        return content.decode('utf-8', errors='replace')
    
    elif cmd == 'hash':
        hashes = veos.get_file_hashes(args[0])
        return f"""
MD5:    {hashes['md5']}
SHA1:   {hashes['sha1']}
SHA256: {hashes['sha256']}
"""
```

---

## 🔗 Complete Data Flow

```
┌─────────────┐
│  CASE TAB   │  Creates case structure + CoC
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ INGEST TAB  │  Imports evidence → Builds VEOS
└──────┬──────┘
       │
       ├──────────────────┐
       ▼                  ▼
┌─────────────┐    ┌─────────────┐
│  FILES TAB  │    │TERMINAL TAB │  Both read from VEOS
└──────┬──────┘    └─────────────┘
       │
       ▼
┌─────────────┐
│ARTIFACTS TAB│  Scans VEOS → Extracts
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ANALYSIS TAB │  Runs ML + Rules + UEBA
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ REPORTS TAB │  Generates PDF/HTML
└─────────────┘

All tabs log to → Chain of Custody
```

---

## ✅ Implementation Checklist

- [x] Case Tab with Create/Load/Seal/Export
- [x] CoC verification logic
- [x] VEOS core (veos.py)
- [x] Evidence CMD (evidence_cmd.py)
- [x] Forensic ML with explanations (forensic_ml_engine.py)
- [x] Investigative visualizations
- [x] Integration orchestrator
- [x] Complete documentation

---

**You now have COMPLETE tab logic in small segments! 🎯**

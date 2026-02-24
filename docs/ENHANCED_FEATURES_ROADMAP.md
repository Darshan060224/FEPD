# FEPD Enhanced Features Implementation Roadmap
## Comprehensive Upgrade to Enterprise Forensics Platform

**Date:** November 7, 2025  
**Status:** Phase 1 Complete (ML/UEBA/TI Core Modules)  
**Remaining:** Visualization, Platform Support, Performance, Compliance

---

## Executive Summary

This document tracks the implementation of advanced features transforming FEPD into an enterprise-grade forensic platform with:

- **Machine Learning** anomaly detection
- **UEBA** user behavior profiling
- **Threat Intelligence** integration
- **Advanced Visualizations** (timeline graphs, heatmaps, relationship graphs)
- **Multi-Platform Support** (macOS, Linux, Mobile)
- **Performance Enhancements** (parallel processing, out-of-core analytics)
- **Compliance Features** (multilingual, transparent rules, configurable templates)

---

## Phase 1: Advanced Analytics (✅ COMPLETE)

### 1.1 ML-Driven Anomaly Detection ✅
**File:** `src/ml/ml_anomaly_detector.py` (850 lines)

**Implemented:**
- `EventEncoder`: Feature extraction from forensic events
  - Temporal features (hour, day-of-week, time deltas)
  - Categorical encoding (event types, sources)
  - Severity levels
- `AutoencoderAnomalyDetector`: Neural network-based detection
  - Architecture: Input → Dense(32) → Dense(16) → Dense(8) → Decoder
  - Trains on benign events
  - Reconstruction error scoring
  - 95th percentile threshold
- `ClusteringAnomalyDetector`: Multi-algorithm approach
  - K-means clustering
  - DBSCAN density-based outliers
  - Isolation Forest
  - Combined anomaly scoring
- `ClockSkewDetector`: Timestamp tampering detection
  - Linear drift detection (clock running fast/slow)
  - Time jump detection (sudden changes)
  - Reverse chronology detection
  - Statistical outlier gaps (IQR and Z-score methods)
- `MLAnomalyDetectionEngine`: Main orchestrator
  - Combined anomaly scoring
  - Model persistence (save/load)
  - Anomaly reporting

**Dependencies:**
- scikit-learn (clustering, preprocessing, isolation forest)
- tensorflow/keras (autoencoder neural network)
- numpy, pandas

**Usage:**
```python
from src.ml import MLAnomalyDetectionEngine

engine = MLAnomalyDetectionEngine()
engine.train(benign_events_df)  # Train on known-good data
results = engine.detect_anomalies(test_events_df)  # Score new events
report = engine.get_anomaly_report(results)
```

**Detected Patterns:**
- Unusual event timing (off-hours activity)
- Rare event types
- Anomalous event sequences
- Clock-skew attacks (scholarworks.uno.edu reference)

---

### 1.2 UEBA User Behavior Profiling ✅
**File:** `src/ml/ueba_profiler.py` (650 lines)

**Implemented:**
- `UserBehaviorProfile`: Individual user baseline
  - Login patterns (hour/day distribution)
  - Process execution history
  - File access patterns
  - Network destinations
  - Session characteristics
  - Deviation scoring
- `UEBAProfiler`: Main UEBA engine
  - Multi-user profile management
  - Entity profiling (machines, services)
  - Anomaly detection
  - Insider threat detection
  - Account takeover detection
  - High-risk user identification

**Detection Capabilities:**
- **Insider Threats:**
  - Mass file access/exfiltration (>100 files)
  - Privilege escalation attempts
  - After-hours data access (10pm-6am)
  - Lateral movement (new network destinations)
- **Account Takeover:**
  - Login from new locations
  - Unusual tool usage
  - Activity spikes (2x+ normal)
  - Different access patterns

**Usage:**
```python
from src.ml import UEBAProfiler

profiler = UEBAProfiler()
profiler.build_profiles(historical_events)  # Build baselines
results = profiler.detect_anomalies(new_events)  # Score deviations
threats = profiler.detect_insider_threats(events)
takeovers = profiler.detect_account_takeover(events)
```

**Behavioral Metrics:**
- Login hour/day distributions
- Typical processes per user
- File access baselines
- Network activity patterns
- Deviation scores (0-1)

---

### 1.3 Threat Intelligence Integration ✅
**File:** `src/ml/threat_intel.py` (750 lines)

**Implemented:**
- `HashDatabase`: Malicious hash lookups
  - Local JSON database
  - VirusTotal API integration (optional)
  - MalwareBazaar support
- `YARAScanner`: Pattern-based file scanning
  - Loads .yar rule files
  - File and data scanning
  - Rule metadata extraction
- `SigmaRuleEngine`: SIEM-style event detection
  - YAML rule loading
  - Event pattern matching
  - Wildcard and regex support
- `DomainReputationChecker`: URL/IP blacklisting
  - Domain and subdomain matching
  - IP address checks
  - Local blacklist files
- `ThreatIntelligenceEngine`: Main TI orchestrator
  - File enrichment (hash + YARA)
  - Event enrichment (Sigma + reputation)
  - Batch artifact scanning
  - Summary reporting

**Intelligence Sources:**
- **Hash Databases:** Known malware signatures
- **YARA Rules:** Pattern-based malware detection
- **Sigma Rules:** Suspicious event patterns (SigmaHQ)
- **Domain Blacklists:** Malicious C2/phishing domains

**Usage:**
```python
from src.ml import ThreatIntelligenceEngine

engine = ThreatIntelligenceEngine()
engine.initialize()  # Load all TI sources

# Enrich file
file_result = engine.enrich_file(Path('/suspicious.exe'), sha256_hash)

# Enrich event
event_result = engine.enrich_event({'domain': 'evil.com', 'event_type': 'dns_query'})

# Batch scan
enriched = engine.scan_artifacts(artifact_list)
report = engine.get_summary_report(enriched)
```

**Findings:**
- Malicious hash matches
- YARA rule hits
- Sigma rule matches
- Blacklisted domains/IPs
- Threat scores (0-1)

---

## Phase 2: Advanced Visualizations (🔄 IN PROGRESS)

### 2.1 Interactive Timeline Graph
**Target:** `src/ui/visualizations/timeline_graph.py`

**Features to Implement:**
- Zoomable histogram of event density over time
- Activity burst detection (visual spikes)
- Click-through to event details
- Time range brushing (select windows)
- Export chart as PNG/SVG

**Technologies:**
- Matplotlib for static charts
- Plotly for interactive web-based charts
- PyQt6 integration (QWebEngineView for Plotly)

**Reference:** Belkasoft X timeline histograms

---

### 2.2 Time-Heatmap Calendar View
**Target:** `src/ui/visualizations/heatmap_view.py`

**Features to Implement:**
- 2D grid: hour-of-day (rows) × day-of-week (columns)
- Color intensity = event frequency
- Click cells to filter timeline
- Multiple event type layers
- Off-hours activity highlighting (red zones)

**Use Cases:**
- Detect 3am logins (odd patterns)
- Malware beacon timing (regular intervals)
- Weekend/holiday suspicious activity

**Reference:** Timesketch heatmaps (medium.com)

---

### 2.3 Event-Relationship Graph (Connections View)
**Target:** `src/ui/visualizations/connections_graph.py`

**Features to Implement:**
- Network graph of related artifacts
- Node types: users, files, IPs, processes, events
- Edge types: accessed, created, connected_to, executed
- Graph analytics: centrality, communities, shortest paths
- Interactive exploration (drag nodes, filter edges)
- Export to GraphML/GEXF

**Technologies:**
- NetworkX for graph analysis
- PyVis or Plotly for interactive visualization
- Force-directed layout algorithms

**Reference:** Magnet Axiom Connections Explorer

---

### 2.4 Timeline Enhancements
**Target:** `src/ui/timeline_tab.py` (enhancement)

**Features to Add:**
- **Time-Jump Indicators:** Visual gaps for idle periods >1 day
- **Advanced Filtering:**
  - Date range picker (calendar widget)
  - Time-of-day slider (0-23 hours)
  - Weekday checkboxes
  - Custom time windows
- **Graphical Brushing:** Select regions on timeline graph to filter table
- **Event Density Indicator:** Scrollbar with color-coded density

**Reference:** Timesketch time bubbles

---

## Phase 3: Platform Support Expansion (📋 PLANNED)

### 3.1 macOS Artifact Support
**Target:** `src/parsers/macos_parser.py`

**Artifacts to Parse:**
- `.bash_history` / `.zsh_history` - Shell command logs
- Unified Logs (`/var/db/diagnostics`) - System event logs
- Safari History (`~/Library/Safari/History.db`)
- Safari Downloads (`~/Library/Safari/Downloads.plist`)
- Keychain items (`security dump-keychain`)
- System plists (`/Library/Preferences/`)
- FSEvents (file system activity)
- Launch Agents/Daemons (`~/Library/LaunchAgents/`)
- Spotlight index (`/.Spotlight-V100/`)

**Parsing Logic:**
- SQLite databases (Safari)
- Binary plists (plutil conversion)
- Unified log format (native parsing)
- Keychain dumps (security command output)

**Timeline Events:**
- User logins (Console.app logs)
- App launches (LaunchServices)
- File access (FSEvents)
- Web browsing (Safari)
- Credential usage (Keychain)

**Reference:** Magnet Axiom macOS support

---

### 3.2 Linux Artifact Support
**Target:** `src/parsers/linux_parser.py`

**Artifacts to Parse:**
- `.bash_history` - User command history
- `/var/log/syslog` - System events
- `/var/log/auth.log` - Authentication events
- `/var/log/messages` - General messages
- `/var/log/secure` - Security logs (RHEL)
- Cron logs (`/var/log/cron`)
- Journal logs (`journalctl --output json`)
- APT/YUM logs (package installs)
- SSH logs (sshd entries)
- Firewall logs (iptables, ufw)

**Parsing Logic:**
- Line-by-line syslog parsing (regex)
- JSON-formatted journal logs
- Timestamp normalization (various formats)
- User/process extraction

**Timeline Events:**
- User logins (auth.log)
- Sudo usage (secure log)
- Package installations (apt/yum)
- Cron job executions
- SSH connections
- Process starts (syslog)

**Reference:** Autopsy Linux support

---

### 3.3 Mobile Artifact Support
**Target:** `src/parsers/mobile_parser.py`

**Android Artifacts:**
- SMS (`/data/data/com.android.providers.telephony/databases/mmssms.db`)
- Call Logs (`/data/data/com.android.providers.contacts/databases/calllog.db`)
- Contacts (`contacts2.db`)
- WhatsApp messages (`msgstore.db`)
- Chrome browsing (`History` database)
- App usage (UsageStatsService)
- Wi-Fi networks (`wpa_supplicant.conf`)
- Location data (Google Location History)

**iOS Artifacts:**
- SMS (`sms.db` in HomeDomain)
- Call History (`CallHistory.storedata`)
- Contacts (`AddressBook.sqlitedb`)
- Safari history (`History.db`)
- Photos (`PhotoData.sqlite`)
- Mail attachments
- Apple Maps (history)
- App usage (KnowledgeC.db)

**Parsing Logic:**
- SQLite database extraction
- Protobuf decoding (some Google data)
- Plist parsing
- Timestamp conversion (Mac absolute time, Unix)

**Timeline Events:**
- Text messages sent/received
- Phone calls
- App installations
- Location history
- Web browsing

**Reference:** Magnet Axiom mobile forensics

---

## Phase 4: Performance & Scalability (📋 PLANNED)

### 4.1 Parallel Processing
**Target:** `src/modules/pipeline.py` (refactor)

**Enhancements:**
- **Multiprocessing for CPU-bound tasks:**
  - Artifact parsing (EVTX, Registry, MFT) in parallel workers
  - File hashing with multiprocessing.Pool
  - YARA scanning across multiple files
- **Threading for I/O-bound tasks:**
  - Concurrent file extraction from disk images
  - Parallel database inserts (batch writes)
  - Simultaneous API calls (threat intelligence)
- **Progress Tracking:**
  - Shared queue for progress updates
  - Inter-process communication (IPC)
  - Real-time UI updates

**Technologies:**
- `multiprocessing` module (Python stdlib)
- `concurrent.futures.ThreadPoolExecutor`
- `multiprocessing.Queue` for progress

**Expected Speedup:**
- 4-8x on quad-core systems
- Linear scaling with CPU cores
- Reduced wait times for large cases

---

### 4.2 Out-of-Core Timeline Processing
**Target:** `src/modules/db_manager.py` (enhancement)

**Enhancements:**
- **Streaming Database Queries:**
  - Fetch events in chunks (LIMIT/OFFSET)
  - SQLite pagination with indexed queries
  - Generator-based iteration (yield rows)
- **Disk-Based Sorting:**
  - External sort for large result sets
  - Temporary sorted files
  - Merge-sort final results
- **Lazy Loading:**
  - Load only visible timeline rows
  - Virtual scrolling in UI (QTableView with proxy model)
  - On-demand detail fetching

**Technologies:**
- SQLite indexes (timestamp, event_type, case_id)
- `pandas.read_sql()` with chunksize
- PyQt6 `QAbstractItemModel` for lazy data

**Benefits:**
- Handle millions of events without RAM exhaustion
- Responsive UI even with huge timelines
- Reduced memory footprint (100MB vs 5GB)

**Reference:** Autopsy's timeline scalability issues (autopsy.com)

---

### 4.3 Fast Search Indexing
**Target:** `src/modules/search_engine.py` (new)

**Features:**
- **Full-Text Search:**
  - SQLite FTS5 indexes (already in schema)
  - Elasticsearch backend (optional)
  - Stemming and stop words
- **Optimized Queries:**
  - Covering indexes (avoid table lookups)
  - Query planning analysis
  - Prepared statements
- **Search Features:**
  - Keyword search across all text fields
  - Regex support
  - Fuzzy matching (Levenshtein distance)
  - Boolean operators (AND, OR, NOT)
  - Field-specific search (event_type:login)

**Technologies:**
- SQLite FTS5 (already created in schema)
- Optional: Elasticsearch for distributed search
- Whoosh (pure Python search engine)

**Performance:**
- Sub-second search on 10M+ events
- Instant autocomplete suggestions
- Highlighted matches in results

**Reference:** Timesketch Elasticsearch integration

---

### 4.4 Distributed Analysis (Future)
**Target:** `src/distributed/` (new module)

**Architecture:**
- **Coordinator Node:**
  - Splits work into tasks
  - Distributes to worker nodes
  - Aggregates results
- **Worker Nodes:**
  - Parse artifacts
  - Run ML models
  - Extract features
- **Shared Storage:**
  - Network file system (NFS, SMB)
  - Object storage (S3, MinIO)
  - Distributed database (PostgreSQL)

**Technologies:**
- Celery (task queue)
- Redis/RabbitMQ (message broker)
- Docker containers for workers
- Kubernetes orchestration (optional)

**Use Cases:**
- Large enterprise caseloads (100+ images)
- 24/7 processing clusters
- Cloud-based forensics (AWS, Azure)

**Note:** Out of scope for single-user workstation, but architecturally possible

---

## Phase 5: Compliance & Reporting (📋 PLANNED)

### 5.1 Multilingual UI & Reports
**Target:** `src/i18n/` (new module)

**Features:**
- **Translation System:**
  - Qt Linguist `.ts` files
  - JSON translation files
  - Language selection in settings
  - Dynamic UI text replacement
- **Supported Languages (Target):**
  - English (default)
  - Spanish
  - French
  - German
  - Japanese
  - Chinese (Simplified)
  - Arabic
  - Portuguese
- **Report Translation:**
  - Localized report templates
  - Translated field labels
  - Date/time formatting per locale
  - Number formatting (1,000 vs 1.000)

**Technologies:**
- PyQt6 `QTranslator`
- `babel` for i18n management
- Google Translate API (optional, for auto-translation)

**Workflow:**
1. Extract translatable strings: `pylupdate6`
2. Translate in Qt Linguist
3. Compile: `lrelease`
4. Load at runtime: `QApplication.installTranslator()`

**Reference:** Oxygen Forensics 55-language support

---

### 5.2 Transparent Rule Explanations
**Target:** `src/ui/artifacts_tab.py`, `src/modules/rule_engine.py` (enhancement)

**Features:**
- **Rule Metadata Display:**
  - Rule ID and name
  - Description (why it triggered)
  - Severity level
  - MITRE ATT&CK mapping
  - References (CVE, articles)
- **UI Enhancements:**
  - Tooltip on classification tags
  - Detail panel with rule info
  - Link to rule source (YAML file)
- **Report Integration:**
  - "Why This Matters" sections
  - Rule citations in findings
  - Chain of evidence linking

**Example:**
```
Classification: Suspicious PowerShell Execution
Rule: sigma_powershell_download_cradle
Description: Detects PowerShell commands that download and execute code from the internet
MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell)
Severity: High
Reference: https://attack.mitre.org/techniques/T1059/001/
Triggered Because: Event contains 'powershell.exe' AND 'DownloadString' AND 'IEX'
```

**Benefits:**
- Court-admissible documentation
- Peer review transparency
- Training for junior analysts
- Reduced false positive confusion

---

### 5.3 Configurable Report Templates
**Target:** `src/modules/template_manager.py` (new)

**Features:**
- **Template System:**
  - YAML-based template definitions
  - Section ordering and inclusion
  - Conditional sections (e.g., only if malware found)
  - Variable substitution
- **Pre-Built Templates:**
  - **Executive Summary:** High-level findings
  - **Technical Report:** Detailed analysis
  - **GDPR Compliance:** Data breach reporting
  - **ISO 27037:** Digital evidence handling
  - **Court Submission:** Legal-ready format
- **Template Editor UI:**
  - Drag-and-drop section reordering
  - Checkbox to enable/disable sections
  - Preview pane
  - Save custom templates

**Template Structure (YAML):**
```yaml
template:
  name: "Executive Summary"
  language: "en"
  sections:
    - id: "case_overview"
      title: "Case Overview"
      required: true
    - id: "key_findings"
      title: "Key Findings"
      required: true
    - id: "malware_analysis"
      title: "Malware Analysis"
      required: false
      condition: "malware_found"
    - id: "recommendations"
      title: "Recommendations"
      required: true
```

**Benefits:**
- Standardized reporting across organization
- Compliance with legal requirements
- Reduced report writing time
- Consistent formatting

---

## Implementation Priority

### Immediate (Next Sprint)
1. ✅ ML Anomaly Detection (DONE)
2. ✅ UEBA Profiling (DONE)
3. ✅ Threat Intelligence (DONE)
4. 🔄 Interactive Timeline Graph (IN PROGRESS)
5. 🔄 Time-Heatmap View (IN PROGRESS)

### Short-Term (2-4 weeks)
6. Event-Relationship Graph
7. Timeline Enhancements (filters, time-jumps)
8. macOS Parser
9. Linux Parser
10. Parallel Processing

### Medium-Term (1-2 months)
11. Mobile Parser (Android/iOS)
12. Out-of-Core Timeline
13. Fast Search Engine
14. Multilingual UI

### Long-Term (3+ months)
15. Transparent Rule Explanations
16. Configurable Templates
17. Distributed Analysis (optional)

---

## Dependencies to Install

### Core ML/Analytics
```bash
pip install scikit-learn>=1.3.0
pip install tensorflow>=2.15.0
pip install numpy>=1.24.0
pip install pandas>=2.0.0
```

### Threat Intelligence
```bash
pip install yara-python>=4.3.0
pip install pyyaml>=6.0
pip install requests>=2.31.0
```

### Visualizations
```bash
pip install matplotlib>=3.8.0
pip install plotly>=5.17.0
pip install networkx>=3.2
pip install pyvis>=0.3.2
```

### Platform Parsers
```bash
# macOS
pip install biplist>=1.0.3  # Binary plist parsing

# Linux
# (no additional deps, uses stdlib)

# Mobile
pip install protobuf>=4.25.0  # Android data structures
```

### Performance
```bash
# Already have multiprocessing (stdlib)
# Optional: Elasticsearch
pip install elasticsearch>=8.11.0
```

### i18n
```bash
pip install babel>=2.13.0
```

---

## Testing Strategy

### Unit Tests
- `tests/test_ml_anomaly.py` - Test anomaly detection models
- `tests/test_ueba.py` - Test behavior profiling
- `tests/test_threat_intel.py` - Test TI enrichment
- `tests/test_visualizations.py` - Test chart generation
- `tests/test_parsers.py` - Test macOS/Linux/Mobile parsers

### Integration Tests
- `tests/test_pipeline_parallel.py` - Test parallel processing
- `tests/test_timeline_large.py` - Test out-of-core with 1M+ events
- `tests/test_search_performance.py` - Test search speed

### Performance Benchmarks
- Parse 100 GB disk image
- Timeline with 10M events
- ML model training time
- Search response time

---

## Documentation Updates Needed

1. **FEPD_ARCHITECTURE.md** - Add ML/UEBA/TI layers
2. **USER_GUIDE.md** - New visualization features
3. **API_REFERENCE.md** - ML module APIs
4. **DEPLOYMENT.md** - Distributed setup (optional)
5. **CHANGELOG.md** - Version history

---

## Success Metrics

- ✅ **Anomaly Detection:** Detect clock-skew attacks, rare events
- ✅ **UEBA:** Flag insider threats, account takeover
- ✅ **Threat Intel:** Enrich with hash/YARA/Sigma matches
- 🎯 **Performance:** 4x speedup with parallel processing
- 🎯 **Scalability:** Handle 10M+ events without RAM issues
- 🎯 **Platform Coverage:** Windows, macOS, Linux, Mobile
- 🎯 **Visualization:** Interactive graphs, heatmaps, relationships
- 🎯 **Compliance:** Multilingual, transparent, customizable reports

---

## Next Steps

1. **Complete Visualization Module:**
   - Finish `timeline_graph.py`
   - Implement `heatmap_view.py`
   - Create `connections_graph.py`

2. **Integrate ML into Pipeline:**
   - Add ML anomaly detection to event processing
   - Run UEBA profiling on ingestion
   - Enrich artifacts with threat intelligence

3. **UI Integration:**
   - Add ML/TI tabs to main window
   - Display anomaly scores in timeline
   - Show threat intelligence warnings

4. **Testing:**
   - Create synthetic datasets for ML training
   - Test with real-world cases
   - Benchmark performance improvements

5. **Documentation:**
   - Update architecture document
   - Write user guides for new features
   - Create API documentation

---

**Status:** Phase 1 (Analytics) Complete ✅  
**Next:** Phase 2 (Visualizations) 🔄  
**ETA for MVP:** 2-4 weeks  
**Full Implementation:** 2-3 months


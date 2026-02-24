# FEPD – Forensic Evidence Parser Dashboard

## Project Overview

**FEPD** is an **enterprise-grade, AI-powered** forensic analysis platform designed for government forensic labs, CERT teams, air-gapped SOCs, and incident response teams. It provides comprehensive automation for digital forensic investigation across **Windows, macOS, Linux, and mobile platforms**.

## 🚀 Key Capabilities

### Core Forensics
- ✅ **Offline Operation**: Completely air-gapped, no internet required
- ✅ **Forensic Sound**: Read-only access, SHA-256 hashing at every stage
- ✅ **Auto-Discovery**: Automatic artifact identification across all platforms
- ✅ **Multi-Parser Support**: EVTX, Registry, Prefetch, MFT, Browser History, System Logs
- ✅ **Multi-Platform**: Windows, macOS, Linux, iOS, Android forensics
- ✅ **Chain of Custody**: Append-only logging for legal admissibility

### 🤖 Advanced Analytics (NEW)
- ✅ **ML Anomaly Detection**: Isolation Forest + statistical methods for unusual pattern identification
- ✅ **User Behavior Analytics (UEBA)**: Baseline profiling and behavioral deviation detection
- ✅ **Threat Intelligence Integration**: IOC matching against MISP, AlienVault OTX, VirusTotal
- ✅ **ML Explainability**: Natural language explanations with SHAP for every detection
- ✅ **Transparent AI**: Evidence-based justifications with confidence scores

### 📊 Rich Visualizations (NEW)
- ✅ **Interactive Timeline Graph**: Temporal relationships and event clustering
- ✅ **Activity Heatmaps**: Intensity visualization across time periods
- ✅ **Network Connection Graphs**: Entity relationship visualization (IPs, users, processes)
- ✅ **Advanced Filtering**: Complex boolean queries and saved filter sets

### ⚡ Performance & Scalability (NEW)
- ✅ **Parallel Processing**: Multi-core support (4x faster on 8-core systems)
- ✅ **Out-of-Core Timeline**: Handle 10M+ events with <500MB RAM
- ✅ **Full-Text Search**: Elasticsearch + SQLite FTS5 dual backend with fuzzy matching
- ✅ **Memory-Mapped I/O**: 256MB mmap for ultra-fast database queries
- ✅ **Streaming Queries**: Process massive datasets without loading into memory

### 🌍 Compliance & Internationalization (NEW)
- ✅ **Multilingual UI**: 6 languages (English, Spanish, French, German, Japanese, Chinese)
- ✅ **Configurable Reports**: Executive, Technical, Compliance, Incident Response templates
- ✅ **PDF/HTML/DOCX Export**: Professional forensic reports with charts
- ✅ **Regulatory Compliance**: PCI-DSS, HIPAA, GDPR, SOX audit trails

## Documentation Structure

```
FEPD/
├── docs/
│   ├── 01_Executive_Summary.md
│   ├── 02_Feasibility_Analysis.md
│   ├── 03_Requirements_Specification.md
│   ├── 04_System_Design.md
│   ├── 05_UI_Specifications.md
│   ├── 06_Implementation_Details.md
│   ├── 07_Testing_and_Results.md
│   ├── 08_Conclusion.md
│   ├── API_Documentation.md               # NEW
│   ├── Performance_Benchmarks.md          # NEW
│   ├── ML_Analytics_Guide.md              # NEW
│   └── Deployment_Guide.md                # NEW
├── diagrams/
│   ├── DFD_Level_0.txt
│   ├── DFD_Level_1.txt
│   ├── Use_Case_Diagram.txt
│   ├── Activity_Diagram.txt
│   ├── Sequence_Diagram.txt
│   ├── Class_Diagram.txt
│   ├── Module_Interaction.txt
│   ├── ML_Pipeline_Architecture.txt       # NEW
│   └── Scalability_Architecture.txt       # NEW
├── ui/
│   ├── UI_Theme_Specification.md
│   ├── Tab_Interface_Design.md
│   ├── Timeline_Wireframe.txt
│   ├── Heatmap_Visualization.txt
│   └── Process_Graph_Visualization.txt
├── technical/
│   ├── Data_Dictionary.md
│   ├── Algorithms_and_Pseudocode.md
│   ├── Software_Requirements.md
│   ├── Report_Layout_Template.md
│   ├── Parallel_Processing_Guide.md       # NEW
│   └── Search_Engine_Configuration.md     # NEW
└── locales/
    ├── README.md                          # NEW - i18n documentation
    ├── fepd_en_US.ts                      # NEW - English translations
    ├── fepd_es_ES.ts                      # NEW - Spanish translations
    └── ... (4 more languages)
```

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/FEPD.git
cd FEPD

# Install dependencies
pip install -r requirements.txt

# Optional: Install Elasticsearch for enhanced search
# See docs/Deployment_Guide.md for details
```

### Basic Usage

```python
from src.modules.pipeline import ForensicPipeline

# Initialize pipeline
pipeline = ForensicPipeline(evidence_path="E:/evidence")

# Run analysis with parallel processing
pipeline.set_parallel_config(max_workers=8, use_parallel=True)
results = pipeline.run()

# Generate report
from src.modules.report_templates import ReportGenerator

generator = ReportGenerator()
report = generator.generate_report(
    report_type='executive',
    data={'events': results['events']},
    format='pdf',
    output_path='forensic_report.pdf'
)
```

### Advanced Features

#### 1. ML Anomaly Detection
```python
from src.ml.anomaly_detector import AnomalyDetector

detector = AnomalyDetector()
detector.train(training_data)
anomalies = detector.detect_anomalies(events)
```

#### 2. UEBA Profiling
```python
from src.ml.ueba import UEBAProfiler

profiler = UEBAProfiler()
user_profile = profiler.build_profile(user_events)
alerts = profiler.detect_deviations(new_events, user_profile)
```

#### 3. Threat Intelligence
```python
from src.ml.threat_intel import ThreatIntelligence

threat_intel = ThreatIntelligence(
    misp_url="https://misp.local",
    otx_api_key="your_key"
)
matches = threat_intel.enrich_events(events)
```

#### 4. Full-Text Search
```python
from src.modules.search_engine import SearchEngine, SearchQuery

search = SearchEngine(
    elasticsearch_hosts=["localhost:9200"],
    sqlite_db_path="timeline.db"
)

# Simple search
results = search.simple_search("malware", limit=100)

# Advanced search with filters
query = SearchQuery(
    text="suspicious activity",
    fuzzy=True,
    categories=["Process Execution"],
    severities=["HIGH", "CRITICAL"],
    start_time=datetime(2025, 11, 1),
    end_time=datetime(2025, 11, 7)
)
results = search.search(query)
```

#### 5. ML Explanations
```python
from src.ml.explainer import Explainer

explainer = Explainer()
explanation = explainer.explain_anomaly(
    event=suspicious_event,
    features=feature_dict,
    baselines=baseline_dict
)

# Print natural language explanation
print(explanation.to_natural_language(verbose=True))
# Output:
# 🔍 ANOMALY Detection - CRITICAL
# Confidence: 87.0%
# 
# 📌 Unusual behavior detected: Access at hour 3 (typical: 14)
# 
# Evidence:
#   1. Access at hour 3 (typical: 14)
#   2. File size 125000000 bytes (900% above normal)
#   3. Accessed sensitive file
```

#### 6. Multilingual UI
```python
from src.utils.i18n import init_i18n, tr

# Initialize with auto-detection
i18n = init_i18n()

# Or set specific language
i18n.set_language('es_ES')  # Spanish

# Translate strings
label_text = tr("File Activity")  # → "Actividad de Archivos"
```

## 🖥️ User Interface

### Main Application Tabs

FEPD provides a comprehensive tab-based interface for complete forensic workflow:

#### 1. 📁 **Image Ingest**
- Disk image ingestion (E01, RAW, DD formats)
- Forensic soundness validation
- SHA-256 hash verification
- Case management

#### 2. 🔍 **Artifacts**
- Discovered artifacts table
- Platform-specific categorization
- Quick access to parsed evidence

#### 3. 📊 **Timeline**
- Temporal event visualization
- Interactive filtering
- Event clustering

#### 4. 🤖 **ML Analytics** (NEW)
Three sub-tabs for AI-powered analysis:
- **Anomaly Detection**: Autoencoder + clustering with color-coded scores
- **UEBA Profiling**: High-risk user identification and behavior analysis
- **Threat Intelligence**: IOC enrichment with VirusTotal/OTX/MISP integration

Features:
- Background threading for non-blocking analysis
- Real-time progress tracking
- Export results to CSV/JSON
- Detailed event summaries

#### 5. 📈 **Visualizations** (NEW)
Three advanced visualization types:
- **Heatmap**: Activity intensity across time periods
- **Connections Graph**: Network and entity relationships
- **Timeline Graph**: Interactive temporal analysis with category stacking

Features:
- Multiple layout options (force-directed, circular, hierarchical)
- Configurable time bins (15min to 1W)
- Export to PNG/PDF
- Category filtering

#### 6. 🔍 **Search** (NEW)
Full-text search interface with dual backend support:
- **Elasticsearch**: High-performance distributed search
- **SQLite FTS5**: Built-in full-text search fallback

Features:
- Fuzzy search for partial matches
- Advanced filters (category, severity, date range)
- Search score ranking
- Color-coded severity in results
- Event details viewer
- Export to CSV

#### 7. 🖥️ **Platform Analysis** (NEW)
Multi-platform forensic artifact parsing:
- **macOS**: Unified Logs, FSEvents, TCC (Privacy)
- **Linux**: syslog, journald, auditd
- **Mobile**: iOS backups, Android backups

Features:
- File/directory browsers for source selection
- Background parsing with progress tracking
- Results summary with statistics
- Automatic platform detection

#### 8. 📄 **Report**
Professional forensic report generation:
- Multiple templates (Executive, Technical, Compliance, Incident Response)
- Export formats (PDF, HTML, DOCX)
- Chart and visualization embedding
- Chain of custody integration

### UI Features
- 🎨 **Dark Indigo Theme**: Professional forensic interface
- 🌍 **6 Languages**: English, Spanish, French, German, Japanese, Chinese
- ⚡ **Responsive**: Background threading for all long operations
- 🔄 **Real-time Updates**: Progress bars and status messages
- 📊 **Color Coding**: Severity-based visual indicators
- 💾 **Export**: Multiple format support (CSV, JSON, Excel, PDF)

## Technology Stack

- **Language**: Python 3.10+
- **UI Framework**: PyQt6
- **Image Access**: pyewf, pytsk3
- **Parsers**: python-evtx, python-registry, python-prefetch-parser, analyzeMFT
- **Processing**: pandas
- **Reporting**: reportlab/fpdf
- **Visualization**: matplotlib, pyqtgraph

## Legal & Forensic Compliance

FEPD is designed to meet forensic soundness requirements:
- Read-only evidence access (no write operations)
- SHA-256 cryptographic hashing at every stage
- Complete chain-of-custody logging
- Deterministic, repeatable analysis
- Court-admissible report generation

## Target Users

- Government Forensic Laboratories
- Law Enforcement Digital Forensics Units
- Corporate Incident Response Teams
- CERT/CSIRT Organizations
- Air-gapped Security Operations Centers

## Project Status

📋 **Documentation Phase**: Complete system specification and design documentation

---

*This system operates completely offline and is designed for legally defensible digital forensic investigations.*

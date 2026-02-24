# FEPD API Documentation

## Overview

FEPD provides a comprehensive Python API for forensic analysis automation, ML-powered threat detection, and report generation.

## Core Modules

### 1. Forensic Pipeline (`src/modules/pipeline.py`)

Main entry point for forensic analysis workflows.

#### ForensicPipeline

```python
from src.modules.pipeline import ForensicPipeline

pipeline = ForensicPipeline(
    evidence_path="E:/evidence",
    output_dir="./output",
    hash_algorithm="sha256"
)
```

**Methods:**

- **`run()`**: Execute complete forensic analysis pipeline
  ```python
  results = pipeline.run()
  # Returns: {
  #   'events': List[Dict],
  #   'artifacts': List[str],
  #   'hash_verification': Dict,
  #   'statistics': Dict
  # }
  ```

- **`set_parallel_config(max_workers=None, use_parallel=True, io_threads=4)`**: Configure parallel processing
  ```python
  pipeline.set_parallel_config(max_workers=8, use_parallel=True)
  ```

- **`get_performance_metrics()`**: Get real-time CPU/memory metrics
  ```python
  metrics = pipeline.get_performance_metrics()
  # Returns: {'cpu_percent': 85.3, 'memory_mb': 450.2}
  ```

### 2. Timeline Database (`src/modules/db_manager.py`)

Out-of-core timeline system for massive datasets.

#### TimelineDB

```python
from src.modules.db_manager import TimelineDB, QueryParams

db = TimelineDB(
    db_path="timeline.db",
    cache_size=1000,  # Cache 1000 queries
    logger=logger
)
```

**Methods:**

- **`insert_event(event: Dict[str, Any]) -> int`**: Insert single event
  ```python
  event_id = db.insert_event({
      'timestamp': datetime.now(),
      'category': 'File Activity',
      'description': 'File accessed',
      'severity': 'MEDIUM'
  })
  ```

- **`insert_events_batch(events: List[Dict], batch_size=5000) -> int`**: Bulk insert
  ```python
  inserted_count = db.insert_events_batch(events, batch_size=5000)
  ```

- **`query_streaming(params: QueryParams) -> StreamingCursor`**: Stream large result sets
  ```python
  params = QueryParams(
      start_time=datetime(2025, 11, 1),
      end_time=datetime(2025, 11, 7),
      categories=['File Activity', 'Process Execution'],
      severities=['HIGH', 'CRITICAL'],
      sort_by='timestamp',
      sort_order='ASC'
  )
  
  cursor = db.query_streaming(params)
  for event in cursor:
      process_event(event)
  ```

- **`query_page(params: QueryParams, use_cache=True) -> Tuple[List[Dict], int]`**: Paginated queries
  ```python
  params = QueryParams(offset=0, limit=100)
  events, total = db.query_page(params, use_cache=True)
  print(f"Page 1 of {total // 100 + 1}")
  ```

- **`export_to_dataframe(params: QueryParams, chunk_size=10000) -> pd.DataFrame`**: Export to Pandas
  ```python
  df = db.export_to_dataframe(params, chunk_size=10000)
  df.to_csv('timeline_export.csv')
  ```

### 3. Search Engine (`src/modules/search_engine.py`)

Full-text search with Elasticsearch and SQLite FTS5.

#### SearchEngine

```python
from src.modules.search_engine import SearchEngine, SearchQuery

# With Elasticsearch
search = SearchEngine(
    elasticsearch_hosts=["localhost:9200"],
    index_name="fepd_events"
)

# Or with SQLite fallback
search = SearchEngine(
    sqlite_db_path="timeline.db"
)
```

**Methods:**

- **`simple_search(text: str, limit=100) -> SearchResponse`**: Quick text search
  ```python
  results = search.simple_search("malware", limit=100)
  
  print(f"Found {results.total} matches in {results.took_ms}ms")
  for result in results.results:
      print(f"[{result.score}] {result.event['description']}")
  ```

- **`advanced_search(...) -> SearchResponse`**: Multi-filter search
  ```python
  results = search.advanced_search(
      text="suspicious activity",
      categories=["Process Execution", "File Activity"],
      severities=["HIGH", "CRITICAL"],
      start_time=datetime(2025, 11, 1),
      end_time=datetime(2025, 11, 7),
      fuzzy=True,  # Enable fuzzy matching
      limit=200
  )
  ```

- **`search(query: SearchQuery) -> SearchResponse`**: Full control
  ```python
  query = SearchQuery(
      text="powershell -enc",
      fields=['description', 'source'],
      fuzzy=True,
      exact_phrase=False,
      filters={'user': 'admin'},
      start_time=datetime(2025, 11, 1),
      limit=50,
      offset=0,
      highlight=True
  )
  
  response = search.search(query)
  
  # Access aggregations
  if response.aggregations:
      print("Top categories:", response.aggregations['by_category'])
  ```

- **`index_events_bulk(events: List[Dict]) -> int`**: Bulk indexing
  ```python
  indexed = search.index_events_bulk(events)
  print(f"Indexed {indexed} events")
  ```

### 4. ML Anomaly Detection (`src/ml/anomaly_detector.py`)

Isolation Forest-based anomaly detection.

#### AnomalyDetector

```python
from src.ml.anomaly_detector import AnomalyDetector

detector = AnomalyDetector(
    contamination=0.1,  # Expect 10% anomalies
    n_estimators=100,
    max_features=1.0
)
```

**Methods:**

- **`train(events: List[Dict]) -> None`**: Train model
  ```python
  detector.train(historical_events)
  
  # Save model
  detector.save_model("anomaly_model.pkl")
  ```

- **`load_model(path: str) -> None`**: Load trained model
  ```python
  detector.load_model("anomaly_model.pkl")
  ```

- **`detect_anomalies(events: List[Dict]) -> List[Dict]`**: Find anomalies
  ```python
  anomalies = detector.detect_anomalies(new_events)
  
  for anomaly in anomalies:
      print(f"Anomaly: {anomaly['description']}")
      print(f"Score: {anomaly['anomaly_score']}")
      print(f"Severity: {anomaly['severity']}")
  ```

- **`explain_anomaly(event: Dict) -> Dict`**: Get explanation
  ```python
  explanation = detector.explain_anomaly(suspicious_event)
  print(explanation['reason'])
  print(explanation['contributing_factors'])
  ```

### 5. UEBA Profiling (`src/ml/ueba.py`)

User and Entity Behavior Analytics.

#### UEBAProfiler

```python
from src.ml.ueba import UEBAProfiler

profiler = UEBAProfiler(
    profile_window_days=30,
    deviation_threshold=2.0  # 2 standard deviations
)
```

**Methods:**

- **`build_profile(user_events: List[Dict]) -> UserProfile`**: Build baseline
  ```python
  profile = profiler.build_profile(user_events)
  
  print(f"User: {profile.user_id}")
  print(f"Baseline activity: {profile.stats['avg_events_per_day']}")
  print(f"Typical hours: {profile.typical_hours}")
  print(f"Common categories: {profile.common_categories}")
  ```

- **`detect_deviations(events: List[Dict], profile: UserProfile) -> List[Dict]`**: Find anomalies
  ```python
  alerts = profiler.detect_deviations(new_events, profile)
  
  for alert in alerts:
      print(f"UEBA Alert: {alert['type']}")
      print(f"Severity: {alert['severity']}")
      print(f"Description: {alert['description']}")
      print(f"Deviation score: {alert['deviation_score']}")
  ```

- **`update_profile(profile: UserProfile, new_events: List[Dict]) -> UserProfile`**: Incremental update
  ```python
  updated_profile = profiler.update_profile(profile, recent_events)
  ```

### 6. Threat Intelligence (`src/ml/threat_intel.py`)

IOC matching and enrichment.

#### ThreatIntelligence

```python
from src.ml.threat_intel import ThreatIntelligence

threat_intel = ThreatIntelligence(
    misp_url="https://misp.local",
    misp_key="your_api_key",
    otx_api_key="your_otx_key",
    vt_api_key="your_vt_key",
    cache_ttl=3600  # Cache for 1 hour
)
```

**Methods:**

- **`enrich_events(events: List[Dict]) -> List[Dict]`**: Add threat context
  ```python
  enriched = threat_intel.enrich_events(events)
  
  for event in enriched:
      if event.get('threat_matches'):
          print(f"Threat detected: {event['description']}")
          for match in event['threat_matches']:
              print(f"  IOC: {match['indicator']}")
              print(f"  Type: {match['type']}")
              print(f"  Source: {match['source']}")
              print(f"  Severity: {match['severity']}")
  ```

- **`check_ioc(indicator: str, ioc_type: str) -> Optional[Dict]`**: Check single IOC
  ```python
  result = threat_intel.check_ioc("192.168.1.100", "ip")
  
  if result:
      print(f"Malicious IP: {result['description']}")
      print(f"Tags: {result['tags']}")
  ```

- **`update_feeds(sources: List[str] = None) -> int`**: Refresh IOC database
  ```python
  updated_count = threat_intel.update_feeds(['misp', 'otx'])
  print(f"Updated {updated_count} indicators")
  ```

### 7. ML Explainability (`src/ml/explainer.py`)

Generate natural language explanations for ML detections.

#### Explainer

```python
from src.ml.explainer import Explainer

explainer = Explainer()
explainer.register_model('anomaly_detector', detector.model)
```

**Methods:**

- **`explain_anomaly(event, model_name, features, baselines) -> Explanation`**: Explain anomaly
  ```python
  explanation = explainer.explain_anomaly(
      event=suspicious_event,
      model_name='anomaly_detector',
      features={'hour': 3, 'file_size': 125000000},
      baselines={'hour': 14, 'file_size': 12500000}
  )
  
  # Natural language output
  print(explanation.to_natural_language(verbose=True))
  # Output:
  # 🔍 ANOMALY Detection - CRITICAL
  # Confidence: 87.0%
  #
  # 📌 Unusual behavior detected: Access at hour 3 (typical: 14)
  #
  # Evidence:
  #   1. Access at hour 3 (typical: 14)
  #      Value: 3 (baseline: 14, deviation: -78.6%)
  #      Importance: ██████████ 0.85
  #   2. File size 125000000 bytes (900% above normal)
  #      Value: 125000000 (baseline: 12500000, deviation: +900.0%)
  #      Importance: ████████░░ 0.78
  #
  # 💡 Counterfactual: Event would not be flagged if Access at hour 3,
  #    File size 125000000 bytes were within normal ranges
  #
  # Recommended Actions:
  #   1. Immediate investigation required
  #   2. Verify if off-hours access was authorized
  #   3. Check file access permissions and sensitivity classification
  ```

- **`explain_ueba_alert(event, user_profile, deviations) -> Explanation`**: Explain UEBA alert
  ```python
  explanation = explainer.explain_ueba_alert(
      event=alert_event,
      user_profile=profile,
      deviations=detected_deviations
  )
  ```

- **`explain_threat_match(event, threat_matches) -> Explanation`**: Explain threat intel match
  ```python
  explanation = explainer.explain_threat_match(
      event=malicious_event,
      threat_matches=ioc_matches
  )
  ```

### 8. Report Generation (`src/modules/report_templates.py`)

Professional forensic reports with Jinja2 templates.

#### ReportGenerator

```python
from src.modules.report_templates import ReportGenerator, ReportConfig

generator = ReportGenerator(templates_dir="./templates")

# Configure branding
config = ReportConfig(
    title="Forensic Analysis Report",
    subtitle="Case #2025-11-07-001",
    organization="ACME Forensics Lab",
    analyst_name="Jane Doe",
    case_number="2025-11-07-001",
    classification="CONFIDENTIAL",
    colors={
        'primary': '#2c3e50',
        'secondary': '#3498db',
        'danger': '#e74c3c'
    }
)
```

**Methods:**

- **`generate_report(report_type, data, config, format, output_path) -> str`**: Generate report
  ```python
  # Executive Summary (PDF)
  report_path = generator.generate_report(
      report_type='executive',
      data={
          'events': timeline_events,
          'anomalies': detected_anomalies,
          'threat_matches': threat_intel_matches
      },
      config=config,
      format='pdf',
      output_path='executive_summary.pdf'
  )
  
  # Technical Deep-Dive (HTML)
  report_path = generator.generate_report(
      report_type='technical',
      data={
          'events': timeline_events,
          'anomaly_details': anomaly_explanations,
          'ueba_alerts': ueba_alerts,
          'artifacts': parsed_artifacts
      },
      config=config,
      format='html',
      output_path='technical_report.html'
  )
  
  # Compliance Audit (DOCX)
  report_path = generator.generate_report(
      report_type='compliance',
      data={
          'events': audit_trail,
          'violations': compliance_violations,
          'chain_of_custody': custody_log
      },
      config=config,
      format='docx',
      output_path='compliance_report.docx'
  )
  
  # Incident Response (PDF)
  report_path = generator.generate_report(
      report_type='incident',
      data={
          'events': incident_timeline,
          'affected_systems': compromised_hosts,
          'iocs': indicators_of_compromise,
          'actions': response_actions
      },
      config=config,
      format='pdf',
      output_path='incident_report.pdf'
  )
  ```

### 9. Internationalization (`src/utils/i18n.py`)

Multilingual UI support.

#### TranslationManager

```python
from src.utils.i18n import init_i18n, tr

# Initialize with auto-detection
i18n = init_i18n()

# Or set specific language
i18n.set_language('es_ES')  # Spanish
```

**Functions:**

- **`tr(text: str, context="") -> str`**: Translate string
  ```python
  from src.utils.i18n import tr
  
  # In UI code
  button_label = tr("Export Report")  # → "Exportar Informe" (Spanish)
  menu_item = tr("File", context="menu")  # → "Archivo"
  ```

- **`format_date(dt: datetime) -> str`**: Locale-aware date formatting
  ```python
  formatted = i18n.format_date(datetime.now())
  # English: "2025-11-07"
  # Spanish: "07/11/2025"
  # German: "07.11.2025"
  ```

- **`format_number(number: float, decimals=2) -> str`**: Locale-aware number formatting
  ```python
  formatted = i18n.format_number(1234567.89)
  # English: "1,234,567.89"
  # Spanish: "1.234.567,89"
  # French: "1 234 567,89"
  ```

## Platform-Specific Parsers

### Windows Parser (`src/parsers/windows_parser.py`)
- EVTX logs
- Registry hives
- Prefetch files
- MFT (Master File Table)
- Browser history
- Windows Defender logs

### macOS Parser (`src/parsers/macos_parser.py`)
- Unified logs (`.tracev3`)
- FSEvents
- Spotlight metadata
- XProtect logs
- Safari history
- Keychain access logs

### Linux Parser (`src/parsers/linux_parser.py`)
- Syslog
- Journald
- Bash history
- Cron logs
- Auth logs
- Apache/Nginx logs

### Mobile Parser (`src/parsers/mobile_parser.py`)
- iOS backups
- Android data extraction
- SMS/Call logs
- Location history
- App data (SQLite databases)
- Contacts and calendar

## Error Handling

All API methods use consistent error handling:

```python
try:
    results = pipeline.run()
except FileNotFoundError as e:
    print(f"Evidence not found: {e}")
except PermissionError as e:
    print(f"Access denied: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
```

## Logging

Enable detailed logging:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fepd.log'),
        logging.StreamHandler()
    ]
)
```

## Examples

See `examples/` directory for complete working examples:
- `examples/basic_analysis.py` - Simple forensic pipeline
- `examples/ml_detection.py` - Anomaly detection workflow
- `examples/threat_hunting.py` - Threat intelligence integration
- `examples/report_generation.py` - Custom report creation
- `examples/bulk_processing.py` - Large-scale batch processing

---

**Last Updated**: 2025-11-07  
**API Version**: 1.0  
**FEPD Version**: 1.0.0

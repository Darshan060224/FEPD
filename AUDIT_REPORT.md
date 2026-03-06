# FEPD ML/Analytics System — Comprehensive Deep Audit Report

**Date:** 2025-01-20  
**Scope:** All ML, analysis, and analytics modules in `src/ml/`, `src/analysis/`, `src/modules/`, `src/ui/tabs/ml_*`  
**Total Files Audited:** 32  
**Total Lines of Code:** ~12,800  

---

## Table of Contents

1. [File Inventory](#1-file-inventory)
2. [Feature Engineering Correctness](#2-feature-engineering-correctness)
3. [Model Training Pipeline](#3-model-training-pipeline)
4. [Inference Pipeline](#4-inference-pipeline)
5. [Dataset Preparation](#5-dataset-preparation)
6. [Model Evaluation](#6-model-evaluation)
7. [Algorithm Selection](#7-algorithm-selection)
8. [Explainability](#8-explainability)
9. [UEBA Profiling](#9-ueba-profiling)
10. [Threat Intelligence](#10-threat-intelligence)
11. [Anomaly Scoring](#11-anomaly-scoring)
12. [Feature Importance](#12-feature-importance)
13. [Model Persistence](#13-model-persistence)
14. [Runtime Errors & Edge Cases](#14-runtime-errors--edge-cases)
15. [Performance](#15-performance)
16. [Data Flow & Integration](#16-data-flow--integration)
17. [Executive Summary](#17-executive-summary)

---

## 1. File Inventory

| File | Lines | Purpose |
|------|------:|---------|
| `src/ml/__init__.py` | 27 | Package exports |
| `src/ml/ml_anomaly_detector.py` | 1,410 | Core ML anomaly engine (Autoencoder, Clustering, ClockSkew, UEBA) |
| `src/ml/forensic_ml_engine.py` | 805 | Event normalization + forensic explainer (EVTX, LOLBins, Sigma) |
| `src/ml/ueba_profiler.py` | 906 | User/Entity Behavior Analytics |
| `src/ml/data_extractors.py` | 888 | Raw data → training CSVs |
| `src/ml/data_quality.py` | 351 | Pre-training dataset validation |
| `src/ml/feature_engineering.py` | 418 | Feature pipeline (File, Registry, Memory, Network) |
| `src/ml/feature_extractors.py` | 396 | Alternative feature extractors (EVTX, Registry, File, Execution) |
| `src/ml/training_pipeline.py` | 566 | Offline training with CV, SMOTE, hyperparameter tuning |
| `src/ml/training_orchestrator.py` | 393 | End-to-end training orchestration (6-step workflow) |
| `src/ml/inference_pipeline.py` | 327 | Real-time inference with frozen models |
| `src/ml/explainability_framework.py` | 452 | SHAP/LIME integration for court-defensible explanations |
| `src/ml/explainer.py` | 781 | Comprehensive explanation system (Evidence, Counterfactuals) |
| `src/ml/specialized_models.py` | 596 | 6 specialized models (Malware, EVTX, Registry, Memory, Network, UEBA) |
| `src/ml/threat_intel.py` | 662 | Threat intelligence (YARA, Sigma, VirusTotal, domain reputation) |
| `src/ml/demo_ml_anomaly.py` | 326 | Interactive demo script |
| `src/ml/test_ml_anomaly_detector.py` | 626 | Test suite (custom runner, not pytest) |
| `src/ml/engine/anomaly_engine.py` | 453 | Full pipeline orchestrator (IF + DBSCAN + flags) |
| `src/ml/engine/feature_builder.py` | 227 | Event → 12-feature numeric vectors |
| `src/ml/clustering/anomaly_cluster.py` | 209 | DBSCAN/KMeans anomaly clustering |
| `src/ml/models/isolation_forest_model.py` | 268 | IsolationForest wrapper with scaler + persistence |
| `src/ml/explainability/shap_explainer.py` | 235 | SHAP TreeExplainer + feature-contribution fallback |
| `src/analysis/forensic_ml_analyzer.py` | 374 | Malware + network traffic analysis pipeline |
| `src/analysis/forensic_timeline_generator.py` | 329 | Timeline generation from network/malware/honeypot data |
| `src/modules/ml_output_handler.py` | 296 | Standardized ML output (JSON, timeline, reports) |
| `src/ui/tabs/ml_analytics_tab.py` | 1,095 | Main ML Analytics UI tab (Anomaly, UEBA, Threat Intel sub-tabs) |
| `src/ui/tabs/ml_analysis_tab.py` | 359 | ML Analysis UI tab (inference pipeline integration) |
| `src/ui/tabs/ml_analysis_tab_enhanced.py` | 634 | Enhanced ML Analysis tab (correlation + attack chains) |
| **TOTAL** | **~12,800** | |

---

## 2. Feature Engineering Correctness

### Assessment: MODERATE RISK — Inconsistent, duplicated, some correctness issues

### Issues Found

#### MAJOR-001: Duplicate Feature Extraction Systems (3 separate implementations)

Three independent feature extraction systems exist with overlapping scope:

| System | File | Scope |
|--------|------|-------|
| System A | `feature_engineering.py` | File, Registry, Memory, Network |
| System B | `feature_extractors.py` | EVTX, Registry, File, Execution, UEBA |
| System C | `engine/feature_builder.py` | Events → 12-feature vectors |

**Impact:** No clear contract on which system is used where. `training_pipeline.py` uses System A; `engine/anomaly_engine.py` uses System C; `inference_pipeline.py` determines model types but `_extract_artifacts()` is a placeholder. System B (`feature_extractors.py`) appears unused in any pipeline.

**Recommendation:** Consolidate into a single `FeatureExtractorFactory` pattern. Retire `feature_extractors.py` or integrate it as the canonical source.

#### MAJOR-002: Shannon Entropy Calculated Differently Across Files

- `feature_engineering.py:FileFeatureExtractor._calculate_entropy()` — character-level frequency distribution over file content bytes
- `feature_extractors.py:FileFeatureExtractor._calculate_shannon_entropy()` — byte-level entropy over raw bytes
- Both are valid Shannon entropy but operate on different granularities (chars vs bytes), producing different values for the same file.

**Impact:** Model trained on one will produce incorrect scores with the other.

#### MINOR-001: `feature_builder.py` Hardcodes 12 Features

The `FeatureBuilder.FEATURE_NAMES` list is hardcoded rather than derived from extractors. Adding a feature requires updating the list, `_build_vector()`, and all consumers simultaneously — fragile coupling.

#### MINOR-002: `_EXT_RISK` Dictionary in `feature_builder.py` Maps Subjective Risk

Extension risk scores (`.exe` → 0.9, `.txt` → 0.05) are static heuristics, not learned. While reasonable for forensic contexts, they bias the model toward expected malware extensions and may miss novel threats using benign extensions.

#### MINOR-003: LabelEncoder Used Inline Without Global Mapping

In `feature_extractors.py`, `LabelEncoder` is used inline on per-batch data. This means label encodings are NOT stable across batches — a value encoded as `3` in training could be encoded as `7` in inference.

**Recommendation:** Use a fitted-and-saved encoder or hash-based encoding (e.g., `OrdinalEncoder` with `handle_unknown='use_encoded_value'`).

---

## 3. Model Training Pipeline

### Assessment: MODERATE RISK — Good framework, but critical gap in orchestrator

### Issues Found

#### CRITICAL-001: `TrainingOrchestrator._train_all_models()` Does Not Actually Train Models

```python
# training_orchestrator.py, lines ~290-345
def _train_all_models(self):
    # Loads CSV, creates model objects, but NEVER calls model.train()
    # Instead just saves metadata JSON files
```

The 6-step orchestrator (enter training mode → extract datasets → validate quality → **train models** → wipe dataa/ → enter inference mode) skips the actual training. The `_train_all_models()` method loads CSV files and creates metadata, but the `specialized_models.py` classes' `.train()` methods are never invoked.

**Impact:** The entire orchestrated training pipeline is a no-op. Models remain untrained.

**Recommendation:** Call `model.train(X_train, y_train)` for each specialized model inside `_train_all_models()`.

#### MAJOR-003: `training_pipeline.py` Is Well-Designed but Disconnected

`TrainingPipeline` has a solid 13-step pipeline (feature selection via `SelectKBest`, SMOTE balancing, `GridSearchCV` tuning, `StratifiedKFold` CV, ensemble building, threshold optimization). However, **no code path calls it**. Neither the UI nor the orchestrator invokes `TrainingPipeline.run()`.

**Impact:** The best training code in the codebase is dead code.

**Recommendation:** Wire `TrainingPipeline` into `TrainingOrchestrator._train_all_models()`.

#### MAJOR-004: Three Unimplemented Specialized Models

In `specialized_models.py`:

| Model | Status |
|-------|--------|
| `MalwareClassifier` | ✅ Implemented (RF+GB ensemble) |
| `EVTXAnomalyDetector` | ✅ Implemented (IsolationForest) |
| `RegistryPersistenceDetector` | ✅ Implemented (RandomForest) |
| `MemoryAnomalyDetector` | ❌ **Stub** — empty `train()` and `predict()` |
| `NetworkAnomalyDetector` | ❌ **Stub** — empty `train()` and `predict()` |
| `UEBAModel` | ❌ **Stub** — empty `train()` and `predict()` |

**Impact:** 50% of specialized models return empty results.

#### MINOR-004: Custom Autoencoder Uses Only Sigmoid Activation

`ml_anomaly_detector.py:AutoencoderAnomalyDetector` implements a numpy-based autoencoder using only sigmoid activation. Sigmoid squashes all values to (0, 1), which:
- Limits reconstruction capability for features with wide ranges
- Can cause vanishing gradient during training (though manual backprop mitigates this)
- ReLU or Leaky ReLU on hidden layers would generally perform better

#### MINOR-005: `data_extractors.py` Generates Synthetic Data as Fallback

When real data files aren't found, extractors generate random synthetic data:
```python
# If no real data found, generate sample
df = pd.DataFrame({
    'file_size': np.random.lognormal(10, 2, 500),
    ...
})
```
This silently masks data pipeline failures and could lead to a model trained entirely on random noise.

---

## 4. Inference Pipeline

### Assessment: HIGH RISK — Critical placeholder prevents real inference

### Issues Found

#### CRITICAL-002: `InferencePipeline._extract_artifacts()` Returns Empty DataFrame

```python
# inference_pipeline.py, line ~220
def _extract_artifacts(self, evidence_path: Path, evidence_type: str) -> pd.DataFrame:
    """Extract artifacts from evidence file."""
    # TODO: Implement actual extraction
    return pd.DataFrame()
```

This is the single most critical issue. The 7-stage inference pipeline (verify integrity → detect type → extract artifacts → engineer features → ML predictions → explanations → save) breaks at stage 3 because no artifacts are ever extracted. All subsequent stages operate on an empty DataFrame.

**Impact:** ML predictions never run on real evidence. The entire inference pipeline produces empty results.

**Recommendation:** Implement artifact extraction by delegating to existing parsers (EVTX, registry, prefetch, etc.) that exist elsewhere in the codebase.

#### MAJOR-005: Model Selection in Inference Uses Hardcoded Mapping

```python
_MODEL_MAP = {
    'disk_image': ['malware', 'registry', 'evtx'],
    'memory_dump': ['memory'],
    'network_capture': ['network'],
    'evtx_log': ['evtx'],
    ...
}
```

But 3 of 6 mapped models (`memory`, `network`, `ueba`) are stubs (see MAJOR-004), so even if artifact extraction were implemented, these evidence types would produce no predictions.

#### MAJOR-006: `ml_analysis_tab_enhanced.py` Uses Entirely Mocked Data

The `ForensicMLAnalysisWorker` in the enhanced analysis tab uses hardcoded mock data:
```python
def _load_artifacts(self) -> List[Dict]:
    return [
        {'type': 'Registry', 'path': 'C:\\Windows\\System32\\config\\SYSTEM'},
        {'type': 'Prefetch', 'path': 'C:\\Windows\\Prefetch\\MALWARE.EXE-ABC123.pf'},
        ...
    ]
```

All correlations, attack chains, and findings are synthetic. The UI appears functional but produces predetermined results regardless of actual case data.

---

## 5. Dataset Preparation

### Assessment: MODERATE — Good structure, some quality concerns

### Issues Found

#### MAJOR-007: Timezone Handling Strips All Timezone Information

```python
# data_extractors.py
df['timestamp'] = pd.to_datetime(df['timestamp']).dt.tz_localize(None)
```

This discards timezone info from all timestamps before training. In forensic analysis, timezone information is critical for establishing event timelines across different systems.

**Impact:** Models cannot distinguish between events at the same local time but different UTC times. Cross-timezone correlation is impossible.

#### MAJOR-008: `data_quality.py` Validates Schema But Not Semantic Correctness

`DataQualityValidator` checks:
- ✅ Required columns exist
- ✅ Null ratios below threshold
- ✅ Feature distributions (basic stats)
- ✅ Duplicate detection
- ❌ Does NOT validate semantic correctness (e.g., entropy values in [0, 8], timestamps in correct epoch range, IP addresses well-formed)
- ❌ Does NOT validate label balance for supervised models
- ❌ Does NOT detect data leakage between train/test splits

#### MINOR-006: No Train/Test/Validation Split Strategy Documented

`data_extractors.py` produces single CSV files. The split into train/test happens ad-hoc in different places:
- `ml_analytics_tab.py`: 70/30 split (line ~65)
- `training_pipeline.py`: StratifiedKFold CV (no holdout)
- `engine/anomaly_engine.py`: Trains and predicts on the same data (data leakage)

No consistent strategy exists.

---

## 6. Model Evaluation

### Assessment: MODERATE — `training_pipeline.py` is excellent, but disconnected

### Issues Found

#### MAJOR-009: `AnomalyEngine` Trains and Evaluates on Same Data

```python
# engine/anomaly_engine.py
def _run_global(self, events, _progress):
    X, feature_names = self._feature_builder.build(events)
    model.fit(X)        # Train on ALL data
    scores = model.predict(X)  # Predict on SAME data
```

The IsolationForest is trained on the entire event set, then used to predict anomalies on that same set. This means:
- The model will always appear to perform well
- True anomaly detection rate is unknown
- Score distribution is biased toward the training data

**Impact:** Overly optimistic anomaly scores. True novel anomalies may be missed.

**Recommendation:** Hold out at least 20% of data, or use a time-based split (train on first N hours, predict on remaining).

#### MAJOR-010: No Cross-Validation for Unsupervised Models

While `training_pipeline.py` implements `StratifiedKFold` for supervised models, no cross-validation exists for:
- `IsolationForest` (contamination tuning)
- `DBSCAN` (eps/min_samples tuning)
- Custom autoencoder (threshold calibration)

These hyperparameters are hardcoded.

#### MINOR-007: Training Pipeline Metrics Are Comprehensive

`training_pipeline.py` computes: accuracy, precision, recall, F1, ROC-AUC, specificity, FPR, confusion matrix. This is commendable. The issue is only that this code is never executed (see MAJOR-003).

---

## 7. Algorithm Selection

### Assessment: GOOD — Appropriate choices with minor improvements possible

### Findings

| Algorithm | Use Case | Assessment |
|-----------|----------|------------|
| IsolationForest | Unsupervised anomaly detection | ✅ Excellent choice for forensic data (no labels needed, handles high dimensions, interpretable) |
| Custom Autoencoder (numpy) | Behavioral anomaly detection | ⚠️ Functional but limited. PyTorch/TF would be more maintainable and performant |
| DBSCAN | Anomaly clustering | ✅ Good choice for arbitrary-shape clusters and noise detection |
| KMeans | Fallback clustering | ✅ Appropriate fallback when DBSCAN finds only noise |
| RandomForest | Supervised classification (malware, registry) | ✅ Strong baseline, handles imbalanced data with `class_weight='balanced'` |
| GradientBoosting | Ensemble component | ✅ Good complementary model to RF |
| VotingClassifier/StackingClassifier | Ensemble | ✅ Well-structured ensemble strategy |
| SMOTE/Undersampling | Class balancing | ✅ Appropriate for imbalanced forensic datasets |

#### MINOR-008: Custom Numpy Autoencoder vs Framework-Based

The autoencoder in `ml_anomaly_detector.py` implements forward pass, backpropagation, and weight updates in raw numpy. While educational and dependency-light, this:
- Lacks GPU acceleration
- Has no dropout, batch normalization, or modern regularization
- Is harder to debug and extend
- Manual gradient computation is error-prone

**Recommendation:** Consider migrating to PyTorch or keeping as-is with explicit documentation of limitations.

---

## 8. Explainability

### Assessment: HIGH RISK — Three competing systems, significant code duplication

### Issues Found

#### MAJOR-011: Three Separate Explainability Implementations

| System | File | Approach |
|--------|------|----------|
| System A | `explainability_framework.py` | `SHAPExplainer` + `LIMEExplainer` + `ForensicExplainer` wrapper |
| System B | `explainer.py` | `SHAPExplainer` (different class) + `RuleExplainer` + `EvidenceCollector` + `Explainer` main class |
| System C | `explainability/shap_explainer.py` | `FeatureContributionExplainer` + `ShapExplainer` |

All three define a `SHAPExplainer` class (or `ShapExplainer`) with different APIs. The codebase has **no single canonical way** to explain predictions.

**Impact:** Consumers (UI tabs, inference pipeline) may import from different systems, producing inconsistent explanations for the same prediction.

**Recommendation:** Designate one as canonical (recommend `explainability/shap_explainer.py` as it's most focused), deprecate the others, and create a facade.

#### MAJOR-012: SHAP/LIME Are Optional With Silent Fallback

All three systems have `try: import shap` with fallback to simpler explanations. This means:
- No guarantee of explanation quality consistency
- A production deployment missing SHAP falls back to z-score deviations without warning the user
- Court-defensibility claims assume SHAP is available

**Recommendation:** Make SHAP a hard requirement, or clearly label explanation method used in output.

#### MINOR-009: `explainer.py` Counterfactual Generation Is Rule-Based

The "counterfactual" generation in `Explainer.generate_counterfactual()` is template-based string matching, not mathematical counterfactual explanation (e.g., DiCE or Alibi). This is misleading terminology.

---

## 9. UEBA Profiling

### Assessment: MODERATE — Solid behavioral model, some forensic gaps

### Issues Found

#### MAJOR-013: UEBA Profile Building Requires Exact Column Names

`UEBAProfiler.build_profiles()` expects columns like `user_id`, `process`, `file`, `source_ip`, `severity` in the DataFrame. If the data doesn't have these exact column names (e.g., uses `user` instead of `user_id`), profiling silently produces empty profiles.

**Impact:** Column name mismatch leads to no behavioral baseline = no anomaly detection.

**Recommendation:** Add column name mapping/aliasing at the profiler entry point.

#### MAJOR-014: Insider Threat Detection Thresholds Are Hardcoded

```python
# ueba_profiler.py
if file_access_count > 50:  # Mass file access
    threats.append(...)
if login_hour < 5 or login_hour > 22:  # After-hours
    threats.append(...)
```

These thresholds are not configurable and not derived from baseline data. A legitimate user who routinely accesses 100 files per shift would always be flagged.

**Recommendation:** Derive thresholds from user-specific baselines (μ + 2σ) rather than global constants.

#### MINOR-010: `save_findings()` Hardcodes `MLEntity` Fields

The UEBA profiler saves findings using `MLOutputHandler` with hardcoded entity metadata. If multiple users are analyzed, all findings reference the same entity.

---

## 10. Threat Intelligence

### Assessment: GOOD — Well-structured with appropriate graceful degradation

### Issues Found

#### MAJOR-015: YARA and Sigma Rules Are Applied But Rule Sets Are Empty

`YARAScanner` and `SigmaRuleEngine` have proper interfaces but depend on external rule files:
- YARA: Looks for `.yar` files in a rules directory
- Sigma: Looks for `.yml` files in a sigma directory

No default rule sets are shipped with the project. Without rules, these scanners always return empty results.

**Recommendation:** Bundle a baseline rule set (e.g., Sigma community rules for common attack patterns, YARA rules for known malware families).

#### MINOR-011: VirusTotal API Key Handling

The `HashDatabase.lookup_virustotal()` method stores the API key in memory but provides no encryption or secure storage mechanism. The UI (`ml_analytics_tab.py`) accepts the key via a plain `QLineEdit` without masking.

**Recommendation:** Use `QLineEdit.setEchoMode(QLineEdit.EchoMode.Password)` and store keys in OS credential store.

#### MINOR-012: Domain Reputation Uses Hardcoded Blacklist

`DomainReputationChecker` uses a static set of known-bad domains/IPs. This will quickly become stale.

**Recommendation:** Integrate with dynamic reputation feeds (e.g., abuse.ch, public blocklists).

---

## 11. Anomaly Scoring

### Assessment: MODERATE RISK — Multiple inconsistent scoring systems

### Issues Found

#### MAJOR-016: Four Different Score Normalization Schemes

| Location | Method | Range | Threshold |
|----------|--------|-------|-----------|
| `ml_anomaly_detector.py` | 95th percentile MSE | 0–1 | Percentile-based |
| `isolation_forest_model.py` | Min-max inversion of `decision_function` | 0–1 | Contamination-based |
| `engine/anomaly_engine.py` | Delegates to IF model | 0–1 | 0.45 for "anomaly" |
| `forensic_ml_engine.py` | Direct Severity enum mapping | Categorical | Hardcoded thresholds |

**Impact:** An event scored 0.7 by the autoencoder may map to "MEDIUM" in one system and "HIGH" in another. UI consumers cannot assume consistent severity semantics.

**Recommendation:** Define a single `AnomalyScore` class with a normalization contract. All engines produce this type.

#### MAJOR-017: Severity Mapping Is Inconsistent

| System | CRITICAL | HIGH | MEDIUM | LOW |
|--------|----------|------|--------|-----|
| `isolation_forest_model.py` | ≥0.85 | ≥0.65 | ≥0.45 | <0.45 |
| `forensic_ml_engine.py` | ≥0.9 | ≥0.7 | ≥0.4 | <0.4 |
| `ml_anomaly_detector.py` | score_to_severity() | (different thresholds) | | |

**Impact:** Same event, different severity labels depending on which engine processes it.

---

## 12. Feature Importance

### Assessment: MODERATE — Available but inconsistently surfaced

### Issues Found

#### MAJOR-018: Feature Importance Not Propagated to UI

`IsolationForestModel.feature_importance()` computes tree-based feature importances, and `AnomalyEngine` stores them in `self._feature_importance`. However:
- `ml_analytics_tab.py` never requests or displays feature importance
- `ml_analysis_tab.py` has a `feature_table` UI widget but it's only populated from inference pipeline explanations (which return empty due to CRITICAL-002)

**Impact:** Users cannot see which features drive detection, undermining the "explainability" design goal.

#### MINOR-013: Autoencoder Has No Feature Importance

The numpy autoencoder in `ml_anomaly_detector.py` provides no mechanism for feature importance extraction. Unlike tree-based models, autoencoders require gradient-based attribution or perturbation analysis for feature importance.

**Recommendation:** Implement reconstruction-error-per-feature as a proxy for importance.

---

## 13. Model Persistence

### Assessment: GOOD — Multiple valid persistence mechanisms

### Issues Found

#### MAJOR-019: Pickle Used for Model Storage (Security Risk)

`IsolationForestModel.save()` and `forensic_ml_analyzer.py` use `pickle.dump`/`pickle.load` for model persistence. Pickle deserialization can execute arbitrary code.

**Impact:** A tampered model file could execute malicious code when loaded. In a forensic tool, this is a chain-of-custody integrity risk.

**Recommendation:** 
- Use `joblib` with `mmap_mode` (slightly safer, still unpickle-based)
- Add SHA-256 integrity verification before loading (the inference pipeline has `MLIntegrityManager` but it's not used for model loading)
- Consider ONNX for model serialization

#### MINOR-014: Three Different Persistence Formats

| System | Format | Location |
|--------|--------|----------|
| `IsolationForestModel` | pickle (`.pkl`) | `models/` |
| `specialized_models.py` | joblib | `models/` |
| `ml_anomaly_detector.py` Autoencoder | numpy `.npz` + JSON | `models/autoencoder/` |

While all functional, this complexity makes model management harder.

#### MINOR-015: No Model Versioning

No model version tracking or compatibility checking exists. A model trained with feature set v1 could be loaded into an inference pipeline expecting feature set v2.

**Recommendation:** Include feature schema hash in model metadata and verify at load time.

---

## 14. Runtime Errors & Edge Cases

### Assessment: HIGH RISK — Multiple crash paths and unhandled edge cases

### Issues Found

#### CRITICAL-003: Empty DataFrame Crashes in Multiple Locations

Several methods lack guards for empty input:

```python
# ueba_profiler.py - will crash if events_df is empty
profiler.build_profiles(empty_df)  # → KeyError on column access

# training_pipeline.py - SMOTE crashes with <6 samples per class
self._augment_and_balance_data()  # → ValueError from SMOTE

# clustering/anomaly_cluster.py - handled correctly (returns early)
```

**Impact:** Empty evidence cases or filtered datasets will crash the analysis.

#### MAJOR-020: `demo_ml_anomaly.py` Uses Bare Import

```python
from ml_anomaly_detector import ...  # Relative import without package prefix
```

This only works when run from `src/ml/` directory. Running from project root or any other location fails with `ModuleNotFoundError`.

#### MAJOR-021: `ml_analysis_tab_enhanced.py` Uses Fragile `sys.path` Manipulation

```python
sys.path.insert(0, str(__file__).replace('\\', '/').rsplit('/src/', 1)[0])
```

This string manipulation to find the project root is fragile and fails if the path contains `/src/` elsewhere (e.g., `/data/src/backup/src/ui/`).

#### MINOR-016: Silent Exception Swallowing

Multiple locations catch broad exceptions and log but continue:
```python
except Exception as e:
    logger.warning("Clustering failed: %s", e)
    # Continues with unclustered results
```

While graceful degradation is good, some failures (e.g., model loading) should abort rather than continue with no model.

#### MINOR-017: No Input Validation on Contamination Parameter

`IsolationForestModel` accepts `contamination` as a float but doesn't validate the range. Values outside (0, 0.5] will cause sklearn to raise, but with a cryptic error message.

---

## 15. Performance

### Assessment: MODERATE — Reasonable for current scale, scaling concerns

### Issues Found

#### MAJOR-022: Autoencoder Training Is Single-Threaded Numpy

The custom autoencoder in `ml_anomaly_detector.py` performs matrix operations in pure numpy on a single thread. For large evidence sets (>100K events × 10+ features), training 200 epochs could take minutes to hours.

**Impact:** UI freezes during training (though `QThread` workers in tabs mitigate this for UI-triggered analysis).

#### MAJOR-023: No Batch Processing for Large Evidence Files

The inference pipeline processes entire evidence files in memory. For large disk images (hundreds of GB), this will exhaust memory.

**Recommendation:** Implement streaming/chunked processing for evidence file parsing.

#### MINOR-018: Clustering Down-Samples at 50K Events

`AnomalyClusterer` down-samples to 50,000 events for DBSCAN. This is a reasonable default but should be configurable and the user should be informed that not all events were clustered.

---

## 16. Data Flow & Integration

### Assessment: HIGH RISK — Fragmented architecture with broken connections

### Issues Found

#### CRITICAL-004: No Single End-to-End Working Path

Tracing the data flow from evidence ingestion to UI display reveals no single complete, working path through the specialized models:

```
Evidence File → [CRITICAL-002: _extract_artifacts() empty]
                → Feature Engineering → [Feature system unclear] 
                → Model Prediction → [CRITICAL-001: Orchestrator broken]
                → Explanation → [MAJOR-011: 3 competing systems]
                → UI Display → [MAJOR-006: Enhanced tab uses mock data]
```

The only complete working path is:
1. User clicks "Run Anomaly Detection" in `ml_analytics_tab.py`
2. `MLAnalysisWorker._run_anomaly_detection()` loads events from a pre-loaded DataFrame
3. `MLAnomalyDetectionEngine.train()` + `detect_anomalies()` runs
4. Results displayed in anomaly table

This path works but uses the `ml_anomaly_detector.py` engine (autoencoder + clustering), bypassing the specialized models entirely.

#### MAJOR-024: Three Competing Analysis Pipelines

| Pipeline | Entry Point | Engine | Status |
|----------|-------------|--------|--------|
| `ml_analytics_tab.py` → `MLAnomalyDetectionEngine` | UI button | Autoencoder + Clustering + ClockSkew | ✅ Works |
| `ml_analysis_tab.py` → `InferencePipeline` | UI button | Specialized models | ❌ Broken (CRITICAL-002) |
| `ml_analysis_tab_enhanced.py` → Mock data | UI button | None (hardcoded results) | ❌ Fake |
| `engine/anomaly_engine.py` → `AnomalyEngine` | API | IsolationForest + DBSCAN | ✅ Works (standalone) |

**Impact:** Confusing UX — user sees three ML analysis tabs with different capabilities and different engines, none providing a unified experience.

#### MAJOR-025: `forensic_ml_analyzer.py` Is Disconnected

`ForensicMLAnalyzer` loads pickle models and analyzes malware/network data from JSON files, but:
- No UI tab invokes it
- Its model file names (`malware_classifier.pkl`, `network_anomaly_detector.pkl`) don't match what `specialized_models.py` saves
- It reads from `forensic_data/malware/malware_samples.json` which is populated by a different subsystem

**Impact:** Dead code that duplicates functionality.

---

## 17. Executive Summary

### Critical Issues (Must Fix)

| ID | Issue | Impact |
|----|-------|--------|
| CRITICAL-001 | `TrainingOrchestrator` doesn't train models | Training pipeline is non-functional |
| CRITICAL-002 | `InferencePipeline._extract_artifacts()` is empty | Inference pipeline produces no results |
| CRITICAL-003 | Empty DataFrame crashes in multiple locations | Application crashes on edge cases |
| CRITICAL-004 | No single end-to-end working path from evidence to display | Only legacy anomaly detection works |

### Major Issues (Should Fix)

| ID | Issue | Impact |
|----|-------|--------|
| MAJOR-001 | 3 duplicate feature extraction systems | Inconsistent behavior |
| MAJOR-002 | Shannon entropy calculated differently | Model/inference mismatch |
| MAJOR-003 | `TrainingPipeline` is dead code | Best training logic unused |
| MAJOR-004 | 3 of 6 specialized models are stubs | 50% model coverage missing |
| MAJOR-005 | Hardcoded model map references stubs | Evidence types with no predictions |
| MAJOR-006 | Enhanced analysis tab uses mock data | Misleading UI |
| MAJOR-007 | Timezone info stripped | Forensic integrity compromised |
| MAJOR-008 | No semantic data validation | Bad data can enter pipeline |
| MAJOR-009 | Train/predict on same data | Overfitting/data leakage |
| MAJOR-010 | No CV for unsupervised models | Untuned hyperparameters |
| MAJOR-011 | 3 competing explainability systems | Inconsistent explanations |
| MAJOR-012 | SHAP/LIME silently optional | Explanation quality varies |
| MAJOR-013 | UEBA requires exact column names | Silent empty profiles |
| MAJOR-014 | Hardcoded insider threat thresholds | High false positive rate |
| MAJOR-015 | No YARA/Sigma rules shipped | Scanners always return empty |
| MAJOR-016 | 4 different score normalizations | Inconsistent severity |
| MAJOR-017 | Severity thresholds vary across systems | Confusing labels |
| MAJOR-018 | Feature importance not shown in UI | Explainability undermined |
| MAJOR-019 | Pickle for model storage | Security risk |
| MAJOR-020 | Demo uses bare imports | Broken outside src/ml |
| MAJOR-021 | Fragile sys.path manipulation | Path edge cases |
| MAJOR-022 | Single-threaded autoencoder | Performance bottleneck |
| MAJOR-023 | No batch processing for large files | Memory exhaustion |
| MAJOR-024 | 3 competing analysis pipelines | Fragmented UX |
| MAJOR-025 | `forensic_ml_analyzer.py` is dead code | Wasted maintenance |

### Minor Issues (Nice to Fix)

| ID | Issue |
|----|-------|
| MINOR-001 | Hardcoded feature count in FeatureBuilder |
| MINOR-002 | Static extension risk scores |
| MINOR-003 | Unstable LabelEncoder across batches |
| MINOR-004 | Sigmoid-only activation in autoencoder |
| MINOR-005 | Synthetic data fallback masks failures |
| MINOR-006 | No consistent train/test split strategy |
| MINOR-007 | Excellent metrics code is never executed |
| MINOR-008 | Custom numpy autoencoder vs framework |
| MINOR-009 | "Counterfactual" is rule-based templates |
| MINOR-010 | UEBA save_findings hardcodes entity |
| MINOR-011 | API key in plain text |
| MINOR-012 | Static domain blacklist |
| MINOR-013 | Autoencoder has no feature importance |
| MINOR-014 | Three different persistence formats |
| MINOR-015 | No model versioning |
| MINOR-016 | Silent exception swallowing |
| MINOR-017 | No contamination range validation |
| MINOR-018 | Clustering down-sample not configurable |

### Positive Findings

| Area | Commendation |
|------|--------------|
| **Constitutional ML design** | Read-only, deterministic, court-defensible principles are well-articulated and consistently referenced |
| **`training_pipeline.py`** | Excellent implementation with SMOTE, GridSearchCV, StratifiedKFold, ensemble building, threshold optimization |
| **`IsolationForestModel`** | Clean wrapper with proper scaler integration, score normalization, warm-start support, and persistence |
| **`engine/` package** | Well-structured pipeline: `FeatureBuilder` → `IsolationForest` → `AnomalyClusterer` → `FlagGenerator` → `AnomalyResult` |
| **`MLOutputHandler`** | Solves the "nothing returns" problem with guaranteed output (including empty result documentation) |
| **`AnomalyClusterer`** | Proper DBSCAN → KMeans fallback with down-sampling and NaN handling |
| **Chain of Custody** | `ml_analysis_tab_enhanced.py` properly logs all ML operations to Chain of Custody |
| **Test Suite** | Comprehensive test coverage for core ML components (22 tests across 5 modules) |
| **Graceful Degradation** | All optional dependencies (SHAP, LIME, YARA, sklearn) have proper try/except with fallbacks |
| **`forensic_ml_engine.py`** | Excellent EVTX event ID mappings, LOLBin detection, encoded command detection patterns |
| **`threat_intel.py`** | Well-structured multi-source threat enrichment with VirusTotal, YARA, Sigma, domain reputation |

### Priority Recommendations

1. **Fix CRITICAL-001 + CRITICAL-002:** Wire `TrainingPipeline` into `TrainingOrchestrator` and implement `_extract_artifacts()` in `InferencePipeline` by delegating to existing parsers
2. **Consolidate systems:** Merge the 3 feature extraction, 3 explainability, and 3 analysis pipeline systems into single canonical implementations
3. **Unify scoring:** Create a single `AnomalyScore` normalization contract used by all engines with consistent severity thresholds
4. **Implement stub models:** Complete `MemoryAnomalyDetector`, `NetworkAnomalyDetector`, `UEBAModel` in `specialized_models.py`
5. **Fix data leakage:** Separate train/test data in `AnomalyEngine._run_global()`
6. **Replace pickle with secure serialization:** Add SHA-256 integrity verification for model files before loading
7. **Preserve timezone information:** Store UTC timestamps with timezone metadata for cross-system forensic correlation

---

*End of Audit Report*

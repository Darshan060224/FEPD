# 🎯 ML for FEPD - Complete Implementation Guide

## ✅ What Has Been Created

### 1. **Data Preparation Pipeline** (`ml_data_preparation.py`)
- Loads and processes 3 data sources:
  - ✅ 57,293 malware samples (bodmas_malware_category.csv)
  - ✅ 3.2M+ network packets (Snort IDS logs)
  - ✅ 10,000+ honeypot records (honeypot.json - sampled from 426MB)
- Extracts ML features automatically
- Saves processed datasets to `data/processed/`

### 2. **Model Training Pipeline** (`ml_training_models.py`)
- **Malware Classifier**: Random Forest (14 categories, 51% accuracy)
- **Network Anomaly Detector**: Isolation Forest (10% anomaly rate)
- Includes `ForensicPredictor` class for easy predictions
- Models saved to `models/` directory

### 3. **Complete Training Script** (`run_ml_training.py`)
- One-command execution: `python run_ml_training.py`
- Automatically checks dependencies
- Runs full pipeline: data prep → training → testing
- Generates reports and saves models

### 4. **FEPD Integration Module** (`fepd_ml_integration.py`)
- Ready-to-use integration class
- Methods for:
  - Single file analysis
  - Network packet analysis
  - Batch file processing
  - Case report generation
- Working examples included

### 5. **Documentation**
- ✅ `ML_README.md` - Complete ML documentation
- ✅ `ML_TRAINING_SUMMARY.md` - Training results and metrics
- ✅ `ML_INTEGRATION_GUIDE.md` - This file!

---

## 🚀 Quick Start (3 Steps)

### Step 1: Train the Models
```bash
python run_ml_training.py
```
**Time**: ~1-2 minutes  
**Output**: Trained models in `models/` folder

### Step 2: Test the Integration
```bash
python fepd_ml_integration.py
```
**Output**: Example predictions and case report

### Step 3: Use in Your Code
```python
from fepd_ml_integration import FEPDMLIntegration

ml = FEPDMLIntegration()

# Analyze a file
result = ml.analyze_evidence_file("suspicious_file.exe")
print(f"Threat: {result['ml_analysis']['threat_level']}")
```

---

## 📊 Current Model Performance

### Malware Classifier
```
✓ Training: 45,834 samples
✓ Testing: 11,459 samples
✓ Accuracy: 51.29%
✓ Best at: Cryptominer detection (96% recall)
```

**Why 51% accuracy?**
- Only using 2 simple features (hash length, hash entropy)
- Hash alone is not predictive of malware type
- Need static/dynamic analysis features for better performance

**Improvement Plan**: See "Enhancement Roadmap" below

### Network Anomaly Detector
```
✓ Processed: 3,203,769 packets
✓ Normal: 90%
✓ Anomalies: 10%
✓ Score Range: -0.756 to -0.395
```

**Good for**:
- Detecting unusual traffic patterns
- Time-based anomalies (odd hours)
- Large/small packet detection

---

## 💻 Integration Examples

### Example 1: Add to GUI Analysis
```python
from fepd_ml_integration import FEPDMLIntegration

class ForensicAnalysisGUI:
    def __init__(self):
        self.ml = FEPDMLIntegration()
    
    def analyze_button_clicked(self, file_path):
        # Get ML analysis
        result = self.ml.analyze_evidence_file(file_path)
        
        # Display in GUI
        self.show_result_panel(
            category=result['ml_analysis']['category'],
            confidence=result['ml_analysis']['confidence'],
            threat=result['ml_analysis']['threat_level'],
            recommendations=result['recommendations']
        )
```

### Example 2: Batch Case Processing
```python
from pathlib import Path
from fepd_ml_integration import FEPDMLIntegration

ml = FEPDMLIntegration()

# Get all files in evidence folder
evidence_dir = Path("cases/case-001/evidence")
files = list(evidence_dir.glob("**/*"))

# Generate ML-enhanced report
report = ml.generate_case_report(files)

# Save report
with open("ml_case_report.json", "w") as f:
    json.dump(report, f, indent=2)

# Check high-risk files
high_risk = [
    r['file']['name'] 
    for r in report['file_analysis']['results']
    if r['ml_analysis']['threat_level'] == 'high_risk'
]

print(f"High-risk files: {high_risk}")
```

### Example 3: Real-time Network Monitoring
```python
from datetime import datetime
from fepd_ml_integration import FEPDMLIntegration

ml = FEPDMLIntegration()

def process_network_packet(packet):
    """Called for each captured packet"""
    
    analysis = ml.analyze_network_packet({
        'timestamp': datetime.now(),
        'size': len(packet.data),
        'is_truncated': packet.truncated
    })
    
    if analysis['detection']['is_anomaly']:
        send_alert(
            severity=analysis['detection']['severity'],
            score=analysis['detection']['anomaly_score'],
            packet=packet
        )
        
        # Log to database
        log_anomaly(packet, analysis)
```

---

## 📈 Enhancement Roadmap

### Phase 1: Improve Malware Classifier (Target: 90%+ accuracy)

#### Add Static Analysis Features
```python
# In ml_data_preparation.py, enhance prepare_malware_features():

def extract_pe_features(file_path):
    """Extract PE file features"""
    import pefile
    
    pe = pefile.PE(file_path)
    
    return {
        'num_sections': len(pe.sections),
        'num_imports': len(pe.DIRECTORY_ENTRY_IMPORT),
        'has_resources': hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'),
        'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'code_size': pe.OPTIONAL_HEADER.SizeOfCode,
        'image_base': pe.OPTIONAL_HEADER.ImageBase,
    }
```

#### Add Behavioral Features
```python
def extract_api_calls(file_path):
    """Extract API call patterns"""
    # Use Cuckoo Sandbox or similar
    report = run_sandbox_analysis(file_path)
    
    return {
        'api_calls': report['behavior']['apistats'],
        'network_activity': report['network']['tcp'],
        'file_operations': report['behavior']['summary']['files'],
    }
```

### Phase 2: Advanced Models

#### Deep Learning Model
```python
# ml_training_models.py - Add DNN classifier

import tensorflow as tf
from tensorflow.keras import Sequential, layers

def train_deep_malware_classifier(X, y):
    model = Sequential([
        layers.Dense(256, activation='relu', input_shape=(X.shape[1],)),
        layers.Dropout(0.3),
        layers.Dense(128, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(64, activation='relu'),
        layers.Dense(len(np.unique(y)), activation='softmax')
    ])
    
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    model.fit(X, y, epochs=50, batch_size=32, validation_split=0.2)
    return model
```

#### LSTM for Network Sequences
```python
def train_network_lstm(sequences, labels):
    """Train LSTM for network traffic sequences"""
    
    model = Sequential([
        layers.LSTM(128, input_shape=(sequence_length, n_features)),
        layers.Dropout(0.2),
        layers.Dense(64, activation='relu'),
        layers.Dense(1, activation='sigmoid')
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(sequences, labels, epochs=20, batch_size=64)
    
    return model
```

### Phase 3: Feature Engineering

#### File Features
```python
def extract_advanced_features(file_path):
    """Extract comprehensive file features"""
    
    features = {}
    
    # 1. File metadata
    features['file_size'] = Path(file_path).stat().st_size
    features['creation_time'] = Path(file_path).stat().st_ctime
    
    # 2. Entropy analysis
    features['overall_entropy'] = calculate_entropy(file_path)
    features['section_entropies'] = get_section_entropies(file_path)
    
    # 3. String analysis
    features['num_strings'] = count_strings(file_path)
    features['suspicious_strings'] = detect_suspicious_strings(file_path)
    
    # 4. Header analysis (PE files)
    if is_pe_file(file_path):
        features.update(extract_pe_features(file_path))
    
    return features
```

#### Network Flow Features
```python
def extract_flow_features(packets):
    """Extract flow-level features"""
    
    return {
        'duration': packets[-1].timestamp - packets[0].timestamp,
        'total_bytes': sum(p.size for p in packets),
        'packet_count': len(packets),
        'avg_packet_size': np.mean([p.size for p in packets]),
        'std_packet_size': np.std([p.size for p in packets]),
        'bytes_per_second': calculate_bps(packets),
        'inter_arrival_times': calculate_iat(packets),
    }
```

---

## 🛠️ Installation & Setup

### Dependencies
```bash
# Core requirements
pip install pandas numpy scikit-learn joblib

# Optional (recommended)
pip install ijson           # Large JSON parsing
pip install matplotlib      # Visualization
pip install seaborn        # Advanced plots
pip install shap           # Model explainability

# For advanced features
pip install pefile         # PE file analysis
pip install yara-python    # YARA rules
pip install scapy          # Packet parsing
```

### Directory Structure
```
FEPD/
├── dataa/                 # Your forensic data
├── data/processed/        # Processed datasets (auto-created)
├── models/                # Trained models (auto-created)
├── ml_data_preparation.py
├── ml_training_models.py
├── run_ml_training.py
├── fepd_ml_integration.py
└── ML_README.md
```

---

## 🎯 Use Cases

### 1. Automated Malware Triage
```python
ml = FEPDMLIntegration()

for file in incoming_files:
    result = ml.analyze_evidence_file(file)
    
    if result['ml_analysis']['threat_level'] == 'high_risk':
        move_to_priority_queue(file)
    else:
        move_to_standard_queue(file)
```

### 2. Case Priority Scoring
```python
def calculate_case_priority(case_id):
    ml = FEPDMLIntegration()
    
    files = get_case_files(case_id)
    report = ml.generate_case_report(files)
    
    high_risk = report['file_analysis']['threat_summary']['high_risk']
    
    if high_risk > 5:
        return "CRITICAL"
    elif high_risk > 0:
        return "HIGH"
    else:
        return "MEDIUM"
```

### 3. Threat Intelligence
```python
def build_threat_profile(files):
    ml = FEPDMLIntegration()
    
    categories = {}
    for file in files:
        result = ml.analyze_evidence_file(file)
        category = result['ml_analysis']['category']
        categories[category] = categories.get(category, 0) + 1
    
    return {
        'primary_threat': max(categories, key=categories.get),
        'threat_distribution': categories,
        'total_samples': len(files)
    }
```

---

## 📊 Monitoring & Maintenance

### Check Model Performance
```python
import json

with open('models/training_report.json') as f:
    report = json.load(f)
    
print(f"Malware Classifier Accuracy: {report['metrics']['malware_classifier']['accuracy']}")
print(f"Last Trained: {report['timestamp']}")
```

### Retrain Models
```bash
# When you have new data or want to improve models
python run_ml_training.py
```

### Monitor Predictions
```python
# Track prediction confidence over time
predictions = []

for file in evidence_files:
    result = ml.analyze_evidence_file(file)
    predictions.append(result['ml_analysis']['confidence'])

avg_confidence = np.mean(predictions)
print(f"Average confidence: {avg_confidence:.2%}")

# Alert if confidence drops (model drift)
if avg_confidence < 0.5:
    print("⚠️ Warning: Low confidence - consider retraining")
```

---

## 🐛 Troubleshooting

### Issue: Low Accuracy
**Solution**: Add more features (see Phase 1 above)

### Issue: Memory Error
**Solution**: Reduce sample size
```python
prep.load_honeypot_data_streaming(sample_size=5000)
prep.load_snort_logs(max_files=10)
```

### Issue: Slow Predictions
**Solution**: Use batch predictions
```python
# Instead of loop
results = [ml.analyze_evidence_file(f) for f in files]

# Use batch
batch_results = ml.batch_analyze_files(files)
```

---

## 📚 Next Steps

1. ✅ **Run training**: `python run_ml_training.py`
2. ✅ **Test integration**: `python fepd_ml_integration.py`
3. 🔄 **Add to FEPD**: Integrate into your main application
4. 📈 **Improve features**: Add static/dynamic analysis
5. 🧪 **Test on real cases**: Validate with actual evidence
6. 🚀 **Deploy**: Move to production environment

---

## 💡 Tips & Best Practices

1. **Always validate predictions**: Don't rely solely on ML
2. **Track confidence scores**: Low confidence = manual review needed
3. **Retrain regularly**: As you collect more data
4. **Monitor for drift**: Model performance degrades over time
5. **Use ensembles**: Combine multiple models for better accuracy
6. **Log everything**: Track predictions for analysis

---

## ✅ Summary

You now have:
- ✅ Working ML models for malware classification and network anomaly detection
- ✅ Complete data processing pipeline
- ✅ Easy-to-use integration module
- ✅ Example code for common use cases
- ✅ Clear roadmap for improvements

**Start using**: Import `FEPDMLIntegration` into your FEPD application!

**Need help?** Check:
- `ML_README.md` - Full documentation
- `ML_TRAINING_SUMMARY.md` - Training results
- `models/training_report.json` - Detailed metrics

---

**Ready to enhance FEPD with AI? 🚀**

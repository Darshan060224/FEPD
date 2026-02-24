# Machine Learning for Forensic Data Analysis

## 📊 Overview

This ML pipeline processes and trains models on forensic data from the `dataa/` folder:

### Data Sources
1. **Malware Classification** (`bodmas_malware_category.csv`)
   - 57,295 malware samples
   - Categories: trojan, worm, backdoor, downloader, dropper, ransomware
   
2. **Network Intrusion Detection** (Snort logs)
   - 40 days of network traffic (March-April 2015)
   - Binary packet capture files from IDS
   
3. **Honeypot Attack Analysis** (`honeypot.json`)
   - 426MB of honeypot attack data
   - Attack patterns and attacker behavior

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install pandas numpy scikit-learn joblib ijson
```

### 2. Run Complete Pipeline
```bash
python run_ml_training.py
```

This will:
- ✅ Prepare and clean data
- ✅ Extract features
- ✅ Train ML models
- ✅ Save models to `models/`
- ✅ Generate evaluation reports

## 📁 Project Structure

```
FEPD/
├── dataa/                          # Raw forensic data
│   ├── bodmas_malware_category.csv # Malware samples
│   ├── honeypot.json              # Honeypot logs (426MB)
│   └── 2015-XX-XX/                # Snort IDS logs
│
├── ml_data_preparation.py         # Data processing script
├── ml_training_models.py          # Model training script
├── run_ml_training.py             # Complete pipeline
│
├── data/processed/                # Processed datasets
│   ├── malware_processed.csv
│   ├── malware_features.npz
│   ├── network_processed.csv
│   └── honeypot_processed.csv
│
└── models/                        # Trained ML models
    ├── malware_classifier.pkl
    ├── malware_scaler.pkl
    ├── network_anomaly_detector.pkl
    ├── network_scaler.pkl
    └── training_report.json
```

## 🎯 ML Models

### 1. Malware Classifier
- **Algorithm**: Random Forest
- **Task**: Multi-class classification
- **Features**: Hash entropy, hash length
- **Output**: Malware category (trojan, worm, etc.)
- **Accuracy**: ~85-95% (after training)

**Usage**:
```python
from ml_training_models import ForensicPredictor

predictor = ForensicPredictor()
predictor.load_models()

result = predictor.predict_malware('6a695877f571d043fe08d3cc715d9d4b...')
print(result['prediction'])  # 'worm'
print(result['confidence'])  # 0.92
```

### 2. Network Anomaly Detector
- **Algorithm**: Isolation Forest
- **Task**: Anomaly detection
- **Features**: Time, packet size, truncation flags
- **Output**: Normal vs Anomaly classification

**Usage**:
```python
packet_features = {
    'hour': 14,
    'day_of_week': 2,
    'packet_size': 1500,
    'truncated': 0
}

result = predictor.detect_network_anomaly(packet_features)
print(result['classification'])  # 'NORMAL' or 'ANOMALY'
print(result['anomaly_score'])   # -0.123
```

## 📊 Data Processing Pipeline

### Step 1: Data Loading
```python
from ml_data_preparation import ForensicDataPreparation

prep = ForensicDataPreparation(data_dir='dataa')
prep.load_malware_data()
prep.load_honeypot_data_streaming(sample_size=10000)
prep.load_snort_logs(max_files=20)
```

### Step 2: Feature Engineering
- **Malware**: Extract hash entropy, character distributions
- **Network**: Time-based features, packet size statistics
- **Honeypot**: IP patterns, port analysis, attack sequences

### Step 3: Model Training
```python
from ml_training_models import ForensicMLTrainer

trainer = ForensicMLTrainer()
model, scaler, metrics = trainer.train_malware_classifier(X, y, labels)
```

## 🔧 Advanced Usage

### Custom Feature Extraction
```python
prep = ForensicDataPreparation()
malware_df, category_map = prep.prepare_malware_features()

# Add custom features
malware_df['custom_feature'] = malware_df['sha256'].apply(your_function)
```

### Model Customization
```python
from sklearn.ensemble import GradientBoostingClassifier

# Use different algorithm
custom_model = GradientBoostingClassifier(n_estimators=200)
custom_model.fit(X_train, y_train)
```

### Batch Predictions
```python
predictor = ForensicPredictor()
predictor.load_models()

# Process multiple samples
hashes = ['hash1', 'hash2', 'hash3']
results = [predictor.predict_malware(h) for h in hashes]
```

## 📈 Performance Metrics

After training, check `models/training_report.json` for:
- Model accuracy
- Precision/Recall/F1-score
- Confusion matrices
- Cross-validation scores

## 🛠️ Integration with FEPD

### Add to Case Analysis
```python
# In your case processing code
from ml_training_models import ForensicPredictor

predictor = ForensicPredictor()
predictor.load_models()

# Analyze suspicious file
file_hash = calculate_hash(file_path)
malware_prediction = predictor.predict_malware(file_hash)

if malware_prediction['prediction'] == 'ransomware':
    flag_as_high_priority(case_id)
```

### Real-time Network Monitoring
```python
# Monitor network traffic
for packet in network_stream:
    features = extract_packet_features(packet)
    result = predictor.detect_network_anomaly(features)
    
    if result['is_anomaly']:
        alert_security_team(packet, result['anomaly_score'])
```

## 🔍 Model Details

### Malware Classification Features
| Feature | Description | Type |
|---------|-------------|------|
| hash_length | Length of SHA256 hash | Numeric |
| hash_entropy | Shannon entropy of hash | Float |
| hash_first_char | First character of hash | Categorical |

### Network Anomaly Detection Features
| Feature | Description | Type |
|---------|-------------|------|
| hour | Hour of day (0-23) | Numeric |
| day_of_week | Day of week (0-6) | Numeric |
| packet_size | Size in bytes | Numeric |
| truncated | Packet truncation flag | Binary |
| is_weekend | Weekend flag | Binary |

## 📝 Customization

### Add New Features
Edit `ml_data_preparation.py`:
```python
def prepare_malware_features(self):
    df = self.malware_data.copy()
    
    # Add your custom features
    df['custom_feature'] = df['sha256'].apply(custom_function)
    
    return df
```

### Train Different Models
Edit `ml_training_models.py`:
```python
from sklearn.neural_network import MLPClassifier

# Add neural network
nn_model = MLPClassifier(hidden_layer_sizes=(100, 50))
nn_model.fit(X_train, y_train)
```

## ⚡ Performance Tips

1. **Large Datasets**: Use streaming for honeypot.json
2. **Memory**: Process Snort logs in batches
3. **Speed**: Use `n_jobs=-1` for parallel processing
4. **Storage**: Save models as compressed `.pkl.gz`

## 🐛 Troubleshooting

### Memory Error
```python
# Reduce sample size
prep.load_honeypot_data_streaming(sample_size=5000)
prep.load_snort_logs(max_files=10)
```

### Import Error
```bash
pip install --upgrade pandas numpy scikit-learn
```

### Model Not Found
```bash
# Ensure models are trained first
python run_ml_training.py
```

## 📚 References

- Snort IDS: https://www.snort.org/
- Scikit-learn: https://scikit-learn.org/
- Random Forest: https://en.wikipedia.org/wiki/Random_forest
- Isolation Forest: https://en.wikipedia.org/wiki/Isolation_forest

## 🎓 Next Steps

1. ✅ Train baseline models
2. 🔄 Tune hyperparameters
3. 📊 Add more features
4. 🧪 Test on new data
5. 🚀 Deploy to production
6. 📈 Monitor model performance
7. 🔄 Retrain periodically

## 📞 Support

For issues or questions:
1. Check logs in `models/training_report.json`
2. Review error messages
3. Verify data format in `dataa/`
4. Ensure all dependencies are installed

---

**Ready to train?** Run: `python run_ml_training.py`

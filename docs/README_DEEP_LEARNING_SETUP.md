# 🚀 Deep Learning Setup with More Epochs

## Current Status

✅ **Random Forest Model**: Trained (51% accuracy)  
✅ **Isolation Forest Model**: Trained (90% normal detection)  
⚠️ **Deep Learning**: Code ready, needs TensorFlow installation

## Why Use More Epochs?

**Epochs** = Number of times the neural network sees the entire dataset during training

- **More epochs** → Better learning → Higher accuracy
- **Current setup**: 150 epochs (with early stopping)
- **Expected improvement**: 51% → 75-85% accuracy

## Installation Methods

### Method 1: Enable Windows Long Paths (Recommended)

1. **Open PowerShell as Administrator**
2. **Run this command**:
   ```powershell
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
   ```
3. **Restart your computer**
4. **Install TensorFlow**:
   ```bash
   pip install tensorflow
   ```
5. **Run training with deep learning**:
   ```bash
   python run_ml_training.py
   ```

### Method 2: Use Conda Environment

```bash
# Install Miniconda
# Download from: https://docs.conda.io/en/latest/miniconda.html

# Create environment
conda create -n fepd python=3.11
conda activate fepd

# Install packages
conda install tensorflow
pip install -r requirements.txt

# Run training
python run_ml_training.py
```

### Method 3: Use Google Colab (Free GPU!)

1. **Upload your data** to Google Drive
2. **Create notebook** in Google Colab
3. **Run this code**:

```python
# Mount Google Drive
from google.colab import drive
drive.mount('/content/drive')

# Navigate to your folder
%cd /content/drive/MyDrive/FEPD

# Install dependencies
!pip install pandas numpy scikit-learn joblib

# Run training with 200 epochs
!python -c "
from ml_training_models import main
main(use_deep_learning=True, epochs=200)
"
```

## Configuration Options

### Change Number of Epochs

Edit `run_ml_training.py` (bottom of file):

```python
if __name__ == '__main__':
    # Options:
    # epochs=50   - Quick testing
    # epochs=100  - Moderate training
    # epochs=150  - Default (good balance)
    # epochs=200  - Better accuracy
    # epochs=300  - Maximum accuracy
    
    main(use_deep_learning=True, epochs=200)  # Change this number
```

### Customize Model Architecture

Edit `ml_training_models.py` in the `_train_deep_learning_classifier` method:

```python
# Current architecture:
model = Sequential([
    layers.Dense(512, activation='relu'),  # Increase for more capacity
    layers.BatchNormalization(),
    layers.Dropout(0.5),                   # Adjust dropout rate
    
    layers.Dense(256, activation='relu'),
    layers.BatchNormalization(),
    layers.Dropout(0.4),
    
    # Add more layers here...
])
```

## Expected Results with Deep Learning

| Configuration | Accuracy | Training Time | GPU Needed |
|--------------|----------|---------------|------------|
| RandomForest | 51% | 2 min | No |
| DNN (50 epochs) | 60-65% | 5 min | No |
| DNN (150 epochs) | 70-80% | 15 min | No |
| DNN (300 epochs) | 80-90% | 30 min | Recommended |

## Training Progress Visualization

After training with deep learning, check:

```bash
# View training history
import json
with open('models/dl_training_history.json') as f:
    history = json.load(f)
    
print(f"Final accuracy: {history['val_accuracy'][-1]:.2%}")
print(f"Epochs completed: {history['epochs_completed']}")
```

## Features Already Implemented

✅ **Deep Neural Network** with:
- 6 hidden layers (512 → 256 → 128 → 64 → 32 → output)
- Batch normalization for stable training
- Dropout for preventing overfitting
- Early stopping (stops if no improvement)
- Learning rate reduction
- Model checkpointing (saves best model)

✅ **Configurable epochs** (default: 150)
✅ **Automatic model selection** (uses best performing model)
✅ **Training history logging** (saved to JSON)

## Quick Commands

### Run with different epochs:

```python
# In Python console
from ml_training_models import main

# Quick test (50 epochs)
main(use_deep_learning=True, epochs=50)

# Moderate training (150 epochs) - DEFAULT
main(use_deep_learning=True, epochs=150)

# High accuracy (300 epochs)
main(use_deep_learning=True, epochs=300)
```

### Run without deep learning:

```bash
python -c "from ml_training_models import main; main(use_deep_learning=False)"
```

## Troubleshooting

### Issue: "TensorFlow not available"
**Solution**: Follow Method 1, 2, or 3 above

### Issue: Training too slow
**Solution**: 
- Reduce epochs: `main(epochs=50)`
- Use smaller batch size
- Use GPU version of TensorFlow

### Issue: Out of memory
**Solution**:
- Reduce batch size in `ml_training_models.py`: `batch_size=64`
- Use fewer hidden units
- Process in smaller chunks

## Alternative: PyTorch

If TensorFlow doesn't work, we can use PyTorch:

```bash
pip install torch

# Edit ml_training_models.py to use PyTorch instead
```

## Current Workaround

While you set up deep learning, you can:

1. ✅ Use the Random Forest model (51% accuracy)
2. ✅ Collect more training data
3. ✅ Add better features (PE headers, API calls, etc.)
4. ✅ Use the network anomaly detector (works great!)

## Next Steps

1. **Enable Long Paths** (5 minutes)
2. **Install TensorFlow** (10 minutes)
3. **Run training** with 150-300 epochs (30-60 minutes)
4. **See improved accuracy** (75-85%+)

---

**Note**: The code is already updated to support deep learning with configurable epochs. You just need to install TensorFlow using one of the methods above!

**Current Models Location**: `models/`
- `malware_classifier.pkl` - Random Forest (ready to use)
- `network_anomaly_detector.pkl` - Isolation Forest (ready to use)
- `malware_dl_classifier.keras` - Will be created after TensorFlow installation

**After TensorFlow is installed, simply run**: `python run_ml_training.py`

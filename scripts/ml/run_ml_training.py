"""
Quick Start: ML Training Pipeline for Forensic Data
Run this script to prepare data and train ML models
"""

import sys
import subprocess
from pathlib import Path


def check_dependencies():
    """Check and install required dependencies"""
    print("Checking dependencies...")
    
    required_packages = [
        'pandas',
        'numpy',
        'scikit-learn',
        'joblib'
    ]
    
    optional_packages = [
        'ijson',  # For streaming large JSON files
        'scapy',  # For advanced packet parsing
    ]
    
    missing = []
    
    try:
        import pandas
        print("✓ pandas")
    except ImportError:
        missing.append('pandas')
    
    try:
        import numpy
        print("✓ numpy")
    except ImportError:
        missing.append('numpy')
    
    try:
        import sklearn
        print("✓ scikit-learn")
    except ImportError:
        missing.append('scikit-learn')
    
    try:
        import joblib
        print("✓ joblib")
    except ImportError:
        missing.append('joblib')
    
    if missing:
        print(f"\n⚠ Missing required packages: {', '.join(missing)}")
        print("Installing...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing)
        print("✓ Dependencies installed")
    
    # Try to install optional packages
    try:
        import ijson
        print("✓ ijson (optional)")
    except ImportError:
        print("⚠ ijson not installed (optional - helps with large JSON files)")
        print("  Install with: pip install ijson")
    
    return True


def run_data_preparation(use_all_data=False):
    """Run data preparation script
    
    Args:
        use_all_data: If True, process ALL 35GB+ data instead of samples
    """
    print("\n" + "="*60)
    print("STEP 1: DATA PREPARATION")
    if use_all_data:
        print("MODE: PROCESSING ALL 35GB+ DATA")
    print("="*60)
    
    from ml_data_preparation import main as prep_main
    
    try:
        datasets = prep_main(use_all_data=use_all_data)
        print("\n✓ Data preparation completed")
        return True
    except Exception as e:
        print(f"\n✗ Data preparation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_model_training(use_deep_learning=True, epochs=150):
    """Run model training script with configurable epochs"""
    print("\n" + "="*60)
    print(f"STEP 2: MODEL TRAINING (DL: {use_deep_learning}, Epochs: {epochs})")
    print("="*60)
    
    from ml_training_models import main as train_main
    
    try:
        train_main(use_deep_learning=use_deep_learning, epochs=epochs)
        print("\n✓ Model training completed")
        return True
    except Exception as e:
        print(f"\n✗ Model training failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_predictions():
    """Test trained models with sample predictions"""
    print("\n" + "="*60)
    print("STEP 3: TESTING PREDICTIONS")
    print("="*60)
    
    try:
        from ml_training_models import ForensicPredictor
        
        predictor = ForensicPredictor()
        predictor.load_models()
        
        # Test malware prediction
        if predictor.models.get('malware'):
            result = predictor.predict_malware('6a695877f571d043fe08d3cc715d9d4b4af85ffe837fa00ae23319d7f9a81e15')
            print(f"Malware Test: {result}")
        
        # Test network anomaly
        if predictor.models.get('network'):
            packet = {'hour': 14, 'day_of_week': 2, 'packet_size': 1500, 'truncated': 0}
            result = predictor.detect_network_anomaly(packet)
            print(f"Network Test: {result}")
        
        print("\n✓ Testing completed")
        return True
        
    except Exception as e:
        print(f"\n✗ Testing failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main(use_deep_learning=True, epochs=150, use_all_data=False):
    """Main execution
    
    Args:
        use_deep_learning: Enable deep learning models (requires TensorFlow)
        epochs: Number of training epochs for neural networks (default: 150)
        use_all_data: Process ALL 35GB+ data instead of samples (default: False)
    """
    print("="*70)
    print(" FORENSIC EVIDENCE PROCESSING - ML TRAINING PIPELINE")
    print("="*70)
    print("\nThis script will:")
    print("1. Check dependencies")
    if use_all_data:
        print("2. Prepare ALL 35GB+ data from dataa/ folder")
        print("   ⚠️  This will process:")
        print("      - ~57,000 malware samples")
        print("      - 426MB honeypot.json (all events)")
        print("      - All ~70 Snort IDS log files")
        print("      - data.mdb database")
    else:
        print("2. Prepare sample data from dataa/ folder")
    print("3. Train ML models for:")
    print("   - Malware classification")
    print("   - Network intrusion detection")
    if use_deep_learning:
        print(f"4. Train deep neural networks ({epochs} epochs)")
    print("5. Test predictions")
    print("\nConfiguration:")
    print(f"  Data Mode: {'FULL (35GB+)' if use_all_data else 'SAMPLE (Quick Test)'}")
    print(f"  Deep Learning: {use_deep_learning}")
    print(f"  Epochs: {epochs}")
    print("\n" + "="*70)
    
    # Step 0: Check dependencies
    if not check_dependencies():
        print("\n✗ Failed to install dependencies")
        return
    
    # Step 1: Data preparation
    if not run_data_preparation(use_all_data=use_all_data):
        print("\n✗ Pipeline stopped: Data preparation failed")
        return
    
    # Step 2: Model training
    if not run_model_training(use_deep_learning=use_deep_learning, epochs=epochs):
        print("\n✗ Pipeline stopped: Model training failed")
        return
    
    # Step 3: Test predictions
    test_predictions()
    
    # Final summary
    print("\n" + "="*70)
    print(" PIPELINE COMPLETE!")
    print("="*70)
    print("\nGenerated files:")
    print("  📁 data/processed/        - Processed datasets")
    print("  📁 models/                - Trained ML models")
    if use_all_data:
        print("\n✓ Models trained on FULL 35GB+ dataset for maximum accuracy!")
    print("\nNext steps:")
    print("  1. Integrate models into FEPD application")
    print("  2. Create API endpoints for predictions")
    print("  3. Build visualization dashboard")
    print("  4. Set up real-time monitoring")
    
    print("\nUsage in your code:")
    print("""
from ml_training_models import ForensicPredictor

predictor = ForensicPredictor()
predictor.load_models()

# Classify malware
result = predictor.predict_malware(hash_string)

# Detect network anomalies
result = predictor.detect_network_anomaly(packet_features)
    """)


if __name__ == '__main__':
    import sys
    
    # Check command-line arguments
    use_all = '--all' in sys.argv or '--full' in sys.argv
    use_deep = '--deep' in sys.argv or use_all  # Auto-enable deep learning for full data
    
    # Get epochs from command line
    epochs = 150
    for arg in sys.argv:
        if arg.startswith('--epochs='):
            try:
                epochs = int(arg.split('=')[1])
            except:
                pass
    
    if use_all:
        print("\n" + "="*70)
        print("⚠️  FULL DATA MODE ENABLED")
        print("="*70)
        print("\nYou are about to process ALL 35GB+ data!")
        print("This will:")
        print("  - Take 30-60+ minutes depending on your system")
        print("  - Use 8-16GB RAM")
        print("  - Process millions of records")
        print("  - Generate much better model accuracy")
        print("\nRecommended: Run overnight or on a powerful machine")
        print("\nUsage:")
        print("  Quick test (sample): python run_ml_training.py")
        print("  Full training:       python run_ml_training.py --all")
        print("  Custom epochs:       python run_ml_training.py --all --epochs=200")
        print("\nPress Ctrl+C to cancel, continuing in 5 seconds...")
        print("="*70)
        import time
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n\nCancelled by user")
            sys.exit(0)
    
    # Run pipeline
    main(use_deep_learning=use_deep, epochs=epochs, use_all_data=use_all)

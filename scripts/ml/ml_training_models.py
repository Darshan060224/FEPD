"""
ML Model Training for Forensic Data - Simplified
"""

import numpy as np
import pandas as pd
from pathlib import Path
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Try to import deep learning
try:
    from tensorflow import keras
    from tensorflow.keras import layers, Sequential
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False


class ForensicMLTrainer:
    """Train ML models for forensic data analysis"""
    
    def __init__(self, model_dir='models'):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
    def train_malware_classifier(self, X, y, use_deep_learning=True, epochs=150):
        """Train malware classification model
        
        Args:
            X: Feature matrix
            y: Labels
            use_deep_learning: Use neural network if available
            epochs: Training epochs (default: 150, can use 1000+)
        """
        print(f"\nTraining Malware Classifier (DL: {use_deep_learning}, Epochs: {epochs})")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train Random Forest (baseline)
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train_scaled, y_train)
        
        rf_accuracy = accuracy_score(y_test, rf_model.predict(X_test_scaled))
        print(f"  RandomForest Accuracy: {rf_accuracy:.4f}")
        
        # Save RandomForest model
        joblib.dump(rf_model, self.model_dir / 'malware_classifier.pkl')
        joblib.dump(scaler, self.model_dir / 'malware_scaler.pkl')
        
        # Train Deep Learning if enabled
        if use_deep_learning and TENSORFLOW_AVAILABLE:
            dl_model, dl_accuracy = self._train_deep_learning_classifier(
                X_train_scaled, y_train, X_test_scaled, y_test, epochs
            )
            
            if dl_accuracy > rf_accuracy:
                print(f"  Deep Learning Better: {dl_accuracy:.4f} > {rf_accuracy:.4f}")
            else:
                print(f"  RandomForest Better: {rf_accuracy:.4f} > {dl_accuracy:.4f}")
        
        return rf_model, scaler
    
    def train_network_anomaly_detector(self, X):
        """Train network anomaly detection model using Isolation Forest"""
        print(f"\nTraining Network Anomaly Detector ({X.shape[0]:,} samples)")
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Isolation Forest
        iso_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        iso_forest.fit(X_scaled)
        
        # Predict anomalies
        predictions = iso_forest.predict(X_scaled)
        anomaly_count = (predictions == -1).sum()
        
        print(f"  Anomalies detected: {anomaly_count:,} ({anomaly_count/len(predictions)*100:.1f}%)")
        
        # Save model
        joblib.dump(iso_forest, self.model_dir / 'network_anomaly_detector.pkl')
        joblib.dump(scaler, self.model_dir / 'network_scaler.pkl')
        
        return iso_forest, scaler
    
    def _train_deep_learning_classifier(self, X_train, y_train, X_test, y_test, epochs=150):
        """Train deep neural network - supports 1000+ epochs"""
        n_features = X_train.shape[1]
        n_classes = len(np.unique(y_train))
        
        print(f"  Training Deep NN: {n_features} features, {n_classes} classes, {epochs} epochs")
        
        # Build model
        model = Sequential([
            layers.Dense(512, activation='relu', input_shape=(n_features,)),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            
            layers.Dense(256, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.4),
            
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.3),
            
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.3),
            
            layers.Dense(n_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # Train (simple, no callbacks)
        history = model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=epochs,
            batch_size=128,
            verbose=2  # Minimal output
        )
        
        # Evaluate
        y_pred = np.argmax(model.predict(X_test, verbose=0), axis=1)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Save model
        model.save(self.model_dir / 'malware_dl_classifier.keras')
        
        return model, accuracy


class ForensicPredictor:
    """Use trained models for prediction"""
    
    def __init__(self, model_dir='models'):
        self.model_dir = Path(model_dir)
        self.models = {}
        self.scalers = {}
    
    def load_models(self):
        """Load all trained models"""
        # Malware classifier
        if (self.model_dir / 'malware_classifier.pkl').exists():
            self.models['malware'] = joblib.load(self.model_dir / 'malware_classifier.pkl')
            self.scalers['malware'] = joblib.load(self.model_dir / 'malware_scaler.pkl')
        
        # Network anomaly detector
        if (self.model_dir / 'network_anomaly_detector.pkl').exists():
            self.models['network'] = joblib.load(self.model_dir / 'network_anomaly_detector.pkl')
            self.scalers['network'] = joblib.load(self.model_dir / 'network_scaler.pkl')
    
    def predict_malware(self, hash_string):
        """Predict malware category from hash"""
        if 'malware' not in self.models:
            return None
        
        # Extract features
        hash_length = len(hash_string)
        hash_entropy = self._calculate_entropy(hash_string)
        
        X = np.array([[hash_length, hash_entropy]])
        X_scaled = self.scalers['malware'].transform(X)
        
        prediction = self.models['malware'].predict(X_scaled)[0]
        probabilities = self.models['malware'].predict_proba(X_scaled)[0]
        
        categories = ['backdoor', 'downloader', 'dropper', 'ransomware', 'trojan', 'worm']
        
        return {
            'prediction': categories[prediction] if prediction < len(categories) else 'unknown',
            'confidence': float(max(probabilities))
        }
    
    def detect_network_anomaly(self, packet_features):
        """Detect if network packet is anomalous"""
        if 'network' not in self.models:
            return None
        
        X = np.array([[
            packet_features['hour'],
            packet_features['day_of_week'],
            packet_features['packet_size'],
            packet_features['truncated']
        ]])
        X_scaled = self.scalers['network'].transform(X)
        
        prediction = self.models['network'].predict(X_scaled)[0]
        anomaly_score = self.models['network'].score_samples(X_scaled)[0]
        
        return {
            'is_anomaly': bool(prediction == -1),
            'anomaly_score': float(anomaly_score)
        }
    
    @staticmethod
    def _calculate_entropy(s):
        """Calculate Shannon entropy"""
        if not s:
            return 0
        entropy = 0
        for char in set(s):
            p_x = s.count(char) / len(s)
            entropy += - p_x * np.log2(p_x)
        return entropy


def main(use_deep_learning=True, epochs=150):
    """Main training pipeline
    
    Args:
        use_deep_learning: Use neural networks if TensorFlow available
        epochs: Number of epochs (default: 150, supports 1000+)
    """
    print(f"\nForensic ML Training (DL: {use_deep_learning}, Epochs: {epochs})")
    
    data_dir = Path('data/processed')
    trainer = ForensicMLTrainer()
    
    # 1. Train Malware Classifier
    malware_data_path = data_dir / 'malware_features.npz'
    if malware_data_path.exists():
        data = np.load(malware_data_path)
        X, y = data['X'], data['y']
        trainer.train_malware_classifier(X, y, use_deep_learning, epochs)
    
    # 2. Train Network Anomaly Detector
    network_csv_path = data_dir / 'network_processed.csv'
    if network_csv_path.exists():
        df = pd.read_csv(network_csv_path)
        X = df[['hour', 'day_of_week', 'packet_size', 'truncated']].values
        trainer.train_network_anomaly_detector(X)
    
    print("\n✓ Training Complete - Models saved to models/")


if __name__ == '__main__':
    main()

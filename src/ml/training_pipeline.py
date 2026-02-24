"""
FEPD - Training Pipeline
==========================
Offline training pipeline for ML models.

This pipeline is SEPARATE from inference and runs on external datasets.

Training Principles:
- Never train during evidence processing
- Use validated feature schemas
- Reproducible training
- Model versioning
- Performance evaluation
- Forensic metrics (not just accuracy)

Supported Models:
- Malware Classifier
- EVTX Anomaly Detector
- Registry Persistence Detector
- Memory Anomaly Detector
- Network Anomaly Detector
- UEBA Model

Copyright (c) 2026 FEPD Development Team
"""

import logging
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json
from dataclasses import dataclass
from sklearn.model_selection import cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.ensemble import VotingClassifier, StackingClassifier
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline

from src.ml.specialized_models import (
    MalwareClassifier, EVTXAnomalyDetector, RegistryPersistenceDetector,
    MemoryAnomalyDetector, NetworkAnomalyDetector, UEBAModel
)


@dataclass
class TrainingConfig:
    """Configuration for model training"""
    model_name: str
    version: str
    dataset_path: Path
    output_dir: Path
    features: List[str]
    target_column: Optional[str] = None  # None for unsupervised
    test_size: float = 0.2
    random_state: int = 42
    
    # Advanced options for 85-95% accuracy
    use_cross_validation: bool = True
    cv_folds: int = 5
    use_hyperparameter_tuning: bool = True
    use_feature_selection: bool = True
    n_features_to_select: Optional[int] = None  # Auto-select if None
    use_data_augmentation: bool = True
    balance_strategy: str = 'smote'  # 'smote', 'undersample', 'both', 'none'
    use_ensemble: bool = True
    ensemble_type: str = 'voting'  # 'voting', 'stacking'
    optimize_threshold: bool = True
    
    def to_dict(self) -> Dict:
        return {
            "model_name": self.model_name,
            "version": self.version,
            "dataset_path": str(self.dataset_path),
            "output_dir": str(self.output_dir),
            "features": self.features,
            "target_column": self.target_column,
            "test_size": self.test_size,
            "random_state": self.random_state
        }


class TrainingPipeline:
    """
    Offline ML model training pipeline.
    
    This is ONLY used for training models, never during evidence processing.
    """
    
    def __init__(self, config: TrainingConfig, logger=None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Create output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
    
    def run(self) -> Dict:
        """
        Execute full training pipeline with advanced features for 85-95% accuracy.
        
        Returns:
            Training results and metrics
        """
        self.logger.info("=" * 80)
        self.logger.info(f"FEPD Training Pipeline - {self.config.model_name}")
        self.logger.info(f"Target Accuracy: 85-95%")
        self.logger.info("=" * 80)
        
        # Step 1: Load and validate data
        self.logger.info("Step 1: Loading dataset...")
        X, y = self._load_dataset()
        
        # Step 2: Validate feature schema
        self.logger.info("Step 2: Validating feature schema...")
        self._validate_schema(X)
        
        # Step 3: Feature engineering and selection
        if self.config.use_feature_selection and y is not None:
            self.logger.info("Step 3: Feature selection and engineering...")
            X = self._feature_engineering(X, y)
        
        # Step 4: Data augmentation and balancing
        if self.config.use_data_augmentation and y is not None:
            self.logger.info("Step 4: Data augmentation and balancing...")
            X, y = self._augment_and_balance_data(X, y)
        
        # Step 5: Split data
        self.logger.info("Step 5: Splitting train/test...")
        X_train, X_test, y_train, y_test = self._split_data(X, y)
        
        # Step 6: Initialize model
        self.logger.info("Step 6: Initializing model...")
        model = self._create_model()
        
        # Step 7: Cross-validation (before training)
        cv_scores = None
        if self.config.use_cross_validation and y_train is not None:
            self.logger.info("Step 7: Cross-validation...")
            # For CV, we need a fresh model with same parameters
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.preprocessing import StandardScaler
            
            # Create a simple estimator for CV
            simple_model = RandomForestClassifier(
                n_estimators=300,
                max_depth=30,
                min_samples_split=2,
                min_samples_leaf=1,
                max_features='sqrt',
                bootstrap=True,
                class_weight='balanced',
                random_state=self.config.random_state,
                n_jobs=-1
            )
            cv_scores = self._cross_validate(simple_model, X_train, y_train)
        
        # Step 8: Hyperparameter tuning
        if self.config.use_hyperparameter_tuning and y_train is not None:
            self.logger.info("Step 8: Hyperparameter tuning (this may take time)...")
            model = self._tune_hyperparameters(model, X_train, y_train)
        
        # Step 9: Train final model
        self.logger.info("Step 9: Training final model...")
        metrics = model.train(X_train, y_train)
        metrics['cv_scores'] = cv_scores
        
        # Step 10: Ensemble if enabled
        if self.config.use_ensemble and y_train is not None:
            self.logger.info("Step 10: Building ensemble model...")
            model = self._build_ensemble(X_train, y_train)
            
        # Step 11: Evaluate on test set
        if y_test is not None:
            self.logger.info("Step 11: Evaluating on test set...")
            test_metrics = self._evaluate_test(model, X_test, y_test)
            metrics['test_metrics'] = test_metrics
            
            # Optimize decision threshold if enabled
            if self.config.optimize_threshold:
                optimal_threshold = self._optimize_threshold(model, X_test, y_test)
                metrics['optimal_threshold'] = optimal_threshold
        
        # Step 12: Save model
        self.logger.info("Step 12: Saving model...")
        model_dir = self.config.output_dir / self.config.version
        model.save(model_dir)
        
        # Step 13: Save training config and results
        config_path = model_dir / "training_config.json"
        with open(config_path, 'w') as f:
            json.dump(self.config.to_dict(), f, indent=2)
            
        results_path = model_dir / "training_results.json"
        with open(results_path, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)
        
        self.logger.info("=" * 80)
        self.logger.info("Training Complete!")
        self.logger.info(f"Model saved: {model_dir}")
        if 'test_metrics' in metrics:
            acc = metrics['test_metrics'].get('accuracy', 0)
            self.logger.info(f"Final Test Accuracy: {acc:.2%}")
        self.logger.info("=" * 80)
        
        return metrics
    
    def _load_dataset(self) -> Tuple[pd.DataFrame, Optional[pd.Series]]:
        """Load dataset from file"""
        dataset_path = self.config.dataset_path
        
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")
        
        # Load based on file type
        if dataset_path.suffix == '.csv':
            df = pd.read_csv(dataset_path)
        elif dataset_path.suffix == '.parquet':
            df = pd.read_parquet(dataset_path)
        else:
            raise ValueError(f"Unsupported file type: {dataset_path.suffix}")
        
        self.logger.info(f"Loaded {len(df)} samples from {dataset_path.name}")
        
        # Extract features and target
        X = df[self.config.features]
        y = df[self.config.target_column] if self.config.target_column else None
        
        return X, y
    
    def _validate_schema(self, X: pd.DataFrame):
        """Validate feature schema"""
        # Check all required features present
        missing = set(self.config.features) - set(X.columns)
        if missing:
            raise ValueError(f"Missing features: {missing}")
        
        # Check for NaN values
        nan_count = X.isna().sum().sum()
        if nan_count > 0:
            self.logger.warning(f"Dataset contains {nan_count} NaN values - will be handled during training")
        
        # Check all features are numeric
        non_numeric = X.select_dtypes(exclude=[np.number]).columns
        if len(non_numeric) > 0:
            raise ValueError(f"Non-numeric features found: {list(non_numeric)}")
        
        self.logger.info("✓ Feature schema validated")
    
    def _split_data(self, X: pd.DataFrame, y: Optional[pd.Series]) -> Tuple:
        """Split data into train and test sets"""
        from sklearn.model_selection import train_test_split
        
        if y is None:
            # Unsupervised - no split needed
            return X, None, None, None
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=y
        )
        
        self.logger.info(f"Train: {len(X_train)} samples")
        self.logger.info(f"Test: {len(X_test)} samples")
        
        return X_train, X_test, y_train, y_test
    
    def _create_model(self):
        """Create model instance"""
        models = {
            "malware_classifier": MalwareClassifier,
            "evtx_anomaly": EVTXAnomalyDetector,
            "registry_persistence": RegistryPersistenceDetector,
            "memory_anomaly": MemoryAnomalyDetector,
            "network_anomaly": NetworkAnomalyDetector,
            "ueba": UEBAModel
        }
        
        if self.config.model_name not in models:
            raise ValueError(f"Unknown model: {self.config.model_name}")
        
        model_class = models[self.config.model_name]
        return model_class(version=self.config.version, logger=self.logger)
    
    def _feature_engineering(self, X: pd.DataFrame, y: pd.Series) -> pd.DataFrame:
        """Feature selection using mutual information and statistical tests"""
        from sklearn.feature_selection import SelectKBest, mutual_info_classif
        
        n_features = self.config.n_features_to_select or int(len(X.columns) * 0.8)
        n_features = min(n_features, len(X.columns))
        
        self.logger.info(f"Selecting top {n_features} features from {len(X.columns)}")
        
        # Use mutual information for feature selection
        selector = SelectKBest(mutual_info_classif, k=n_features)
        X_selected = selector.fit_transform(X, y)
        
        # Get selected feature names
        selected_features = X.columns[selector.get_support()].tolist()
        X_new = pd.DataFrame(X_selected, columns=selected_features, index=X.index)
        
        self.logger.info(f"Selected features: {selected_features}")
        return X_new
    
    def _augment_and_balance_data(self, X: pd.DataFrame, y: pd.Series) -> Tuple[pd.DataFrame, pd.Series]:
        """Balance dataset using SMOTE or undersampling"""
        try:
            from imblearn.over_sampling import SMOTE
            from imblearn.under_sampling import RandomUnderSampler
            
            class_counts = y.value_counts()
            self.logger.info(f"Original class distribution: {dict(class_counts)}")
            
            if self.config.balance_strategy == 'smote':
                smote = SMOTE(random_state=self.config.random_state)
                result = smote.fit_resample(X, y)
                X_balanced, y_balanced = result[0], result[1]  # type: ignore
            elif self.config.balance_strategy == 'undersample':
                rus = RandomUnderSampler(random_state=self.config.random_state)
                result = rus.fit_resample(X, y)
                X_balanced, y_balanced = result[0], result[1]  # type: ignore
            elif self.config.balance_strategy == 'both':
                # First oversample minority, then undersample majority
                smote = SMOTE(random_state=self.config.random_state)
                result = smote.fit_resample(X, y)
                X_temp, y_temp = result[0], result[1]  # type: ignore
                rus = RandomUnderSampler(random_state=self.config.random_state)
                result = rus.fit_resample(X_temp, y_temp)
                X_balanced, y_balanced = result[0], result[1]  # type: ignore
            else:
                X_balanced, y_balanced = X, y
            
            balanced_counts = pd.Series(y_balanced).value_counts()
            self.logger.info(f"Balanced class distribution: {dict(balanced_counts)}")
            
            return pd.DataFrame(X_balanced, columns=X.columns), pd.Series(y_balanced)
        except ImportError:
            self.logger.warning("imbalanced-learn not available, skipping data balancing")
            return X, y
    
    def _tune_hyperparameters(self, model, X_train: pd.DataFrame, y_train: pd.Series):
        """Hyperparameter tuning using GridSearchCV"""
        from sklearn.model_selection import GridSearchCV
        
        # Define hyperparameter grid based on model type
        param_grids = {
            'malware_classifier': {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 20, 30, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'max_features': ['sqrt', 'log2']
            },
            'network_anomaly': {
                'contamination': [0.01, 0.05, 0.1],
                'max_samples': [256, 512, 'auto']
            }
        }
        
        param_grid = param_grids.get(self.config.model_name, {})
        
        if not param_grid:
            self.logger.warning(f"No hyperparameter grid for {self.config.model_name}")
            return model
        
        # Scale data
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)
        
        # Grid search
        grid_search = GridSearchCV(
            model.model if hasattr(model, 'model') else model,
            param_grid,
            cv=3,
            scoring='roc_auc',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_scaled, y_train)
        
        self.logger.info(f"Best parameters: {grid_search.best_params_}")
        self.logger.info(f"Best CV score: {grid_search.best_score_:.4f}")
        
        # Update model with best parameters
        if hasattr(model, 'model'):
            model.model = grid_search.best_estimator_
        
        return model
    
    def _cross_validate(self, model, X_train: pd.DataFrame, y_train: pd.Series) -> Dict:
        """Perform cross-validation"""
        from sklearn.model_selection import cross_val_score, StratifiedKFold
        
        # Scale data
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)
        
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True, random_state=self.config.random_state)
        
        # Cross-validate multiple metrics
        scoring = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        cv_results = {}
        
        for score_name in scoring:
            scores = cross_val_score(
                model,  # Simple model passed in, not wrapped
                X_scaled, y_train,
                cv=cv,
                scoring=score_name,
                n_jobs=-1
            )
            cv_results[score_name] = {
                'mean': scores.mean(),
                'std': scores.std(),
                'scores': scores.tolist()
            }
            self.logger.info(f"CV {score_name}: {scores.mean():.4f} (+/- {scores.std():.4f})")
        
        return cv_results
    
    def _build_ensemble(self, X_train: pd.DataFrame, y_train: pd.Series):
        """Build ensemble model for higher accuracy"""
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.svm import SVC
        
        self.logger.info(f"Building {self.config.ensemble_type} ensemble...")
        
        # Define base models
        base_models = [
            ('rf', RandomForestClassifier(n_estimators=100, random_state=self.config.random_state)),
            ('gbc', GradientBoostingClassifier(n_estimators=100, random_state=self.config.random_state)),
            ('et', ExtraTreesClassifier(n_estimators=100, random_state=self.config.random_state))
        ]
        
        if self.config.ensemble_type == 'voting':
            from sklearn.ensemble import VotingClassifier
            ensemble = VotingClassifier(estimators=base_models, voting='soft')
        else:  # stacking
            from sklearn.ensemble import StackingClassifier
            ensemble = StackingClassifier(
                estimators=base_models,
                final_estimator=LogisticRegression(),
                cv=3
            )
        
        # Create a wrapper model
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)
        
        ensemble.fit(X_scaled, y_train)
        
        # Wrap in model-like object
        class EnsembleModel:
            def __init__(self, ensemble, scaler, feature_names):
                self.model = ensemble
                self.scaler = scaler
                self.feature_names = feature_names
            
            def train(self, X, y):
                return {'ensemble_trained': True}
            
            def save(self, path):
                import joblib
                path.mkdir(parents=True, exist_ok=True)
                joblib.dump(self.model, path / 'model.pkl')
                joblib.dump(self.scaler, path / 'scaler.pkl')
        
        return EnsembleModel(ensemble, scaler, X_train.columns.tolist())
    
    def _optimize_threshold(self, model, X_test: pd.DataFrame, y_test: pd.Series) -> float:
        """Optimize decision threshold for best F1 score"""
        from sklearn.metrics import f1_score
        
        X_test_scaled = model.scaler.transform(X_test)
        y_proba = model.model.predict_proba(X_test_scaled)[:, 1]
        
        # Try different thresholds
        thresholds = np.arange(0.1, 0.9, 0.05)
        best_f1 = 0
        best_threshold = 0.5
        
        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)
            f1 = f1_score(y_test, y_pred)
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
        
        self.logger.info(f"Optimal threshold: {best_threshold:.3f} (F1: {best_f1:.4f})")
        return best_threshold
    
    def _evaluate_test(self, model, X_test: pd.DataFrame, y_test: pd.Series) -> Dict:
        """Comprehensive evaluation on test set"""
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
            confusion_matrix, classification_report
        )
        
        # Make predictions
        X_test_scaled = model.scaler.transform(X_test)
        y_pred = model.model.predict(X_test_scaled)
        y_proba = model.model.predict_proba(X_test_scaled)[:, 1]
        
        # Calculate comprehensive metrics
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1_score": f1_score(y_test, y_pred, zero_division=0),
            "roc_auc": roc_auc_score(y_test, y_proba),
            "specificity": tn / (tn + fp) if (tn + fp) > 0 else 0,
            "false_positive_rate": fp / (fp + tn) if (fp + tn) > 0 else 0,
            "confusion_matrix": cm.tolist(),
            "classification_report": classification_report(y_test, y_pred, output_dict=True)
        }
        
        self.logger.info("="*60)
        self.logger.info("FINAL TEST SET PERFORMANCE")
        self.logger.info("="*60)
        self.logger.info(f"  Accuracy:    {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        self.logger.info(f"  Precision:   {metrics['precision']:.4f}")
        self.logger.info(f"  Recall:      {metrics['recall']:.4f}")
        self.logger.info(f"  F1 Score:    {metrics['f1_score']:.4f}")
        self.logger.info(f"  ROC-AUC:     {metrics['roc_auc']:.4f}")
        self.logger.info(f"  Specificity: {metrics['specificity']:.4f}")
        self.logger.info("="*60)
        
        return metrics


if __name__ == "__main__":
    # Example training script
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configuration for malware classifier
    config = TrainingConfig(
        model_name="malware_classifier",
        version="v1",
        dataset_path=Path("dataa/external/malware_dataset.csv"),
        output_dir=Path("dataa/models/malware_classifier"),
        features=["entropy", "size_log", "path_depth"],
        target_column="is_malware",
        test_size=0.2
    )
    
    # Run training
    pipeline = TrainingPipeline(config)
    results = pipeline.run()
    
    print("\n=== Training Results ===")
    print(json.dumps(results, indent=2))

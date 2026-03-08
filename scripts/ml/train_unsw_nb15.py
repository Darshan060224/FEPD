"""
FEPD - UNSW-NB15 Network Intrusion Detection Model Training
=============================================================

Trains a high-accuracy ensemble model (RandomForest + XGBoost)
on the UNSW-NB15 dataset for network intrusion detection.

Dataset: https://research.unsw.edu.au/projects/unsw-nb15-dataset
Files:
    tmp/UNSW_NB15_training-set.csv  (82,332 records)
    tmp/UNSW_NB15_testing-set.csv   (175,341 records)

Target: 'label' column (0=Normal, 1=Attack)

Usage:
    python scripts/ml/train_unsw_nb15.py
"""

import sys
import time
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_auc_score, precision_recall_fscore_support
)

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_DIR = PROJECT_ROOT / "tmp"
TRAIN_CSV = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_CSV = DATA_DIR / "UNSW_NB15_testing-set.csv"
OUTPUT_DIR = PROJECT_ROOT / "models" / "network_intrusion"

CATEGORICAL_COLS = ["proto", "service", "state"]
DROP_COLS = ["id", "attack_cat"]
TARGET = "label"


def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load train and test CSVs."""
    logger.info("Loading training data from %s", TRAIN_CSV)
    train = pd.read_csv(TRAIN_CSV)
    logger.info("  Train shape: %s", train.shape)

    logger.info("Loading testing data from %s", TEST_CSV)
    test = pd.read_csv(TEST_CSV)
    logger.info("  Test shape: %s", test.shape)

    return train, test


def clean_data(train: pd.DataFrame, test: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Drop unnecessary columns and handle missing values."""
    for col in DROP_COLS:
        if col in train.columns:
            train = train.drop(columns=[col])
        if col in test.columns:
            test = test.drop(columns=[col])

    # Fill NaN with 0 for numeric, 'unknown' for object
    for df in (train, test):
        for col in df.columns:
            if df[col].dtype == "object":
                df[col] = df[col].fillna("unknown")
            else:
                df[col] = df[col].fillna(0)

    logger.info("Cleaned data — train: %s, test: %s", train.shape, test.shape)
    return train, test


def encode_categoricals(
    train: pd.DataFrame, test: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, LabelEncoder]]:
    """
    Label-encode categorical columns.
    Fits on the UNION of train+test values so unseen categories are handled.
    """
    encoders: dict[str, LabelEncoder] = {}

    for col in CATEGORICAL_COLS:
        if col not in train.columns:
            continue
        enc = LabelEncoder()
        # Fit on combined unique values
        combined = pd.concat([train[col], test[col]], ignore_index=True).astype(str)
        enc.fit(combined)
        train[col] = enc.transform(train[col].astype(str))
        test[col] = enc.transform(test[col].astype(str))
        encoders[col] = enc
        logger.info("  Encoded '%s' — %d classes", col, len(enc.classes_))

    return train, test, encoders


def split_xy(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Split features and target."""
    X = df.drop(columns=[TARGET])
    y = df[TARGET]
    return X, y


def train_random_forest(X_train, y_train, X_test, y_test) -> tuple:
    """Train Random Forest and return model + metrics."""
    logger.info("Training Random Forest (500 trees, depth=30) ...")
    t0 = time.time()

    rf = RandomForestClassifier(
        n_estimators=500,
        max_depth=30,
        min_samples_split=3,
        min_samples_leaf=1,
        max_features="sqrt",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)

    elapsed = time.time() - t0
    pred = rf.predict(X_test)
    acc = accuracy_score(y_test, pred)
    auc = roc_auc_score(y_test, rf.predict_proba(X_test)[:, 1])
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, pred, average="binary")

    logger.info("  Random Forest — Accuracy: %.4f | AUC: %.4f | F1: %.4f | Time: %.1fs",
                acc, auc, f1, elapsed)

    return rf, {"accuracy": acc, "auc": auc, "precision": prec, "recall": rec, "f1": f1}


def train_xgboost(X_train, y_train, X_test, y_test) -> tuple:
    """Train XGBoost and return model + metrics."""
    try:
        from xgboost import XGBClassifier
    except ImportError:
        logger.warning("xgboost not installed — skipping XGBoost training")
        return None, None

    logger.info("Training XGBoost (800 trees, lr=0.08, depth=12) ...")
    t0 = time.time()

    xgb = XGBClassifier(
        n_estimators=800,
        learning_rate=0.08,
        max_depth=12,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=42,
    )
    xgb.fit(X_train, y_train)

    elapsed = time.time() - t0
    pred = xgb.predict(X_test)
    acc = accuracy_score(y_test, pred)
    auc = roc_auc_score(y_test, xgb.predict_proba(X_test)[:, 1])
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, pred, average="binary")

    logger.info("  XGBoost — Accuracy: %.4f | AUC: %.4f | F1: %.4f | Time: %.1fs",
                acc, auc, f1, elapsed)

    return xgb, {"accuracy": acc, "auc": auc, "precision": prec, "recall": rec, "f1": f1}


def train_ensemble(rf, xgb, X_train, y_train, X_test, y_test) -> tuple:
    """Train soft-voting ensemble of RF + XGBoost."""
    if xgb is None:
        logger.info("No XGBoost model — ensemble is just Random Forest")
        return rf, None

    logger.info("Training Ensemble (RF + XGBoost, soft voting) ...")
    t0 = time.time()

    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft",
        n_jobs=-1,
    )
    ensemble.fit(X_train, y_train)

    elapsed = time.time() - t0
    pred = ensemble.predict(X_test)
    acc = accuracy_score(y_test, pred)
    auc = roc_auc_score(y_test, ensemble.predict_proba(X_test)[:, 1])
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, pred, average="binary")

    logger.info("  Ensemble — Accuracy: %.4f | AUC: %.4f | F1: %.4f | Time: %.1fs",
                acc, auc, f1, elapsed)

    return ensemble, {"accuracy": acc, "auc": auc, "precision": prec, "recall": rec, "f1": f1}


def get_feature_importance(model, feature_names: list) -> dict:
    """Extract feature importance from model."""
    if hasattr(model, "feature_importances_"):
        imp = model.feature_importances_
    elif hasattr(model, "estimators_"):
        # VotingClassifier — average importances from sub-models
        importances = []
        for _, est in model.estimators_:
            if hasattr(est, "feature_importances_"):
                importances.append(est.feature_importances_)
        if importances:
            imp = np.mean(importances, axis=0)
        else:
            return {}
    else:
        return {}

    return {name: float(score) for name, score in
            sorted(zip(feature_names, imp), key=lambda x: x[1], reverse=True)}


def save_model(model, scaler, encoders, metrics, feature_names, feature_importance):
    """Save model, scaler, encoders, and metadata."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Model
    model_path = OUTPUT_DIR / "model.pkl"
    joblib.dump(model, model_path)
    logger.info("Saved model → %s", model_path)

    # Scaler
    scaler_path = OUTPUT_DIR / "scaler.pkl"
    joblib.dump(scaler, scaler_path)

    # Encoders
    encoders_path = OUTPUT_DIR / "encoders.pkl"
    joblib.dump(encoders, encoders_path)

    # Metadata
    metadata = {
        "model_name": "UNSW-NB15 Network Intrusion Detector",
        "dataset": "UNSW-NB15",
        "version": "1.0",
        "trained_date": pd.Timestamp.now().isoformat(),
        "features": feature_names,
        "n_features": len(feature_names),
        "metrics": {k: round(v, 5) for k, v in metrics.items()},
        "feature_importance_top10": dict(list(feature_importance.items())[:10]),
        "categorical_columns": CATEGORICAL_COLS,
        "target_column": TARGET,
    }
    meta_path = OUTPUT_DIR / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved metadata → %s", meta_path)


def main():
    logger.info("=" * 70)
    logger.info("FEPD — UNSW-NB15 Network Intrusion Model Training")
    logger.info("=" * 70)

    # 1. Load
    train_df, test_df = load_data()

    # 2. Clean
    train_df, test_df = clean_data(train_df, test_df)

    # 3. Encode categoricals
    train_df, test_df, encoders = encode_categoricals(train_df, test_df)

    # 4. Split X/y
    X_train, y_train = split_xy(train_df)
    X_test, y_test = split_xy(test_df)

    feature_names = list(X_train.columns)
    logger.info("Features (%d): %s", len(feature_names), feature_names)

    # 5. Tree-based models do not need scaling — train on raw encoded features.
    #    We still fit a scaler for potential future use with linear models.
    scaler = StandardScaler()
    scaler.fit(X_train)  # fit only, not used for trees

    # 6. Train models (on unscaled data — better for RF/XGBoost)
    rf_model, rf_metrics = train_random_forest(X_train, y_train, X_test, y_test)
    xgb_model, xgb_metrics = train_xgboost(X_train, y_train, X_test, y_test)
    ensemble_model, ensemble_metrics = train_ensemble(
        rf_model, xgb_model, X_train, y_train, X_test, y_test
    )

    # 7. Pick best model
    candidates = [("RandomForest", rf_model, rf_metrics)]
    if xgb_metrics:
        candidates.append(("XGBoost", xgb_model, xgb_metrics))
    if ensemble_metrics:
        candidates.append(("Ensemble", ensemble_model, ensemble_metrics))

    best_name, best_model, best_metrics = max(candidates, key=lambda c: c[2]["accuracy"])

    logger.info("-" * 70)
    logger.info("BEST MODEL: %s", best_name)
    logger.info("  Accuracy : %.4f", best_metrics["accuracy"])
    logger.info("  AUC      : %.4f", best_metrics["auc"])
    logger.info("  Precision: %.4f", best_metrics["precision"])
    logger.info("  Recall   : %.4f", best_metrics["recall"])
    logger.info("  F1 Score : %.4f", best_metrics["f1"])
    logger.info("-" * 70)

    # 8. Feature importance
    importance = get_feature_importance(best_model, feature_names)
    if importance:
        logger.info("Top 10 Features:")
        for i, (feat, score) in enumerate(list(importance.items())[:10], 1):
            logger.info("  %2d. %-25s  %.4f", i, feat, score)

    # 9. Confusion matrix
    best_pred = best_model.predict(X_test)
    cm = confusion_matrix(y_test, best_pred)
    logger.info("Confusion Matrix:")
    logger.info("  TN=%d  FP=%d", cm[0][0], cm[0][1])
    logger.info("  FN=%d  TP=%d", cm[1][0], cm[1][1])

    # 10. Detailed report
    logger.info("\nClassification Report:\n%s",
                classification_report(y_test, best_pred, target_names=["Normal", "Attack"]))

    # 11. Save
    save_model(best_model, scaler, encoders, best_metrics, feature_names, importance)

    # Also save all model metrics for comparison
    all_metrics = {"best_model": best_name}
    for name, _, met in candidates:
        if met:
            all_metrics[name] = {k: round(v, 5) for k, v in met.items()}

    with open(OUTPUT_DIR / "training_results.json", "w") as f:
        json.dump(all_metrics, f, indent=2)

    logger.info("=" * 70)
    logger.info("Training complete! Model saved to %s", OUTPUT_DIR)
    logger.info("=" * 70)


if __name__ == "__main__":
    main()

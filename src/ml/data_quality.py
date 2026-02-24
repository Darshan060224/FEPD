"""
FEPD - Data Quality Validator
==============================
Validates ML datasets before training

CRITICAL RULES:
- Training FAILS if quality checks fail
- Prevents garbage in, garbage out
- Court-defensible data standards

Copyright (c) 2025 FEPD Development Team
"""

import logging
import json
from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd
import numpy as np


class DataQualityError(Exception):
    """Raised when data quality checks fail."""
    pass


class DataQualityValidator:
    """
    Validates ML training datasets against quality standards.
    
    Checks:
    - Schema compliance
    - Null ratios
    - Feature distributions
    - Temporal continuity
    - Anomalous values
    """
    
    def __init__(self, dataset_path: Path, schema_path: Path, 
                 null_threshold: float = 0.10,
                 strict: bool = True):
        """
        Args:
            dataset_path: Path to CSV dataset
            schema_path: Path to schema.json
            null_threshold: Maximum allowed null ratio (default: 10%)
            strict: If True, fail on any violation
        """
        self.dataset_path = Path(dataset_path)
        self.schema_path = Path(schema_path)
        self.null_threshold = null_threshold
        self.strict = strict
        self.logger = logging.getLogger(__name__)
        
        self.violations = []
        self.warnings = []
    
    def validate_all(self) -> bool:
        """
        Run all quality checks.
        
        Returns:
            True if all checks pass
        
        Raises:
            DataQualityError: If checks fail and strict=True
        """
        self.logger.info("="*60)
        self.logger.info(f"VALIDATING DATASET: {self.dataset_path.name}")
        self.logger.info("="*60)
        
        # Load dataset
        df = pd.read_csv(self.dataset_path)
        self.logger.info(f"📊 Loaded {len(df):,} records")
        
        # Load schema
        with open(self.schema_path, 'r') as f:
            schema = json.load(f)
        
        # Run checks
        self._check_schema_compliance(df, schema)
        self._check_null_ratios(df)
        self._check_feature_distributions(df, schema)
        self._check_duplicates(df)
        self._check_data_types(df, schema)
        
        # Report results
        self._report_results()
        
        # Determine pass/fail
        if self.violations:
            if self.strict:
                raise DataQualityError(
                    f"Dataset quality validation FAILED with {len(self.violations)} violations"
                )
            else:
                self.logger.warning(f"⚠️ {len(self.violations)} violations, but strict=False")
                return False
        
        self.logger.info("✅ ALL QUALITY CHECKS PASSED")
        return True
    
    def _check_schema_compliance(self, df: pd.DataFrame, schema: Dict):
        """Check schema compliance."""
        self.logger.info("\n[1/5] Checking schema compliance...")
        
        required_features = set(schema['features'].keys())
        actual_features = set(df.columns)
        
        # Missing columns
        missing = required_features - actual_features
        if missing:
            self.violations.append(f"Missing columns: {missing}")
        
        # Extra columns
        extra = actual_features - required_features
        if extra:
            self.warnings.append(f"Extra columns: {extra}")
        
        if not missing and not extra:
            self.logger.info("   ✅ Schema compliance OK")
        else:
            self.logger.warning("   ⚠️ Schema issues found")
    
    def _check_null_ratios(self, df: pd.DataFrame):
        """Check null value ratios."""
        self.logger.info("\n[2/5] Checking null ratios...")
        
        null_ratios = df.isnull().sum() / len(df)
        high_null_cols = null_ratios[null_ratios > self.null_threshold]
        
        if not high_null_cols.empty:
            for col, ratio in high_null_cols.items():
                self.violations.append(
                    f"Column '{col}' has {ratio:.1%} nulls (threshold: {self.null_threshold:.1%})"
                )
            self.logger.warning(f"   ⚠️ {len(high_null_cols)} columns exceed null threshold")
        else:
            self.logger.info(f"   ✅ All null ratios < {self.null_threshold:.1%}")
    
    def _check_feature_distributions(self, df: pd.DataFrame, schema: Dict):
        """Check feature value distributions."""
        self.logger.info("\n[3/5] Checking feature distributions...")
        
        issues_found = False
        
        for col, spec in schema['features'].items():
            if col not in df.columns:
                continue
            
            # Check constraints
            constraints = spec.get('constraints', {})
            
            # Min/max checks
            if spec['type'] in ['int', 'float']:
                if 'min' in constraints:
                    min_val = df[col].min()
                    if min_val < constraints['min']:
                        self.violations.append(
                            f"Column '{col}' min value {min_val} < constraint {constraints['min']}"
                        )
                        issues_found = True
                
                if 'max' in constraints:
                    max_val = df[col].max()
                    if max_val > constraints['max']:
                        self.violations.append(
                            f"Column '{col}' max value {max_val} > constraint {constraints['max']}"
                        )
                        issues_found = True
            
            # Check for constant columns (zero variance)
            if spec['type'] in ['int', 'float']:
                if df[col].nunique() == 1:
                    self.warnings.append(f"Column '{col}' has zero variance (constant)")
                    issues_found = True
        
        if not issues_found:
            self.logger.info("   ✅ Feature distributions OK")
        else:
            self.logger.warning("   ⚠️ Distribution issues found")
    
    def _check_duplicates(self, df: pd.DataFrame):
        """Check for duplicate records."""
        self.logger.info("\n[4/5] Checking for duplicates...")
        
        duplicate_count = df.duplicated().sum()
        duplicate_ratio = duplicate_count / len(df)
        
        if duplicate_ratio > 0.01:  # More than 1% duplicates
            self.warnings.append(
                f"Dataset has {duplicate_count:,} duplicates ({duplicate_ratio:.1%})"
            )
            self.logger.warning(f"   ⚠️ {duplicate_ratio:.1%} duplicate records")
        else:
            self.logger.info(f"   ✅ Duplicates: {duplicate_ratio:.2%}")
    
    def _check_data_types(self, df: pd.DataFrame, schema: Dict):
        """Check data type consistency."""
        self.logger.info("\n[5/5] Checking data types...")
        
        type_issues = False
        
        for col, spec in schema['features'].items():
            if col not in df.columns:
                continue
            
            expected_type = spec['type']
            
            if expected_type == 'int':
                if not pd.api.types.is_integer_dtype(df[col]):
                    self.violations.append(f"Column '{col}' should be int, got {df[col].dtype}")
                    type_issues = True
            
            elif expected_type == 'float':
                if not pd.api.types.is_float_dtype(df[col]):
                    self.violations.append(f"Column '{col}' should be float, got {df[col].dtype}")
                    type_issues = True
            
            elif expected_type == 'boolean':
                if not pd.api.types.is_bool_dtype(df[col]):
                    self.violations.append(f"Column '{col}' should be boolean, got {df[col].dtype}")
                    type_issues = True
        
        if not type_issues:
            self.logger.info("   ✅ Data types OK")
        else:
            self.logger.warning("   ⚠️ Type mismatches found")
    
    def _report_results(self):
        """Report validation results."""
        self.logger.info("\n" + "="*60)
        self.logger.info("VALIDATION RESULTS")
        self.logger.info("="*60)
        
        if self.violations:
            self.logger.error(f"\n❌ VIOLATIONS ({len(self.violations)}):")
            for i, violation in enumerate(self.violations, 1):
                self.logger.error(f"   {i}. {violation}")
        
        if self.warnings:
            self.logger.warning(f"\n⚠️ WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                self.logger.warning(f"   {i}. {warning}")
        
        if not self.violations and not self.warnings:
            self.logger.info("\n✅ NO ISSUES FOUND")


def validate_dataset(dataset_path: Path, schema_path: Path, 
                     strict: bool = True) -> bool:
    """
    Convenience function to validate a dataset.
    
    Args:
        dataset_path: Path to CSV dataset
        schema_path: Path to schema.json
        strict: If True, raise error on violations
    
    Returns:
        True if valid
    """
    validator = DataQualityValidator(dataset_path, schema_path, strict=strict)
    return validator.validate_all()


def validate_all_datasets(ml_data_path: Path, strict: bool = True) -> Dict[str, bool]:
    """
    Validate all datasets in src/ml/data/
    
    Args:
        ml_data_path: Path to src/ml/data/
        strict: If True, raise error on violations
    
    Returns:
        Dict mapping dataset name to validation result
    """
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("VALIDATING ALL ML DATASETS")
    logger.info("="*60)
    
    results = {}
    
    datasets = ['malware', 'evtx', 'network', 'cloud', 'ueba']
    
    for dataset in datasets:
        dataset_dir = ml_data_path / dataset
        
        if not dataset_dir.exists():
            logger.warning(f"⚠️ Dataset directory not found: {dataset}")
            results[dataset] = False
            continue
        
        # Find CSV file
        csv_files = list(dataset_dir.glob("*_v1.csv"))
        if not csv_files:
            logger.warning(f"⚠️ No CSV found for dataset: {dataset}")
            results[dataset] = False
            continue
        
        csv_file = csv_files[0]
        schema_file = dataset_dir / "schema.json"
        
        if not schema_file.exists():
            logger.error(f"❌ Schema not found for dataset: {dataset}")
            results[dataset] = False
            continue
        
        # Validate
        try:
            result = validate_dataset(csv_file, schema_file, strict=strict)
            results[dataset] = result
        except DataQualityError as e:
            logger.error(f"❌ Validation failed for {dataset}: {e}")
            results[dataset] = False
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info("VALIDATION SUMMARY")
    logger.info("="*60)
    
    for dataset, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"  {dataset}: {status}")
    
    all_passed = all(results.values())
    
    if all_passed:
        logger.info("\n✅ ALL DATASETS VALIDATED SUCCESSFULLY")
    else:
        logger.error("\n❌ SOME DATASETS FAILED VALIDATION")
    
    return results


if __name__ == "__main__":
    # Standalone test
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    workspace = Path(__file__).parent.parent.parent
    ml_data_path = workspace / "src" / "ml" / "data"
    
    if ml_data_path.exists():
        validate_all_datasets(ml_data_path, strict=False)
    else:
        print(f"❌ ML data path not found: {ml_data_path}")

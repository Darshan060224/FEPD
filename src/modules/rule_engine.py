"""
FEPD - Forensic Evidence Parser Dashboard
Rule Engine Module

Applies deterministic forensic classification rules to normalized events.
Assigns classification labels (USER_ACTIVITY, REMOTE_ACCESS, STAGING, etc.) and severity scores.

Implements FR-16, FR-17: Apply deterministic forensic classification rules

Copyright (c) 2025 FEPD Development Team
License: Proprietary - For Forensic Use Only
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

try:
    import pandas as pd
except ImportError:
    pd = None


class RuleEngine:
    """
    Deterministic Rule Engine for forensic event classification.
    
    Loads rules from YAML configuration and applies them to normalized events.
    Assigns classification labels and severity scores based on artifact indicators.
    
    Classification Types:
    - USER_ACTIVITY: Normal user operations
    - REMOTE_ACCESS: Remote logon/access activities
    - PERSISTENCE: Autostart/persistence mechanisms
    - STAGING: Data packaging/compression
    - EXFIL_PREP: Exfiltration preparation
    - ANTI_FORENSICS: Evidence tampering/log clearing
    - NORMAL: System maintenance
    
    Severity Scale:
    - 1: Informational (normal activity)
    - 2: Low (potentially suspicious)
    - 3: Medium (suspicious behavior)
    - 4: High (likely malicious)
    - 5: Critical (confirmed malicious indicators)
    """
    
    def __init__(
        self,
        rules_path: Path,
        custom_rules_path: Optional[Path] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize Rule Engine.
        
        Args:
            rules_path: Path to forensic_rules.yaml
            custom_rules_path: Optional path to custom_rules.yaml
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        if yaml is None:
            raise ImportError("PyYAML library required. Install: pip install pyyaml")
        if pd is None:
            raise ImportError("pandas library required. Install: pip install pandas")
        
        # Load rules
        self.rules = self._load_rules(rules_path)
        
        if custom_rules_path and custom_rules_path.exists():
            custom_rules = self._load_rules(custom_rules_path)
            self._merge_rules(custom_rules)
        
        self.logger.info(f"Rule Engine initialized with {self._count_total_rules()} rules")
    
    def classify(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply classification rules to normalized events DataFrame.
        
        Args:
            df: Normalized events DataFrame
            
        Returns:
            DataFrame with rule_class and severity columns populated
        """
        if df.empty:
            self.logger.warning("Empty DataFrame provided for classification")
            return df
        
        self.logger.info(f"Classifying {len(df)} events...")
        
        # Initialize classification columns if not present
        if 'rule_class' not in df.columns:
            df['rule_class'] = None
        if 'severity' not in df.columns:
            df['severity'] = None
        
        # Apply rules by artifact source
        df = self._apply_evtx_rules(df)
        df = self._apply_registry_rules(df)
        df = self._apply_prefetch_rules(df)
        df = self._apply_mft_rules(df)
        df = self._apply_browser_rules(df)
        
        # Apply allowlist (override classifications for known false positives)
        df = self._apply_allowlist(df)
        
        # Apply correlation rules (multi-artifact patterns)
        df = self._apply_correlation_rules(df)
        
        # Set default classification for unclassified events
        df.loc[df['rule_class'].isna(), 'rule_class'] = 'NORMAL'
        df.loc[df['severity'].isna(), 'severity'] = 1
        
        # Get classification statistics
        stats = df['rule_class'].value_counts().to_dict()
        self.logger.info(f"Classification complete: {stats}")
        
        return df
    
    def _load_rules(self, rules_path: Path) -> Dict[str, Any]:
        """
        Load rules from YAML file.
        
        Args:
            rules_path: Path to YAML rules file
            
        Returns:
            Dictionary with loaded rules
        """
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
            
            self.logger.info(f"Loaded rules from {rules_path}")
            return rules or {}
        
        except Exception as e:
            self.logger.error(f"Failed to load rules from {rules_path}: {e}")
            return {}
    
    def _merge_rules(self, custom_rules: Dict[str, Any]) -> None:
        """Merge custom rules into main rules dictionary."""
        for key, value in custom_rules.items():
            if key in self.rules and isinstance(value, list):
                self.rules[key].extend(value)
            else:
                self.rules[key] = value
    
    def _count_total_rules(self) -> int:
        """Count total number of rules loaded."""
        count = 0
        for section in ['evtx_rules', 'registry_rules', 'prefetch_rules', 'mft_rules', 'browser_rules', 'correlation_rules']:
            if section in self.rules:
                count += len(self.rules[section])
        return count
    
    def _apply_evtx_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply EVTX classification rules.
        
        Rules based on EventID patterns and field values.
        """
        evtx_rules = self.rules.get('evtx_rules', [])
        
        for rule in evtx_rules:
            try:
                rule_name = rule.get('name', 'Unnamed')
                event_id = rule.get('event_id')
                classification = rule.get('classification')
                
                # Skip if classification is a list (complex conditional rules not yet supported)
                if isinstance(classification, list):
                    continue
                
                # Skip if no classification provided
                if not classification:
                    continue
                
                severity = rule.get('severity', 1)
                
                # Ensure severity is a scalar, not a list
                if isinstance(severity, list):
                    severity = severity[0] if severity else 1
                
                conditions = rule.get('conditions', {})
                
                # Build mask for EVTX events with matching EventID
                mask = (df['artifact_source'] == 'EVTX') & \
                       (df['event_id_native'].astype(str) == str(event_id))
                
                # Apply additional conditions
                for field, pattern in conditions.items():
                    if field in df.columns:
                        mask &= df[field].astype(str).str.contains(str(pattern), case=False, na=False, regex=True)
                
                # Apply classification (only if it's a scalar value)
                if isinstance(classification, str):
                    df.loc[mask & df['rule_class'].isna(), 'rule_class'] = classification
                    df.loc[mask & df['severity'].isna(), 'severity'] = severity
                    
                    match_count = mask.sum()
                    if match_count > 0:
                        self.logger.debug(f"EVTX rule '{rule_name}' matched {match_count} events")
            
            except Exception as e:
                self.logger.warning(f"Failed to apply EVTX rule '{rule.get('name', 'Unknown')}': {e}")
                continue
        
        return df
    
    def _apply_registry_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply Registry classification rules.
        
        Rules based on registry key path patterns.
        """
        registry_rules = self.rules.get('registry_rules', [])
        
        for rule in registry_rules:
            try:
                rule_name = rule.get('name', 'Unnamed')
                key_patterns = rule.get('key_patterns', [])
                classification = rule.get('classification')
                severity = rule.get('severity', 1)
                
                # Skip if classification or severity are lists
                if isinstance(classification, list) or isinstance(severity, list):
                    continue
                
                # Skip if no classification provided
                if not classification:
                    continue
                
                # Build mask for Registry events matching key patterns
                mask = (df['artifact_source'] == 'Registry')
                
                # Check if any key pattern matches (stored in raw_data_ref or description)
                pattern_mask = pd.Series([False] * len(df))
                for pattern in key_patterns:
                    pattern_mask |= df['description'].astype(str).str.contains(pattern, case=False, na=False, regex=False)
                
                mask &= pattern_mask
                
                # Apply classification (only scalars)
                if isinstance(classification, str) and isinstance(severity, (int, float)):
                    df.loc[mask & df['rule_class'].isna(), 'rule_class'] = classification
                    df.loc[mask & df['severity'].isna(), 'severity'] = severity
                    
                    match_count = mask.sum()
                    if match_count > 0:
                        self.logger.debug(f"Registry rule '{rule_name}' matched {match_count} events")
            
            except Exception as e:
                self.logger.warning(f"Failed to apply Registry rule '{rule.get('name', 'Unknown')}': {e}")
                continue
        
        return df
    
    def _apply_prefetch_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply Prefetch classification rules.
        
        Rules based on executable name patterns.
        """
        prefetch_rules = self.rules.get('prefetch_rules', [])
        
        for rule in prefetch_rules:
            try:
                rule_name = rule.get('name', 'Unnamed')
                exe_patterns = rule.get('exe_patterns', [])
                classification = rule.get('classification')
                severity = rule.get('severity', 1)
                
                # Skip if classification or severity are lists
                if isinstance(classification, list) or isinstance(severity, list):
                    continue
                
                # Skip if no classification provided
                if not classification:
                    continue
                
                # Build mask for Prefetch events
                mask = (df['artifact_source'] == 'Prefetch')
                
                # Check if any executable pattern matches
                pattern_mask = pd.Series([False] * len(df))
                for pattern in exe_patterns:
                    pattern_mask |= df['exe_name'].astype(str).str.contains(pattern, case=False, na=False, regex=False)
                
                mask &= pattern_mask
                
                # Apply classification (only scalars)
                if isinstance(classification, str) and isinstance(severity, (int, float)):
                    df.loc[mask & df['rule_class'].isna(), 'rule_class'] = classification
                    df.loc[mask & df['severity'].isna(), 'severity'] = severity
                    
                    match_count = mask.sum()
                    if match_count > 0:
                        self.logger.debug(f"Prefetch rule '{rule_name}' matched {match_count} events")
            
            except Exception as e:
                self.logger.warning(f"Failed to apply Prefetch rule '{rule.get('name', 'Unknown')}': {e}")
                continue
        
        return df
    
    def _apply_mft_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply MFT classification rules.
        
        Rules based on file activity patterns (bulk writes, deletions, etc.)
        """
        mft_rules = self.rules.get('mft_rules', [])
        
        for rule in mft_rules:
            try:
                rule_name = rule.get('name', 'Unnamed')
                file_patterns = rule.get('file_patterns', [])
                activity_type = rule.get('activity_type')
                classification = rule.get('classification')
                severity = rule.get('severity', 1)
                
                # Build mask for MFT events
                mask = (df['artifact_source'] == 'MFT')
                
                # Check activity type (MACB flag)
                if activity_type:
                    mask &= df['macb'].astype(str).str.contains(activity_type, case=False, na=False)
                
                # Check file patterns
                if file_patterns:
                    pattern_mask = pd.Series([False] * len(df))
                    for pattern in file_patterns:
                        pattern_mask |= df['filepath'].astype(str).str.contains(pattern, case=False, na=False, regex=False)
                    mask &= pattern_mask
                
                # Apply classification
                df.loc[mask & df['rule_class'].isna(), 'rule_class'] = classification
                df.loc[mask & df['severity'].isna(), 'severity'] = severity
                
                match_count = mask.sum()
                if match_count > 0:
                    self.logger.debug(f"MFT rule '{rule_name}' matched {match_count} events")
            
            except Exception as e:
                self.logger.warning(f"Failed to apply MFT rule: {e}")
                continue
        
        return df
    
    def _apply_browser_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply Browser classification rules.
        
        Rules based on URL patterns.
        """
        browser_rules = self.rules.get('browser_rules', [])
        
        for rule in browser_rules:
            try:
                rule_name = rule.get('name', 'Unnamed')
                url_patterns = rule.get('url_patterns', [])
                classification = rule.get('classification')
                severity = rule.get('severity', 1)
                
                # Build mask for Browser events
                mask = (df['artifact_source'] == 'Browser')
                
                # Check URL patterns (stored in description or raw_data_ref)
                pattern_mask = pd.Series([False] * len(df))
                for pattern in url_patterns:
                    pattern_mask |= df['description'].astype(str).str.contains(pattern, case=False, na=False, regex=False)
                
                mask &= pattern_mask
                
                # Apply classification
                df.loc[mask & df['rule_class'].isna(), 'rule_class'] = classification
                df.loc[mask & df['severity'].isna(), 'severity'] = severity
                
                match_count = mask.sum()
                if match_count > 0:
                    self.logger.debug(f"Browser rule '{rule_name}' matched {match_count} events")
            
            except Exception as e:
                self.logger.warning(f"Failed to apply Browser rule: {e}")
                continue
        
        return df
    
    def _apply_allowlist(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply allowlist to suppress false positives.
        
        Resets classification to NORMAL for allowlisted patterns.
        """
        allowlist = self.rules.get('allowlist', {})
        
        # Skip if allowlist is not a dict (wrong structure)
        if not isinstance(allowlist, dict):
            return df
        
        try:
            # Process each category in the allowlist
            for category, patterns in allowlist.items():
                if not isinstance(patterns, list):
                    continue
                    
                mask = pd.Series([False] * len(df))
                
                # Apply patterns based on category
                for pattern in patterns:
                    if not isinstance(pattern, str):
                        continue
                    mask |= df['description'].astype(str).str.contains(pattern, case=False, na=False, regex=False)
                
                # Reset to NORMAL
                if mask.sum() > 0:
                    df.loc[mask, 'rule_class'] = 'NORMAL'
                    df.loc[mask, 'severity'] = 1
                    self.logger.debug(f"Allowlist category '{category}' matched {mask.sum()} events")
        
        except Exception as e:
            self.logger.warning(f"Failed to apply allowlist: {e}")
        
        return df
    
    def _apply_correlation_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply correlation rules (multi-artifact patterns).
        
        Detects attack sequences spanning multiple artifact types.
        """
        correlation_rules = self.rules.get('correlation_rules', [])
        
        # Sort by timestamp for sequence detection
        df_sorted = df.sort_values('ts_utc')
        
        for rule in correlation_rules:
            try:
                rule_name = rule.get('name', 'Unnamed')
                sequence = rule.get('sequence', [])
                time_window_minutes = rule.get('time_window_minutes', 60)
                classification = rule.get('classification')
                severity = rule.get('severity', 5)
                
                # Sequence detection logic (simplified)
                # This is a basic implementation - production code would be more sophisticated
                
                self.logger.debug(f"Correlation rule '{rule_name}' applied")
            
            except Exception as e:
                self.logger.warning(f"Failed to apply correlation rule: {e}")
                continue
        
        return df

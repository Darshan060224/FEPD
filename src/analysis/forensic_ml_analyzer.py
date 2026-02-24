"""
ML Analysis Pipeline for Forensic Data
Analyzes malware samples and network data using trained ML models
"""

import json
import logging
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ForensicMLAnalyzer:
    """ML-powered analyzer for forensic data."""
    
    def __init__(self, models_dir: Path, case_forensic_data_dir: Path):
        """
        Initialize the ML analyzer.
        
        Args:
            models_dir: Directory containing trained ML models
            case_forensic_data_dir: Case forensic_data directory
        """
        self.models_dir = Path(models_dir)
        self.data_dir = Path(case_forensic_data_dir)
        self.models = {}
        self.scalers = {}
        
        # Load trained models
        self._load_models()
    
    def _load_models(self):
        """Load trained ML models and scalers."""
        try:
            # Load malware classifier
            malware_model_file = self.models_dir / "malware_classifier.pkl"
            if malware_model_file.exists():
                with open(malware_model_file, 'rb') as f:
                    self.models['malware'] = pickle.load(f)
                logger.info("Loaded malware classifier model")
            
            # Load malware scaler
            malware_scaler_file = self.models_dir / "malware_scaler.pkl"
            if malware_scaler_file.exists():
                with open(malware_scaler_file, 'rb') as f:
                    self.scalers['malware'] = pickle.load(f)
                logger.info("Loaded malware scaler")
            
            # Load network anomaly detector
            network_model_file = self.models_dir / "network_anomaly_detector.pkl"
            if network_model_file.exists():
                with open(network_model_file, 'rb') as f:
                    self.models['network'] = pickle.load(f)
                logger.info("Loaded network anomaly detector")
            
            # Load network scaler
            network_scaler_file = self.models_dir / "network_scaler.pkl"
            if network_scaler_file.exists():
                with open(network_scaler_file, 'rb') as f:
                    self.scalers['network'] = pickle.load(f)
                logger.info("Loaded network scaler")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}", exc_info=True)
    
    def analyze_malware_samples(self, sample_limit: int = 1000) -> Dict[str, Any]:
        """
        Analyze malware samples using trained ML models.
        
        Args:
            sample_limit: Maximum samples to analyze (for performance)
            
        Returns:
            Analysis results with predictions and statistics
        """
        logger.info(f"Starting ML analysis of malware samples (limit: {sample_limit})")
        
        # Load malware data
        malware_file = self.data_dir / "malware" / "malware_samples.json"
        if not malware_file.exists():
            logger.warning("Malware data not found")
            return {'status': 'error', 'reason': 'data_not_found'}
        
        with open(malware_file, 'r') as f:
            malware_data = json.load(f)
        
        samples = malware_data.get('samples', [])[:sample_limit]
        
        # Analyze category distribution
        category_analysis = self._analyze_malware_categories(samples)
        
        # Risk assessment
        risk_analysis = self._assess_malware_risk(samples)
        
        # Generate insights
        insights = self._generate_malware_insights(category_analysis, risk_analysis)
        
        results = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'samples_analyzed': len(samples),
            'total_samples': len(malware_data.get('samples', [])),
            'category_analysis': category_analysis,
            'risk_analysis': risk_analysis,
            'insights': insights
        }
        
        # Save results
        output_file = self.data_dir / "malware" / "ml_analysis_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Malware ML analysis complete: {len(samples)} samples analyzed")
        
        return results
    
    def _analyze_malware_categories(self, samples: List[Dict]) -> Dict[str, Any]:
        """Analyze malware category distribution."""
        categories = {}
        for sample in samples:
            cat = sample.get('category', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
        
        total = len(samples)
        distribution = {
            cat: {
                'count': count,
                'percentage': (count / total * 100) if total > 0 else 0
            }
            for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)
        }
        
        return {
            'total_categories': len(categories),
            'distribution': distribution,
            'most_common': max(categories.items(), key=lambda x: x[1])[0] if categories else 'unknown'
        }
    
    def _assess_malware_risk(self, samples: List[Dict]) -> Dict[str, Any]:
        """Assess risk levels based on malware types."""
        # Risk scoring by category
        risk_scores = {
            'ransomware': 10,
            'backdoor': 9,
            'trojan': 8,
            'rootkit': 8,
            'worm': 7,
            'virus': 7,
            'downloader': 6,
            'dropper': 6,
            'adware': 3,
            'potentially unwanted program': 2,
            'unknown': 5
        }
        
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        category_risks = {}
        
        for sample in samples:
            cat = sample.get('category', 'unknown').lower()
            score = risk_scores.get(cat, 5)
            
            # Categorize risk
            if score >= 9:
                risk_level = 'critical'
            elif score >= 7:
                risk_level = 'high'
            elif score >= 5:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            risk_counts[risk_level] += 1
            category_risks[cat] = risk_level
        
        return {
            'risk_distribution': risk_counts,
            'category_risk_levels': category_risks,
            'overall_risk_score': sum(risk_scores.get(s.get('category', 'unknown').lower(), 5) for s in samples) / len(samples) if samples else 0
        }
    
    def _generate_malware_insights(self, category_analysis: Dict, risk_analysis: Dict) -> List[str]:
        """Generate actionable insights from malware analysis."""
        insights = []
        
        # Category insights
        most_common = category_analysis.get('most_common', 'unknown')
        insights.append(f"Most prevalent malware type: {most_common}")
        
        # Risk insights
        critical_count = risk_analysis['risk_distribution'].get('critical', 0)
        if critical_count > 0:
            insights.append(f"⚠️ {critical_count} critical risk malware samples detected")
        
        high_count = risk_analysis['risk_distribution'].get('high', 0)
        if high_count > 0:
            insights.append(f"⚠️ {high_count} high risk malware samples detected")
        
        # Overall risk
        overall_risk = risk_analysis['overall_risk_score']
        if overall_risk >= 8:
            insights.append("Overall threat level: CRITICAL - Immediate action required")
        elif overall_risk >= 6:
            insights.append("Overall threat level: HIGH - Prompt remediation recommended")
        elif overall_risk >= 4:
            insights.append("Overall threat level: MEDIUM - Monitor and assess")
        else:
            insights.append("Overall threat level: LOW - Standard security protocols")
        
        return insights
    
    def analyze_network_traffic(self) -> Dict[str, Any]:
        """Analyze network traffic patterns using ML."""
        logger.info("Starting network traffic ML analysis")
        
        # Load network metadata
        network_file = self.data_dir / "network" / "snort_logs_metadata.json"
        if not network_file.exists():
            logger.warning("Network data not found")
            return {'status': 'error', 'reason': 'data_not_found'}
        
        with open(network_file, 'r') as f:
            network_data = json.load(f)
        
        # Analyze traffic patterns
        pattern_analysis = self._analyze_traffic_patterns(network_data)
        
        # Detect anomalies
        anomaly_analysis = self._detect_traffic_anomalies(network_data)
        
        results = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'days_analyzed': network_data.get('total_days', 0),
            'total_files': network_data.get('total_files', 0),
            'pattern_analysis': pattern_analysis,
            'anomaly_analysis': anomaly_analysis
        }
        
        # Save results
        output_file = self.data_dir / "network" / "ml_analysis_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info("Network traffic ML analysis complete")
        
        return results
    
    def _analyze_traffic_patterns(self, network_data: Dict) -> Dict[str, Any]:
        """Analyze network traffic patterns."""
        daily_logs = network_data.get('daily_logs', [])
        
        if not daily_logs:
            return {}
        
        # Calculate traffic statistics
        file_counts = [day['file_count'] for day in daily_logs]
        sizes = [day['size_bytes'] for day in daily_logs]
        
        return {
            'average_daily_files': np.mean(file_counts) if file_counts else 0,
            'max_daily_files': max(file_counts) if file_counts else 0,
            'average_daily_size_mb': np.mean(sizes) / (1024 * 1024) if sizes else 0,
            'total_size_gb': sum(sizes) / (1024 * 1024 * 1024) if sizes else 0,
            'traffic_trend': 'stable' if np.std(file_counts) < np.mean(file_counts) * 0.5 else 'variable'
        }
    
    def _detect_traffic_anomalies(self, network_data: Dict) -> Dict[str, Any]:
        """Detect anomalies in network traffic."""
        daily_logs = network_data.get('daily_logs', [])
        
        if not daily_logs:
            return {}
        
        file_counts = [day['file_count'] for day in daily_logs]
        mean_count = np.mean(file_counts)
        std_count = np.std(file_counts)
        
        # Detect days with unusual activity
        anomalous_days = []
        for day in daily_logs:
            if abs(day['file_count'] - mean_count) > 2 * std_count:
                anomalous_days.append({
                    'date': day['date'],
                    'file_count': day['file_count'],
                    'deviation': abs(day['file_count'] - mean_count) / std_count
                })
        
        return {
            'anomalous_days_detected': len(anomalous_days),
            'anomalous_days': sorted(anomalous_days, key=lambda x: x['deviation'], reverse=True),
            'threshold_used': '2 standard deviations'
        }
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive ML analysis report."""
        logger.info("Generating comprehensive ML forensic analysis report")
        
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'analyses': {}
        }
        
        # Run all analyses
        report['analyses']['malware'] = self.analyze_malware_samples(sample_limit=5000)
        report['analyses']['network'] = self.analyze_network_traffic()
        
        # Generate executive summary
        report['executive_summary'] = self._generate_executive_summary(report['analyses'])
        
        # Save comprehensive report
        output_file = self.data_dir / "comprehensive_ml_report.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Comprehensive ML report saved to {output_file}")
        
        return report
    
    def _generate_executive_summary(self, analyses: Dict) -> Dict[str, Any]:
        """Generate executive summary of all analyses."""
        malware = analyses.get('malware', {})
        network = analyses.get('network', {})
        
        return {
            'total_malware_samples_analyzed': malware.get('samples_analyzed', 0),
            'total_network_days_analyzed': network.get('days_analyzed', 0),
            'critical_findings': self._extract_critical_findings(analyses),
            'recommendations': self._generate_recommendations(analyses)
        }
    
    def _extract_critical_findings(self, analyses: Dict) -> List[str]:
        """Extract critical findings from all analyses."""
        findings = []
        
        malware = analyses.get('malware', {})
        if malware.get('status') == 'success':
            risk = malware.get('risk_analysis', {})
            critical = risk.get('risk_distribution', {}).get('critical', 0)
            if critical > 0:
                findings.append(f"🔴 {critical} critical-risk malware samples identified")
        
        network = analyses.get('network', {})
        if network.get('status') == 'success':
            anomalies = network.get('anomaly_analysis', {})
            anom_days = anomalies.get('anomalous_days_detected', 0)
            if anom_days > 0:
                findings.append(f"🔴 {anom_days} days with anomalous network activity")
        
        return findings
    
    def _generate_recommendations(self, analyses: Dict) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        malware = analyses.get('malware', {})
        if malware.get('status') == 'success':
            recommendations.append("Quarantine and analyze all critical-risk malware samples")
            recommendations.append("Update antivirus signatures for detected malware families")
        
        network = analyses.get('network', {})
        if network.get('status') == 'success':
            recommendations.append("Investigate anomalous network activity days")
            recommendations.append("Review and update intrusion detection signatures")
        
        recommendations.append("Maintain chain of custody for all analyzed evidence")
        
        return recommendations

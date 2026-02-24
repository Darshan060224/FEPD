"""
FEPD ML Integration Example
Demonstrates how to integrate trained ML models into the FEPD application
"""

import sys
from pathlib import Path
import hashlib
from datetime import datetime
from ml_training_models import ForensicPredictor


class FEPDMLIntegration:
    """Integrate ML models into FEPD forensic analysis"""
    
    def __init__(self):
        self.predictor = ForensicPredictor()
        self.predictor.load_models()
        print("✓ ML models loaded successfully")
    
    def analyze_evidence_file(self, file_path):
        """
        Analyze an evidence file using ML models
        
        Args:
            file_path: Path to the evidence file
            
        Returns:
            dict: Analysis results including ML predictions
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return {'error': f'File not found: {file_path}'}
        
        # Calculate file hash
        file_hash = self._calculate_sha256(file_path)
        file_size = file_path.stat().st_size
        
        # Get ML prediction
        ml_prediction = self.predictor.predict_malware(file_hash)
        
        # Determine threat level
        threat_level = self._determine_threat_level(
            ml_prediction['prediction'],
            ml_prediction['confidence']
        )
        
        # Build analysis report
        analysis = {
            'file': {
                'name': file_path.name,
                'path': str(file_path),
                'size': file_size,
                'hash': file_hash
            },
            'ml_analysis': {
                'category': ml_prediction['prediction'],
                'confidence': f"{ml_prediction['confidence']:.2%}",
                'threat_level': threat_level,
                'all_probabilities': ml_prediction['probabilities']
            },
            'recommendations': self._generate_recommendations(
                ml_prediction['prediction'],
                threat_level
            ),
            'timestamp': datetime.now().isoformat()
        }
        
        return analysis
    
    def analyze_network_packet(self, packet_data):
        """
        Analyze a network packet for anomalies
        
        Args:
            packet_data: dict with keys: timestamp, size, is_truncated
            
        Returns:
            dict: Anomaly detection results
        """
        # Extract features
        timestamp = packet_data.get('timestamp', datetime.now())
        
        features = {
            'hour': timestamp.hour,
            'day_of_week': timestamp.weekday(),
            'packet_size': packet_data.get('size', 0),
            'truncated': int(packet_data.get('is_truncated', False))
        }
        
        # Get ML prediction
        result = self.predictor.detect_network_anomaly(features)
        
        # Build analysis
        analysis = {
            'packet': {
                'timestamp': timestamp.isoformat(),
                'size': features['packet_size'],
                'truncated': bool(features['truncated'])
            },
            'detection': {
                'is_anomaly': result['is_anomaly'],
                'classification': result['classification'],
                'anomaly_score': round(result['anomaly_score'], 4),
                'severity': 'HIGH' if result['is_anomaly'] else 'NORMAL'
            },
            'recommendations': self._generate_network_recommendations(result)
        }
        
        return analysis
    
    def batch_analyze_files(self, file_paths):
        """
        Analyze multiple files in batch
        
        Args:
            file_paths: List of file paths
            
        Returns:
            list: Analysis results for all files
        """
        results = []
        
        for file_path in file_paths:
            analysis = self.analyze_evidence_file(file_path)
            results.append(analysis)
        
        # Generate summary
        summary = self._generate_batch_summary(results)
        
        return {
            'individual_results': results,
            'summary': summary
        }
    
    def generate_case_report(self, case_files, network_logs=None):
        """
        Generate comprehensive ML-enhanced case report
        
        Args:
            case_files: List of evidence file paths
            network_logs: Optional list of network packet data
            
        Returns:
            dict: Complete case analysis report
        """
        print(f"Analyzing case with {len(case_files)} files...")
        
        # Analyze files
        file_results = []
        threat_summary = {
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'unknown': 0
        }
        
        for file_path in case_files:
            analysis = self.analyze_evidence_file(file_path)
            file_results.append(analysis)
            
            if 'ml_analysis' in analysis:
                threat_level = analysis['ml_analysis']['threat_level']
                threat_summary[threat_level] = threat_summary.get(threat_level, 0) + 1
        
        # Analyze network logs if provided
        network_results = []
        anomaly_count = 0
        
        if network_logs:
            print(f"Analyzing {len(network_logs)} network packets...")
            for packet in network_logs[:1000]:  # Limit to 1000 packets
                analysis = self.analyze_network_packet(packet)
                network_results.append(analysis)
                
                if analysis['detection']['is_anomaly']:
                    anomaly_count += 1
        
        # Generate final report
        report = {
            'case_id': f"CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'analysis_timestamp': datetime.now().isoformat(),
            'file_analysis': {
                'total_files': len(case_files),
                'results': file_results,
                'threat_summary': threat_summary
            },
            'network_analysis': {
                'total_packets': len(network_logs) if network_logs else 0,
                'analyzed_packets': len(network_results),
                'anomalies_detected': anomaly_count,
                'anomaly_rate': f"{anomaly_count/len(network_results)*100:.2f}%" if network_results else "N/A",
                'results': network_results
            },
            'overall_assessment': self._generate_overall_assessment(
                threat_summary,
                anomaly_count,
                len(network_results)
            )
        }
        
        return report
    
    @staticmethod
    def _calculate_sha256(file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def _determine_threat_level(category, confidence):
        """Determine threat level based on category and confidence"""
        high_risk_categories = ['ransomware', 'trojan', 'backdoor', 'rootkit']
        medium_risk_categories = ['worm', 'virus', 'informationstealer']
        
        if category in high_risk_categories:
            if confidence > 0.7:
                return 'high_risk'
            else:
                return 'medium_risk'
        elif category in medium_risk_categories:
            return 'medium_risk'
        else:
            return 'low_risk'
    
    @staticmethod
    def _generate_recommendations(category, threat_level):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        if threat_level == 'high_risk':
            recommendations.extend([
                'Isolate affected system immediately',
                'Perform full system scan',
                'Check for lateral movement',
                'Review network logs for C2 communication',
                'Consider system reimaging'
            ])
        elif threat_level == 'medium_risk':
            recommendations.extend([
                'Quarantine suspicious file',
                'Perform behavioral analysis',
                'Monitor network activity',
                'Update antivirus signatures'
            ])
        else:
            recommendations.extend([
                'Monitor for suspicious behavior',
                'Log for future reference'
            ])
        
        # Category-specific recommendations
        if category == 'ransomware':
            recommendations.append('Check for encrypted files')
            recommendations.append('Verify backup integrity')
        elif category == 'backdoor':
            recommendations.append('Check for unauthorized remote access')
            recommendations.append('Review firewall logs')
        
        return recommendations
    
    @staticmethod
    def _generate_network_recommendations(result):
        """Generate recommendations for network anomalies"""
        if result['is_anomaly']:
            return [
                'Investigate packet contents',
                'Check source/destination IPs',
                'Review firewall rules',
                'Look for related traffic patterns',
                'Consider blocking source if malicious'
            ]
        else:
            return ['Normal traffic - continue monitoring']
    
    @staticmethod
    def _generate_batch_summary(results):
        """Generate summary for batch analysis"""
        total = len(results)
        high_risk = sum(1 for r in results if r.get('ml_analysis', {}).get('threat_level') == 'high_risk')
        medium_risk = sum(1 for r in results if r.get('ml_analysis', {}).get('threat_level') == 'medium_risk')
        
        return {
            'total_files': total,
            'high_risk_files': high_risk,
            'medium_risk_files': medium_risk,
            'risk_percentage': f"{(high_risk + medium_risk)/total*100:.1f}%" if total > 0 else "0%"
        }
    
    @staticmethod
    def _generate_overall_assessment(threat_summary, anomaly_count, total_packets):
        """Generate overall case assessment"""
        high_risk = threat_summary.get('high_risk', 0)
        anomaly_rate = anomaly_count / total_packets if total_packets > 0 else 0
        
        if high_risk > 0 or anomaly_rate > 0.2:
            severity = 'CRITICAL'
            recommendation = 'Immediate investigation required'
        elif threat_summary.get('medium_risk', 0) > 0 or anomaly_rate > 0.1:
            severity = 'MODERATE'
            recommendation = 'Further analysis recommended'
        else:
            severity = 'LOW'
            recommendation = 'Routine monitoring sufficient'
        
        return {
            'severity': severity,
            'recommendation': recommendation,
            'summary': f"{high_risk} high-risk files, {anomaly_count} network anomalies"
        }


def example_usage():
    """Example usage of ML integration"""
    print("="*70)
    print("FEPD ML INTEGRATION - EXAMPLE USAGE")
    print("="*70)
    
    # Initialize
    ml_integration = FEPDMLIntegration()
    
    # Example 1: Analyze a single file
    print("\n1. Single File Analysis")
    print("-" * 70)
    
    # Create a test file
    test_file = Path('test_sample.txt')
    test_file.write_text("This is a test file for malware analysis")
    
    analysis = ml_integration.analyze_evidence_file(test_file)
    print(f"File: {analysis['file']['name']}")
    print(f"Hash: {analysis['file']['hash']}")
    print(f"ML Category: {analysis['ml_analysis']['category']}")
    print(f"Confidence: {analysis['ml_analysis']['confidence']}")
    print(f"Threat Level: {analysis['ml_analysis']['threat_level']}")
    print(f"Recommendations: {', '.join(analysis['recommendations'][:3])}")
    
    # Example 2: Analyze network packet
    print("\n2. Network Packet Analysis")
    print("-" * 70)
    
    packet_data = {
        'timestamp': datetime.now(),
        'size': 1500,
        'is_truncated': False
    }
    
    analysis = ml_integration.analyze_network_packet(packet_data)
    print(f"Classification: {analysis['detection']['classification']}")
    print(f"Anomaly Score: {analysis['detection']['anomaly_score']}")
    print(f"Severity: {analysis['detection']['severity']}")
    
    # Example 3: Generate case report
    print("\n3. Case Report Generation")
    print("-" * 70)
    
    case_files = [test_file]
    network_logs = [
        {'timestamp': datetime.now(), 'size': 1500, 'is_truncated': False},
        {'timestamp': datetime.now(), 'size': 64, 'is_truncated': True},
    ]
    
    report = ml_integration.generate_case_report(case_files, network_logs)
    print(f"Case ID: {report['case_id']}")
    print(f"Files Analyzed: {report['file_analysis']['total_files']}")
    print(f"Packets Analyzed: {report['network_analysis']['analyzed_packets']}")
    print(f"Anomalies: {report['network_analysis']['anomalies_detected']}")
    print(f"Overall Severity: {report['overall_assessment']['severity']}")
    print(f"Recommendation: {report['overall_assessment']['recommendation']}")
    
    # Cleanup
    test_file.unlink()
    
    print("\n" + "="*70)
    print("EXAMPLE COMPLETED")
    print("="*70)


if __name__ == '__main__':
    example_usage()

"""
Complete Forensic Data Analysis Pipeline
Integrates all forensic analysis components: import, ML analysis, and timeline generation
"""

import sys
import logging
from pathlib import Path
from datetime import datetime

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.core.forensic_data_importer import ForensicDataImporter
from src.analysis.forensic_ml_analyzer import ForensicMLAnalyzer
from src.analysis.forensic_timeline_generator import ForensicTimelineGenerator
from src.utils.logger import setup_logging
from src.utils.config import Config

logger = logging.getLogger(__name__)


class ForensicAnalysisPipeline:
    """Complete forensic data analysis pipeline."""
    
    def __init__(self, case_path: Path, data_source_path: Path, models_dir: Path):
        """
        Initialize the analysis pipeline.
        
        Args:
            case_path: Path to the case directory
            data_source_path: Path to the dataa directory
            models_dir: Path to the models directory
        """
        self.case_path = Path(case_path)
        self.data_source_path = Path(data_source_path)
        self.models_dir = Path(models_dir)
        
        self.importer = None
        self.ml_analyzer = None
        self.timeline_generator = None
    
    def run_complete_analysis(self) -> dict:
        """
        Run the complete forensic analysis pipeline.
        
        Returns:
            Dictionary with all analysis results
        """
        logger.info("=" * 80)
        logger.info("STARTING COMPLETE FORENSIC ANALYSIS PIPELINE")
        logger.info("=" * 80)
        
        results = {
            'case_id': self.case_path.name,
            'start_time': datetime.now().isoformat(),
            'steps': {}
        }
        
        try:
            # Step 1: Import forensic data
            logger.info("\n[STEP 1/3] Importing forensic data into case...")
            self.importer = ForensicDataImporter(self.case_path, self.data_source_path)
            import_results = self.importer.import_all_data()
            results['steps']['import'] = import_results
            logger.info(f"✓ Import complete: {import_results['summary']}")
            
            # Step 2: ML Analysis
            logger.info("\n[STEP 2/3] Running ML analysis on forensic data...")
            forensic_data_dir = self.case_path / "forensic_data"
            self.ml_analyzer = ForensicMLAnalyzer(self.models_dir, forensic_data_dir)
            ml_results = self.ml_analyzer.generate_comprehensive_report()
            results['steps']['ml_analysis'] = ml_results
            logger.info("✓ ML analysis complete")
            
            # Step 3: Timeline Generation
            logger.info("\n[STEP 3/3] Generating forensic timelines...")
            self.timeline_generator = ForensicTimelineGenerator(forensic_data_dir)
            timeline_results = self.timeline_generator.generate_comprehensive_timeline()
            results['steps']['timeline'] = timeline_results
            logger.info("✓ Timeline generation complete")
            
            # Final summary
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'success'
            
            self._print_summary(results)
            
        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _print_summary(self, results: dict):
        """Print analysis summary."""
        logger.info("\n" + "=" * 80)
        logger.info("FORENSIC ANALYSIS PIPELINE COMPLETE")
        logger.info("=" * 80)
        
        import_data = results['steps'].get('import', {})
        ml_data = results['steps'].get('ml_analysis', {})
        timeline_data = results['steps'].get('timeline', {})
        
        logger.info("\n📊 IMPORT SUMMARY:")
        if import_data:
            summary = import_data.get('summary', {})
            logger.info(f"  • Malware Samples: {summary.get('total_malware_samples', 0):,}")
            logger.info(f"  • Honeypot Attacks: {summary.get('total_honeypot_attacks', 0):,}")
            logger.info(f"  • Network Traffic Days: {summary.get('total_network_days', 0)}")
            logger.info(f"  • Network Log Files: {summary.get('total_network_files', 0)}")
        
        logger.info("\n🤖 ML ANALYSIS SUMMARY:")
        if ml_data:
            exec_summary = ml_data.get('executive_summary', {})
            logger.info(f"  • Malware Samples Analyzed: {exec_summary.get('total_malware_samples_analyzed', 0):,}")
            logger.info(f"  • Network Days Analyzed: {exec_summary.get('total_network_days_analyzed', 0)}")
            
            critical = exec_summary.get('critical_findings', [])
            if critical:
                logger.info("  • Critical Findings:")
                for finding in critical:
                    logger.info(f"    - {finding}")
        
        logger.info("\n📅 TIMELINE SUMMARY:")
        if timeline_data:
            timelines = timeline_data.get('timelines', {})
            network = timelines.get('network', {})
            if network.get('status') == 'success':
                logger.info(f"  • Network Timeline: {network.get('total_days', 0)} days")
                key_events = network.get('key_events', [])
                logger.info(f"  • Key Events Identified: {len(key_events)}")
        
        logger.info("\n" + "=" * 80)


def main():
    """Main entry point."""
    # Initialize configuration and logging
    config = Config()
    setup_logging(config)
    
    print("\n" + "=" * 80)
    print("FEPD - COMPLETE FORENSIC ANALYSIS PIPELINE")
    print("=" * 80)
    print("\nThis pipeline will:")
    print("1. Import forensic data (malware, honeypot, network traffic)")
    print("2. Run ML analysis on imported data")
    print("3. Generate comprehensive timelines")
    print("4. Produce detailed reports")
    print("\n" + "=" * 80 + "\n")
    
    # Define paths
    workspace_dir = Path(__file__).parent
    case_path = workspace_dir / "cases" / "d"  # Use the case from modal test
    data_source_path = workspace_dir / "dataa"
    models_dir = workspace_dir / "models"
    
    # Verify paths
    if not case_path.exists():
        print(f"❌ Error: Case directory not found: {case_path}")
        return 1
    
    if not data_source_path.exists():
        print(f"❌ Error: Data source directory not found: {data_source_path}")
        return 1
    
    if not models_dir.exists():
        print(f"❌ Error: Models directory not found: {models_dir}")
        return 1
    
    print(f"✓ Case Path: {case_path}")
    print(f"✓ Data Source: {data_source_path}")
    print(f"✓ Models: {models_dir}")
    print("\nStarting analysis...\n")
    
    # Create and run pipeline
    pipeline = ForensicAnalysisPipeline(case_path, data_source_path, models_dir)
    results = pipeline.run_complete_analysis()
    
    # Print results location
    if results.get('status') == 'success':
        print("\n" + "=" * 80)
        print("✅ ANALYSIS COMPLETE!")
        print("=" * 80)
        print(f"\nResults saved to: {case_path / 'forensic_data'}")
        print("\nGenerated files:")
        print("  • forensic_data/import_manifest.json")
        print("  • forensic_data/comprehensive_ml_report.json")
        print("  • forensic_data/timeline/comprehensive_timeline.json")
        print("  • forensic_data/malware/ml_analysis_results.json")
        print("  • forensic_data/network/ml_analysis_results.json")
        print("\n" + "=" * 80 + "\n")
        return 0
    else:
        print("\n❌ Analysis failed. Check logs for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

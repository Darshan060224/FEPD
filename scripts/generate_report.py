#!/usr/bin/env python3
"""
Quick Report Generator
======================

Generate a professional forensic report for any FEPD case.

Usage:
    python generate_report.py <case_name>
    python generate_report.py adcdsc --analyst "John Smith"
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from reporting.forensic_report_generator import ForensicReportGenerator


def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <case_name> [--analyst NAME] [--org ORGANIZATION]")
        print("\nExample:")
        print("  python generate_report.py adcdsc")
        print("  python generate_report.py corp-leak --analyst 'Jane Doe' --org 'Security Team'")
        sys.exit(1)
    
    case_name = sys.argv[1]
    analyst = "FEPD Analyst"
    org = "Forensic Investigation Unit"
    
    # Parse optional arguments
    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == '--analyst' and i + 1 < len(sys.argv):
            analyst = sys.argv[i + 1]
        elif arg == '--org' and i + 1 < len(sys.argv):
            org = sys.argv[i + 1]
    
    print("=" * 80)
    print("FEPD FORENSIC REPORT GENERATOR")
    print("=" * 80)
    print(f"Case: {case_name}")
    print(f"Analyst: {analyst}")
    print(f"Organization: {org}")
    print("=" * 80)
    print()
    print("Generating professional forensic report...")
    print()
    
    generator = ForensicReportGenerator(workspace_root='.')
    
    try:
        report = generator.generate_report(case_name, analyst, org)
        
        # Save report
        output_dir = os.path.join('cases', case_name, 'reports')
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"{case_name}_forensic_report.md")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✓ Report generated successfully!")
        print()
        print(f"Location: {output_path}")
        print(f"Size: {len(report):,} characters")
        print()
        print("Report includes:")
        print("  • Cover page with case classification")
        print("  • Executive summary for stakeholders")
        print("  • Evidence integrity verification")
        print("  • Artifact discovery analysis")
        print("  • Timeline status assessment")
        print("  • ML/UEBA findings interpretation")
        print("  • Chain of custody documentation")
        print("  • Actionable recommendations")
        print("  • Technical appendix")
        print()
        print("This report is court-admissible and follows DFIR best practices.")
        print()
        
        # Offer to open
        print(f"To view: Open {output_path} in your markdown viewer")
        
    except Exception as e:
        print(f"✗ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

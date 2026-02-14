#!/usr/bin/env python3
"""
VulnReach Pipeline - Quick Start CLI

Complete security analysis pipeline that runs:
1. SBOM Generation → SCA Scanning → Exploit Analysis
2. Static Taint Analysis  
3. Container Detection → Dynamic Analysis (conditional)
4. Correlation (Static ↔ Dynamic)
5. Unified Output Generation

Usage:
    python run_vulnreach.py <project_path> [options]

Examples:
    # Full analysis
    python run_vulnreach.py ./labs/python_vuln_app
    
    # Skip dynamic analysis
    python run_vulnreach.py ./labs/python_vuln_app --no-dynamic
    
    # Skip exploitability  
    python run_vulnreach.py ./labs/python_vuln_app --no-exploits
    
    # Custom output directory
    python run_vulnreach.py ./labs/python_vuln_app --output ./results
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from vulnreach.pipeline.pipeline import VulnReachPipeline, PipelineConfig


def main():
    parser = argparse.ArgumentParser(
        description='VulnReach Pipeline - Complete Security Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        'project_path',
        help='Path to the project to analyze'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output directory for findings (default: security_findings/<project_name>)'
    )
    
    parser.add_argument(
        '--no-sbom',
        action='store_true',
        help='Skip SBOM generation'
    )
    
    parser.add_argument(
        '--no-sca',
        action='store_true',
        help='Skip SCA scanning'
    )
    
    parser.add_argument(
        '--no-exploits',
        action='store_true',
        help='Skip exploitability analysis'
    )
    
    parser.add_argument(
        '--no-taint',
        action='store_true',
        help='Skip static taint analysis'
    )
    
    parser.add_argument(
        '--no-dynamic',
        action='store_true',
        help='Skip dynamic analysis'
    )
    
    parser.add_argument(
        '--no-correlation',
        action='store_true',
        help='Skip correlation analysis'
    )
    
    parser.add_argument(
        '--sbom-format',
        default='spdx-json',
        choices=['spdx-json', 'cyclonedx-json', 'syft-json'],
        help='SBOM format (default: spdx-json)'
    )
    
    parser.add_argument(
        '--docker-image',
        help='Docker image name for container-based dynamic analysis'
    )

    parser.add_argument(
        '--use-container',
        action='store_true',
        help='Run dynamic analysis inside Docker container'
    )

    args = parser.parse_args()
    
    # Create configuration
    config = PipelineConfig(
        enable_sbom=not args.no_sbom,
        enable_sca=not args.no_sca,
        enable_exploitability=not args.no_exploits,
        enable_static_taint=not args.no_taint,
        enable_dynamic=not args.no_dynamic,
        enable_correlation=not args.no_correlation,
        sbom_format=args.sbom_format,
        output_dir=args.output,
        docker_image=args.docker_image,
        use_container=args.use_container
    )
    
    # Run pipeline
    print("🚀 Starting VulnReach Pipeline...")
    print(f"📁 Project: {args.project_path}")
    print()
    
    pipeline = VulnReachPipeline(args.project_path, config)
    results = pipeline.run_full_analysis()
    
    if results['success']:
        print("\n" + "=" * 70)
        print("✅ PIPELINE COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        print(f"\n📊 Summary:")
        summary = results.get('summary', {})
        print(f"   Total Components: {summary.get('total_components', 0)}")
        print(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   Duration: {results.get('duration', 0):.2f} seconds")
        print(f"\n📄 Results saved to:")
        print(f"   {results['output_path']}")
        print("\n" + "=" * 70)
        sys.exit(0)
    else:
        print(f"\n❌ Pipeline failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == '__main__':
    main()

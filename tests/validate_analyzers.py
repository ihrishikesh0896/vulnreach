#!/usr/bin/env python3
"""
Simple validation script to confirm all analyzers exist and have correct entry points.
"""

import os
from pathlib import Path

def validate_analyzers():
    """Validate that all analyzer files exist and have correct structure."""

    base_path = Path(__file__).parent / 'src' / 'vulnreach' / 'utils'

    analyzers = {
        'Python': ('vuln_reachability_analyzer.py', 'run_reachability_analysis'),
        'Java': ('java_reachability_analyzer.py', 'run_java_reachability_analysis'),
        'JavaScript': ('javascript_reachability_analyzer.py', 'run_javascript_reachability_analysis'),
        'Go': ('go_reachability_analyzer.py', 'run_go_reachability_analysis'),
        'C#': ('csharp_reachability_analyzer.py', 'run_csharp_reachability_analysis'),
        'PHP': ('php_reachability_analyzer.py', 'run_php_reachability_analysis'),
    }

    print("=" * 70)
    print("ANALYZER VALIDATION REPORT")
    print("=" * 70)
    print()

    all_valid = True

    for language, (filename, entry_point) in analyzers.items():
        file_path = base_path / filename

        # Check file exists
        if not file_path.exists():
            print(f"✗ {language:15} - File missing: {filename}")
            all_valid = False
            continue

        # Check entry point function exists
        with open(file_path, 'r') as f:
            content = f.read()
            has_entry_point = f'def {entry_point}' in content

        # Check file size
        file_size = file_path.stat().st_size

        if has_entry_point:
            print(f"✓ {language:15} - {filename:45} ({file_size:,} bytes)")
        else:
            print(f"✗ {language:15} - Missing entry point: {entry_point}")
            all_valid = False

    print()
    print("=" * 70)

    # Check multi_language_analyzer.py
    multi_lang_path = base_path / 'multi_language_analyzer.py'
    if multi_lang_path.exists():
        with open(multi_lang_path, 'r') as f:
            content = f.read()

        print("Multi-Language Analyzer:")
        print(f"  File: {multi_lang_path.name} ({multi_lang_path.stat().st_size:,} bytes)")
        print(f"  Dynamic imports:")

        for lang in ['javascript', 'go', 'csharp', 'php']:
            has_import = f'{lang}_reachability_analyzer' in content
            print(f"    {'✓' if has_import else '✗'} {lang}")

    print()
    print("=" * 70)

    if all_valid:
        print("✓ ALL ANALYZERS VALIDATED SUCCESSFULLY")
    else:
        print("✗ VALIDATION FAILED - SOME ANALYZERS MISSING OR INCOMPLETE")

    print("=" * 70)

    return all_valid


if __name__ == "__main__":
    import sys
    success = validate_analyzers()
    sys.exit(0 if success else 1)


#!/usr/bin/env python3
"""
Example: How to Club Multiple Language Analyzers

This demonstrates analyzing a multi-language project (e.g., Python + JavaScript)
"""

import os
import json
from pathlib import Path
from typing import List, Dict


def analyze_multi_language_project_enhanced(project_root: str, consolidated_path: str, output_dir: str):
    """
    Enhanced version that analyzes ALL languages in a project, not just the primary one.

    This is an example of how you could extend the existing system to handle
    projects with multiple programming languages (e.g., Python backend + JavaScript frontend).
    """

    # Import the language-specific analyzers
    try:
        from vulnreach.utils.vuln_reachability_analyzer import run_reachability_analysis
    except ImportError:
        run_reachability_analysis = None

    try:
        from vulnreach.utils.java_reachability_analyzer import run_java_reachability_analysis
    except ImportError:
        run_java_reachability_analysis = None

    try:
        from vulnreach.utils.javascript_reachability_analyzer import run_javascript_reachability_analysis
    except ImportError:
        run_javascript_reachability_analysis = None

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Detect ALL languages in the project (not just primary)
    languages_detected = detect_all_languages(project_root)

    print(f"🔍 Detected languages in project: {', '.join(languages_detected)}")
    print(f"📊 Analyzing {len(languages_detected)} language(s)...\n")

    # Run analysis for each detected language
    results = {}

    for language in languages_detected:
        print(f"🔄 Analyzing {language.upper()} codebase...")

        if language == 'python' and run_reachability_analysis:
            output_path = os.path.join(output_dir, "python_vulnerability_reachability_report.json")
            run_reachability_analysis(project_root, consolidated_path, output_path)
            results['python'] = output_path
            print(f"   ✅ Python analysis complete → {output_path}")

        elif language == 'java' and run_java_reachability_analysis:
            output_path = os.path.join(output_dir, "java_vulnerability_reachability_report.json")
            run_java_reachability_analysis(project_root, consolidated_path, output_path)
            results['java'] = output_path
            print(f"   ✅ Java analysis complete → {output_path}")

        elif language == 'javascript' and run_javascript_reachability_analysis:
            output_path = os.path.join(output_dir, "javascript_vulnerability_reachability_report.json")
            run_javascript_reachability_analysis(project_root, consolidated_path, output_path)
            results['javascript'] = output_path
            print(f"   ✅ JavaScript analysis complete → {output_path}")

        else:
            print(f"   ⚠️  {language.upper()} analyzer not available, skipping...")

        print()

    # Generate consolidated multi-language report
    if results:
        consolidated_report = generate_consolidated_report(results)
        consolidated_path = os.path.join(output_dir, "multi_language_consolidated_report.json")

        with open(consolidated_path, 'w') as f:
            json.dump(consolidated_report, f, indent=2)

        print(f"📋 Consolidated multi-language report: {consolidated_path}")
        print_multi_language_summary(consolidated_report)

    return results


def detect_all_languages(project_root: str, threshold: int = 3) -> List[str]:
    """
    Detect ALL languages in a project (not just the primary one).

    Args:
        project_root: Path to project root
        threshold: Minimum number of files to consider a language present

    Returns:
        List of detected language names
    """
    project_path = Path(project_root)
    file_counts = {}
    build_files = set()

    exclude_dirs = {
        '.git', '__pycache__', '.venv', 'venv', 'node_modules',
        'target', 'build', '.gradle', '.idea', '.vscode', 'bin', 'out'
    }

    # Scan project structure
    for root, dirs, files in os.walk(project_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            # Count source files
            if file.endswith('.py'):
                file_counts['python'] = file_counts.get('python', 0) + 1
            elif file.endswith('.java'):
                file_counts['java'] = file_counts.get('java', 0) + 1
            elif file.endswith(('.js', '.ts', '.jsx', '.tsx')):
                file_counts['javascript'] = file_counts.get('javascript', 0) + 1
            elif file.endswith('.go'):
                file_counts['go'] = file_counts.get('go', 0) + 1
            elif file.endswith('.cs'):
                file_counts['csharp'] = file_counts.get('csharp', 0) + 1
            elif file.endswith('.php'):
                file_counts['php'] = file_counts.get('php', 0) + 1
            elif file.endswith('.rs'):
                file_counts['rust'] = file_counts.get('rust', 0) + 1
            elif file.endswith('.rb'):
                file_counts['ruby'] = file_counts.get('ruby', 0) + 1

            # Track build files
            if file in {'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'}:
                build_files.add('python')
            elif file in {'pom.xml', 'build.gradle', 'build.gradle.kts'}:
                build_files.add('java')
            elif file in {'package.json', 'yarn.lock'}:
                build_files.add('javascript')
            elif file in {'go.mod', 'go.sum'}:
                build_files.add('go')
            elif file.endswith(('.csproj', '.sln')):
                build_files.add('csharp')
            elif file == 'composer.json':
                build_files.add('php')
            elif file == 'Cargo.toml':
                build_files.add('rust')
            elif file == 'Gemfile':
                build_files.add('ruby')

    # Determine which languages are present
    detected_languages = []

    for language, count in file_counts.items():
        # Include if: has build file OR meets threshold
        if language in build_files or count >= threshold:
            detected_languages.append(language)

    # Sort by file count (most files first)
    detected_languages.sort(key=lambda lang: file_counts.get(lang, 0), reverse=True)

    return detected_languages if detected_languages else ['unknown']


def generate_consolidated_report(analysis_results: Dict[str, str]) -> Dict:
    """
    Generate a consolidated report from multiple language-specific reports.

    Args:
        analysis_results: Dict mapping language to report file path

    Returns:
        Consolidated report dictionary
    """
    consolidated = {
        "languages_analyzed": list(analysis_results.keys()),
        "total_languages": len(analysis_results),
        "summary": {
            "total_vulnerabilities": 0,
            "critical_reachable": 0,
            "high_reachable": 0,
            "medium_reachable": 0,
            "low_reachable": 0,
            "not_reachable": 0
        },
        "by_language": {}
    }

    # Load and aggregate each language report
    for language, report_path in analysis_results.items():
        try:
            with open(report_path, 'r') as f:
                language_report = json.load(f)

            # Extract summary
            if 'summary' in language_report:
                lang_summary = language_report['summary']
                consolidated['by_language'][language] = lang_summary

                # Aggregate totals
                consolidated['summary']['total_vulnerabilities'] += lang_summary.get('total_vulnerabilities', 0)
                consolidated['summary']['critical_reachable'] += lang_summary.get('critical_reachable', 0)
                consolidated['summary']['high_reachable'] += lang_summary.get('high_reachable', 0)
                consolidated['summary']['medium_reachable'] += lang_summary.get('medium_reachable', 0)
                consolidated['summary']['low_reachable'] += lang_summary.get('low_reachable', 0)
                consolidated['summary']['not_reachable'] += lang_summary.get('not_reachable', 0)

        except Exception as e:
            print(f"⚠️  Could not load {language} report: {e}")
            consolidated['by_language'][language] = {"error": str(e)}

    return consolidated


def print_multi_language_summary(report: Dict):
    """Print a summary of the multi-language analysis"""
    print("\n" + "="*70)
    print("🌍 MULTI-LANGUAGE VULNERABILITY ANALYSIS SUMMARY")
    print("="*70)

    summary = report['summary']
    print(f"\n📊 Overall Statistics:")
    print(f"   Languages analyzed: {report['total_languages']}")
    print(f"   Total vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"   🔴 Critical (actively used): {summary['critical_reachable']}")
    print(f"   🟠 High (used with calls): {summary['high_reachable']}")
    print(f"   🟡 Medium (imported): {summary['medium_reachable']}")
    print(f"   🟢 Low (limited usage): {summary['low_reachable']}")
    print(f"   ⚪ Not reachable: {summary['not_reachable']}")

    print(f"\n📋 By Language:")
    for language, lang_summary in report['by_language'].items():
        if 'error' in lang_summary:
            print(f"   ❌ {language.upper()}: Error - {lang_summary['error']}")
        else:
            total = lang_summary.get('total_vulnerabilities', 0)
            critical = lang_summary.get('critical_reachable', 0)
            high = lang_summary.get('high_reachable', 0)
            print(f"   ✅ {language.upper()}: {total} vulnerabilities "
                  f"({critical} critical, {high} high)")

    print("="*70 + "\n")


# ============================================================================
# Example Usage Scenarios
# ============================================================================

def example_1_single_language():
    """Example 1: Analyze a single-language project (current behavior)"""
    print("\n" + "="*70)
    print("EXAMPLE 1: Single Language Project (Python)")
    print("="*70 + "\n")

    from vulnreach.utils.multi_language_analyzer import run_multi_language_analysis

    # This is the existing behavior - analyzes primary language only
    language = run_multi_language_analysis(
        project_root="./my-python-app",
        consolidated_path="security_findings/consolidated.json",
        output_dir="security_findings"
    )

    print(f"Analyzed primary language: {language}")


def example_2_multi_language():
    """Example 2: Analyze a multi-language project (enhanced version)"""
    print("\n" + "="*70)
    print("EXAMPLE 2: Multi-Language Project (Python + JavaScript)")
    print("="*70 + "\n")

    # Use the enhanced version that analyzes ALL detected languages
    results = analyze_multi_language_project_enhanced(
        project_root="./my-fullstack-app",
        consolidated_path="security_findings/consolidated.json",
        output_dir="security_findings"
    )

    print(f"Analyzed {len(results)} languages: {list(results.keys())}")


def example_3_selective_analysis():
    """Example 3: Analyze specific languages only"""
    print("\n" + "="*70)
    print("EXAMPLE 3: Selective Language Analysis")
    print("="*70 + "\n")

    from vulnreach.utils.vuln_reachability_analyzer import run_reachability_analysis
    from vulnreach.utils.java_reachability_analyzer import run_java_reachability_analysis

    # Manually run specific analyzers
    run_reachability_analysis(
        "./backend",
        "security_findings/consolidated.json",
        "security_findings/backend_python_report.json"
    )

    run_java_reachability_analysis(
        "./services",
        "security_findings/consolidated.json",
        "security_findings/services_java_report.json"
    )

    print("✅ Analyzed Python backend and Java services separately")


if __name__ == "__main__":
    import sys

    print("""
╔══════════════════════════════════════════════════════════════╗
║   Multi-Language Analyzer - Clubbing Example                ║
║                                                              ║
║   This demonstrates how to analyze projects with multiple   ║
║   programming languages (e.g., Python + JavaScript).        ║
╚══════════════════════════════════════════════════════════════╝
    """)

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python clubbing_example.py <project_root> <consolidated_json> [output_dir]")
        print()
        print("Example:")
        print("  python clubbing_example.py ./my-fullstack-app security_findings/consolidated.json security_findings")
        print()
        print("This will:")
        print("  1. Detect all languages in the project")
        print("  2. Run appropriate analyzer for each language")
        print("  3. Generate individual reports per language")
        print("  4. Create a consolidated multi-language report")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "security_findings"

    # Run the enhanced multi-language analysis
    analyze_multi_language_project_enhanced(project_root, consolidated_path, output_dir)


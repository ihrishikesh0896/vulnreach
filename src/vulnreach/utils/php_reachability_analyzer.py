#!/usr/bin/env python3
"""
PHP Vulnerability Reachability Analyzer

Analyzes whether vulnerable PHP packages are actually used in the codebase,
providing intelligent risk assessment beyond simple version checking.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass, asdict
from enum import Enum


class CriticalityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_REACHABLE = "NOT_REACHABLE"


@dataclass
class UsageContext:
    file_path: str
    line_number: int
    context_line: str
    usage_type: str  # "use", "namespace", "function_call", "class_usage"


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str


class PHPReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        # Common PHP use/namespace patterns
        self.use_patterns = [
            re.compile(r'^\s*use\s+([a-zA-Z_\\][a-zA-Z0-9_\\]*)\s*;'),
            re.compile(r'^\s*use\s+([a-zA-Z_\\][a-zA-Z0-9_\\]*)\s+as\s+'),
            re.compile(r'^\s*namespace\s+([a-zA-Z_\\][a-zA-Z0-9_\\]*)\s*;')
        ]

    def find_php_files(self) -> List[Path]:
        """Find all PHP source files in the project."""
        php_files = []
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'vendor', 'node_modules', 'cache', 'var'
            }]
            for file in files:
                if file.endswith('.php'):
                    php_files.append(Path(root) / file)
        return php_files

    def extract_use_statements(self, file_path: Path) -> Set[str]:
        """Extract use statements from a PHP file."""
        uses = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    for pattern in self.use_patterns:
                        match = pattern.match(line)
                        if match:
                            uses.add(match.group(1))
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")
        return uses

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        """Find all usages of a package in the codebase."""
        usage_contexts = []
        php_files = self.find_php_files()

        # Convert package name to namespace pattern (e.g., "vendor/package" -> "Vendor\\Package")
        namespace_variants = [
            package_name,
            package_name.replace('/', '\\'),
            package_name.replace('-', ''),
        ]

        for php_file in php_files:
            try:
                with open(php_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # Check for any variant of the package name
                        for variant in namespace_variants:
                            if variant.lower() in line.lower():
                                usage_type = "use" if "use " in line else "usage"
                                if "namespace" in line:
                                    usage_type = "namespace"

                                usage_contexts.append(UsageContext(
                                    file_path=str(php_file.relative_to(self.project_root)),
                                    line_number=line_num,
                                    context_line=line.strip(),
                                    usage_type=usage_type
                                ))
                                break
            except Exception as e:
                print(f"Warning: Could not read {php_file}: {e}")

        return usage_contexts

    def parse_composer_json(self) -> Dict[str, str]:
        """Parse dependencies from composer.json."""
        dependencies = {}
        composer_file = self.project_root / "composer.json"

        if not composer_file.exists():
            return dependencies

        try:
            with open(composer_file, 'r', encoding='utf-8') as f:
                composer_data = json.load(f)

                # Get both require and require-dev
                for section in ['require', 'require-dev']:
                    if section in composer_data:
                        for package, version in composer_data[section].items():
                            if package != 'php':  # Skip PHP itself
                                dependencies[package] = version
        except Exception as e:
            print(f"Warning: Could not parse composer.json: {e}")

        return dependencies

    def analyze_vulnerability(self, vuln_data: Dict) -> VulnAnalysis:
        """Analyze a single vulnerability for reachability."""
        package_name = vuln_data.get('package_name', '')
        installed_version = vuln_data.get('installed_version', '')
        recommended_version = vuln_data.get('recommended_version', '')

        # Find usages
        usage_contexts = self.find_package_usage(package_name)
        is_used = len(usage_contexts) > 0

        # Determine criticality
        if not is_used:
            criticality = CriticalityLevel.NOT_REACHABLE
            risk_reason = "Package declared but not actively used in code"
        else:
            severity = vuln_data.get('severity', 'MEDIUM').upper()
            if severity == 'CRITICAL':
                criticality = CriticalityLevel.CRITICAL
            elif severity == 'HIGH':
                criticality = CriticalityLevel.HIGH
            elif severity == 'MEDIUM':
                criticality = CriticalityLevel.MEDIUM
            else:
                criticality = CriticalityLevel.LOW

            risk_reason = f"Package actively used in {len(usage_contexts)} location(s)"

        return VulnAnalysis(
            package_name=package_name,
            installed_version=installed_version,
            recommended_version=recommended_version,
            is_used=is_used,
            usage_contexts=usage_contexts,
            criticality=criticality,
            risk_reason=risk_reason
        )


def run_php_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    """Main entry point for PHP reachability analysis."""
    print(f"\n{'='*60}")
    print("PHP Vulnerability Reachability Analysis")
    print(f"{'='*60}\n")

    # Load consolidated vulnerabilities
    try:
        with open(consolidated_path, 'r') as f:
            consolidated_data = json.load(f)
    except Exception as e:
        print(f"Error loading consolidated data: {e}")
        return

    analyzer = PHPReachabilityAnalyzer(project_root)

    # Get installed dependencies
    installed_deps = analyzer.parse_composer_json()
    print(f"📦 Found {len(installed_deps)} PHP packages")

    # Analyze each vulnerability
    analyses = []

    # Handle both list and dict formats
    if isinstance(consolidated_data, list):
        vulnerabilities = consolidated_data
    elif isinstance(consolidated_data, dict):
        vulnerabilities = consolidated_data.get('vulnerabilities', [])
    else:
        print("Error: consolidated data must be a list or dict")
        return

    print(f"🔍 Analyzing {len(vulnerabilities)} vulnerabilities...\n")

    for vuln in vulnerabilities:
        analysis = analyzer.analyze_vulnerability(vuln)
        analyses.append(analysis)

        # Print summary
        status = "✓ USED" if analysis.is_used else "✗ NOT USED"
        print(f"{status} | {analysis.package_name:30} | {analysis.criticality.value:15} | {analysis.risk_reason}")

    # Generate report
    report = {
        "project_root": project_root,
        "language": "php",
        "total_vulnerabilities": len(vulnerabilities),
        "reachable_vulnerabilities": sum(1 for a in analyses if a.is_used),
        "not_reachable_vulnerabilities": sum(1 for a in analyses if not a.is_used),
        "analyses": [
            {
                **{k: v for k, v in asdict(a).items() if k != 'usage_contexts'},
                'criticality': a.criticality.value,
                'usage_count': len(a.usage_contexts),
                'usage_contexts': [asdict(uc) for uc in a.usage_contexts[:5]]  # Limit to 5 examples
            }
            for a in analyses
        ]
    }

    # Save report
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*60}")
    print(f"✓ Report saved to: {output_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python php_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "php_vulnerability_reachability_report.json"

    run_php_reachability_analysis(project_root, consolidated_path, output_path)


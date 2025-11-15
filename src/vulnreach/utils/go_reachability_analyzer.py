#!/usr/bin/env python3
"""
Go Vulnerability Reachability Analyzer

Analyzes whether vulnerable Go packages are actually used in the codebase,
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
    usage_type: str  # "import", "blank_import", "aliased_import"


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str


class GoReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        # Common Go import patterns
        self.import_patterns = [
            # Single import
            re.compile(r'^\s*import\s+"([^"]+)"'),
            # Aliased import
            re.compile(r'^\s*import\s+\w+\s+"([^"]+)"'),
            # Blank import
            re.compile(r'^\s*import\s+_\s+"([^"]+)"'),
            # Multi-line imports
            re.compile(r'^\s*"([^"]+)"'),
        ]

    def find_go_files(self) -> List[Path]:
        """Find all Go source files in the project."""
        go_files = []
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'vendor', 'bin', '.idea', '.vscode'
            }]
            for file in files:
                if file.endswith('.go') and not file.endswith('_test.go'):
                    go_files.append(Path(root) / file)
        return go_files

    def extract_imports(self, file_path: Path) -> Set[str]:
        """Extract import statements from a Go file."""
        imports = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                in_import_block = False
                for line in f:
                    # Check for import block start
                    if re.match(r'^\s*import\s*\(', line):
                        in_import_block = True
                        continue

                    # Check for import block end
                    if in_import_block and ')' in line:
                        in_import_block = False
                        continue

                    # Parse imports
                    for pattern in self.import_patterns:
                        match = pattern.match(line)
                        if match:
                            imports.add(match.group(1))
                            break
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")
        return imports

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        """Find all usages of a package in the codebase."""
        usage_contexts = []
        go_files = self.find_go_files()

        # Normalize package name for matching
        package_patterns = [
            re.compile(rf'import\s+"[^"]*{re.escape(package_name)}[^"]*"'),
            re.compile(rf'import\s+\w+\s+"[^"]*{re.escape(package_name)}[^"]*"'),
            re.compile(rf'import\s+_\s+"[^"]*{re.escape(package_name)}[^"]*"'),
            re.compile(rf'"[^"]*{re.escape(package_name)}[^"]*"'),
        ]

        for go_file in go_files:
            try:
                with open(go_file, 'r', encoding='utf-8', errors='ignore') as f:
                    in_import_block = False
                    for line_num, line in enumerate(f, 1):
                        # Track import blocks
                        if re.match(r'^\s*import\s*\(', line):
                            in_import_block = True
                        elif in_import_block and ')' in line:
                            in_import_block = False

                        # Check for package usage
                        for pattern in package_patterns:
                            if pattern.search(line):
                                usage_type = "import"
                                if "_ " in line:
                                    usage_type = "blank_import"
                                elif re.match(r'^\s*import\s+\w+\s+', line):
                                    usage_type = "aliased_import"

                                usage_contexts.append(UsageContext(
                                    file_path=str(go_file.relative_to(self.project_root)),
                                    line_number=line_num,
                                    context_line=line.strip(),
                                    usage_type=usage_type
                                ))
                                break
            except Exception as e:
                print(f"Warning: Could not read {go_file}: {e}")

        return usage_contexts

    def parse_go_mod(self) -> Dict[str, str]:
        """Parse dependencies from go.mod."""
        dependencies = {}
        go_mod_file = self.project_root / "go.mod"

        if not go_mod_file.exists():
            return dependencies

        try:
            with open(go_mod_file, 'r', encoding='utf-8') as f:
                in_require_block = False
                for line in f:
                    line = line.strip()

                    # Check for require block
                    if line.startswith('require ('):
                        in_require_block = True
                        continue
                    elif in_require_block and line == ')':
                        in_require_block = False
                        continue

                    # Parse require statements
                    if in_require_block or line.startswith('require '):
                        # Remove 'require ' prefix if single-line
                        if line.startswith('require '):
                            line = line[8:]

                        # Parse package and version
                        parts = line.split()
                        if len(parts) >= 2:
                            package = parts[0]
                            version = parts[1]
                            dependencies[package] = version
        except Exception as e:
            print(f"Warning: Could not parse go.mod: {e}")

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
            risk_reason = "Package declared but not actively imported in code"
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

            risk_reason = f"Package actively imported in {len(usage_contexts)} location(s)"

        return VulnAnalysis(
            package_name=package_name,
            installed_version=installed_version,
            recommended_version=recommended_version,
            is_used=is_used,
            usage_contexts=usage_contexts,
            criticality=criticality,
            risk_reason=risk_reason
        )


def run_go_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    """Main entry point for Go reachability analysis."""
    print(f"\n{'='*60}")
    print("Go Vulnerability Reachability Analysis")
    print(f"{'='*60}\n")

    # Load consolidated vulnerabilities
    try:
        with open(consolidated_path, 'r') as f:
            consolidated_data = json.load(f)
    except Exception as e:
        print(f"Error loading consolidated data: {e}")
        return

    analyzer = GoReachabilityAnalyzer(project_root)

    # Get installed dependencies
    installed_deps = analyzer.parse_go_mod()
    print(f"📦 Found {len(installed_deps)} Go packages")

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
        "language": "go",
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
        print("Usage: python go_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "go_vulnerability_reachability_report.json"

    run_go_reachability_analysis(project_root, consolidated_path, output_path)


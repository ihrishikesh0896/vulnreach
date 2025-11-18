#!/usr/bin/env python3
"""
C# Vulnerability Reachability Analyzer

Analyzes whether vulnerable C# packages are actually used in the codebase,
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
    usage_type: str  # "using", "method_call", "instantiation"


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str


class CSharpReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        # Common C# using patterns
        self.using_patterns = [
            re.compile(r'^\s*using\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*;'),
            re.compile(r'^\s*using\s+static\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*;'),
            re.compile(r'^\s*using\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*=')
        ]

    def find_cs_files(self) -> List[Path]:
        """Find all C# source files in the project."""
        cs_files = []
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'bin', 'obj', 'packages', '.vs', 'node_modules'
            }]
            for file in files:
                if file.endswith('.cs'):
                    cs_files.append(Path(root) / file)
        return cs_files

    def extract_using_statements(self, file_path: Path) -> Set[str]:
        """Extract using statements from a C# file."""
        usings = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    for pattern in self.using_patterns:
                        match = pattern.match(line)
                        if match:
                            usings.add(match.group(1))
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")
        return usings

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        """Find all usages of a package in the codebase."""
        usage_contexts = []
        cs_files = self.find_cs_files()

        # Normalize package name for matching
        package_patterns = [
            re.compile(rf'\busing\s+{re.escape(package_name)}\b'),
            re.compile(rf'\b{re.escape(package_name)}\.')
        ]

        for cs_file in cs_files:
            try:
                with open(cs_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in package_patterns:
                            if pattern.search(line):
                                usage_type = "using" if "using" in line else "usage"
                                usage_contexts.append(UsageContext(
                                    file_path=str(cs_file.relative_to(self.project_root)),
                                    line_number=line_num,
                                    context_line=line.strip(),
                                    usage_type=usage_type
                                ))
                                break
            except Exception as e:
                print(f"Warning: Could not read {cs_file}: {e}")

        return usage_contexts

    def parse_csproj_dependencies(self) -> Dict[str, str]:
        """Parse dependencies from .csproj files."""
        dependencies = {}

        for csproj_file in self.project_root.rglob("*.csproj"):
            try:
                with open(csproj_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Match PackageReference entries
                    pattern = re.compile(
                        r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
                        re.IGNORECASE
                    )
                    for match in pattern.finditer(content):
                        package_name = match.group(1)
                        version = match.group(2)
                        dependencies[package_name] = version
            except Exception as e:
                print(f"Warning: Could not parse {csproj_file}: {e}")

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


def run_csharp_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    """Main entry point for C# reachability analysis."""
    print(f"\n{'='*60}")
    print("C# Vulnerability Reachability Analysis")
    print(f"{'='*60}\n")

    # Load consolidated vulnerabilities
    try:
        with open(consolidated_path, 'r') as f:
            consolidated_data = json.load(f)
    except Exception as e:
        print(f"Error loading consolidated data: {e}")
        return

    analyzer = CSharpReachabilityAnalyzer(project_root)

    # Get installed dependencies
    installed_deps = analyzer.parse_csproj_dependencies()
    print(f"📦 Found {len(installed_deps)} C# packages")

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
        "language": "csharp",
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
        print("Usage: python csharp_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "csharp_vulnerability_reachability_report.json"

    run_csharp_reachability_analysis(project_root, consolidated_path, output_path)


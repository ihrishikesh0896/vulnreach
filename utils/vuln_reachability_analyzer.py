# utils/vuln_reachability_analyzer.py
# !/usr/bin/env python3
"""
Vulnerability Reachability Analyzer

Analyzes whether vulnerable packages are actually used in the codebase,
providing intelligent risk assessment beyond simple version checking.
"""

import ast
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from .get_metadata import get_package_mappings


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
    usage_type: str  # "import", "function_call", "attribute_access"


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str


class VulnReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.python_files = []
        self.package_usage_map = {}
        # Get dynamic package mappings from installed packages
        # This maps import names -> distribution names
        self.import_to_dist = get_package_mappings()

    def scan_python_files(self) -> List[Path]:
        """Find all Python files in the project."""
        python_files = []
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', '.venv', 'venv', 'node_modules'}]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)
        return python_files

    def extract_imports_and_usage(self, file_path: Path) -> Dict[str, List[UsageContext]]:
        """Extract import statements and usage patterns from a Python file."""
        usage_map = {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return usage_map

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"Warning: Syntax error in {file_path}: {e}")
            return usage_map

        # Track imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkg_name = alias.name.split('.')[0]  # Get root package
                    # Normalize to distribution name
                    dist_name = self.import_to_distribution_name(pkg_name)
                    if dist_name not in usage_map:
                        usage_map[dist_name] = []
                    usage_map[dist_name].append(UsageContext(
                        file_path=str(file_path),
                        line_number=node.lineno,
                        context_line=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                        usage_type="import"
                    ))

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    pkg_name = node.module.split('.')[0]  # Get root package
                    # Normalize to distribution name
                    dist_name = self.import_to_distribution_name(pkg_name)
                    if dist_name not in usage_map:
                        usage_map[dist_name] = []
                    usage_map[dist_name].append(UsageContext(
                        file_path=str(file_path),
                        line_number=node.lineno,
                        context_line=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                        usage_type="import"
                    ))

            # Track function calls and attribute access
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    # Check if this might be a package function call
                    dist_name = self.import_to_distribution_name(func_name)
                    if dist_name in usage_map:
                        usage_map[dist_name].append(UsageContext(
                            file_path=str(file_path),
                            line_number=node.lineno,
                            context_line=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                            usage_type="function_call"
                        ))
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        pkg_name = node.func.value.id
                        dist_name = self.import_to_distribution_name(pkg_name)
                        if dist_name in usage_map:
                            usage_map[dist_name].append(UsageContext(
                                file_path=str(file_path),
                                line_number=node.lineno,
                                context_line=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                usage_type="function_call"
                            ))

        return usage_map

    def import_to_distribution_name(self, import_name: str) -> str:
        """Convert import name to distribution name using dynamic mappings."""
        import_name_lower = import_name.lower()

        # First check dynamic mappings from installed packages
        if import_name_lower in self.import_to_dist:
            return self.import_to_dist[import_name_lower]

        # If not found, assume import name matches distribution name
        # (this is the case for most packages)
        return import_name_lower

    def analyze_vulnerability_reachability(self, vuln_data: List[Dict]) -> List[VulnAnalysis]:
        """Analyze if vulnerable packages are actually used in the codebase."""
        python_files = self.scan_python_files()

        # Build comprehensive usage map (now keyed by distribution names)
        all_usage = {}
        for file_path in python_files:
            file_usage = self.extract_imports_and_usage(file_path)
            for dist_name, contexts in file_usage.items():
                if dist_name not in all_usage:
                    all_usage[dist_name] = []
                all_usage[dist_name].extend(contexts)

        analyses = []

        for vuln in vuln_data:
            pkg_name = vuln['package_name'].lower()
            installed_version = vuln['installed_version']
            recommended_version = vuln.get('recommended_fixed_version', 'latest')

            # Check if package is actually used
            is_used = pkg_name in all_usage
            usage_contexts = all_usage.get(pkg_name, [])

            # Determine criticality
            if not is_used:
                criticality = CriticalityLevel.NOT_REACHABLE
                risk_reason = f"Package {pkg_name} is not imported or used in the codebase"
            else:
                # Analyze usage patterns to determine criticality
                has_direct_calls = any(ctx.usage_type == "function_call" for ctx in usage_contexts)
                num_files = len(set(ctx.file_path for ctx in usage_contexts))

                if has_direct_calls and num_files > 1:
                    criticality = CriticalityLevel.CRITICAL
                    risk_reason = f"Package {pkg_name} is actively used across {num_files} files with direct function calls"
                elif has_direct_calls:
                    criticality = CriticalityLevel.HIGH
                    risk_reason = f"Package {pkg_name} is actively used with direct function calls"
                elif num_files > 1:
                    criticality = CriticalityLevel.MEDIUM
                    risk_reason = f"Package {pkg_name} is imported across {num_files} files"
                else:
                    criticality = CriticalityLevel.LOW
                    risk_reason = f"Package {pkg_name} is imported but usage is limited"

            analyses.append(VulnAnalysis(
                package_name=pkg_name,
                installed_version=installed_version,
                recommended_version=recommended_version,
                is_used=is_used,
                usage_contexts=usage_contexts,
                criticality=criticality,
                risk_reason=risk_reason
            ))

        return analyses

    def generate_report(self, analyses: List[VulnAnalysis]) -> Dict:
        """Generate a comprehensive vulnerability reachability report."""
        report = {
            "summary": {
                "total_vulnerabilities": len(analyses),
                "critical_reachable": len([a for a in analyses if a.criticality == CriticalityLevel.CRITICAL]),
                "high_reachable": len([a for a in analyses if a.criticality == CriticalityLevel.HIGH]),
                "medium_reachable": len([a for a in analyses if a.criticality == CriticalityLevel.MEDIUM]),
                "low_reachable": len([a for a in analyses if a.criticality == CriticalityLevel.LOW]),
                "not_reachable": len([a for a in analyses if a.criticality == CriticalityLevel.NOT_REACHABLE])
            },
            "vulnerabilities": []
        }

        # Sort by criticality (most critical first)
        criticality_order = [CriticalityLevel.CRITICAL, CriticalityLevel.HIGH,
                             CriticalityLevel.MEDIUM, CriticalityLevel.LOW, CriticalityLevel.NOT_REACHABLE]
        sorted_analyses = sorted(analyses, key=lambda x: criticality_order.index(x.criticality))

        for analysis in sorted_analyses:
            vuln_report = {
                "package_name": analysis.package_name,
                "installed_version": analysis.installed_version,
                "recommended_version": analysis.recommended_version,
                "criticality": analysis.criticality.value,
                "is_used": analysis.is_used,
                "risk_reason": analysis.risk_reason,
                "usage_details": {
                    "total_usages": len(analysis.usage_contexts),
                    "files_affected": len(set(ctx.file_path for ctx in analysis.usage_contexts)),
                    "usage_contexts": [
                        {
                            "file": ctx.file_path,
                            "line": ctx.line_number,
                            "code": ctx.context_line,
                            "type": ctx.usage_type
                        }
                        for ctx in analysis.usage_contexts
                    ]
                }
            }
            report["vulnerabilities"].append(vuln_report)

        return report


def run_reachability_analysis(project_root: str, consolidated_path: str, output_path: str = None):
    """Run vulnerability reachability analysis"""
    if not output_path:
        output_path = "vulnerability_reachability_report.json"

    analyzer = VulnReachabilityAnalyzer(project_root)

    # Load vulnerability data
    try:
        with open(consolidated_path, "r") as f:
            vuln_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {consolidated_path} not found")
        return
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {consolidated_path}")
        return

    # Perform analysis
    analyses = analyzer.analyze_vulnerability_reachability(vuln_data)
    report = analyzer.generate_report(analyses)

    # Save detailed report
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print("=== Vulnerability Reachability Analysis ===")
    print(f"Total vulnerabilities analyzed: {report['summary']['total_vulnerabilities']}")
    print(f"Critical (actively used): {report['summary']['critical_reachable']}")
    print(f"High (used with calls): {report['summary']['high_reachable']}")
    print(f"Medium (imported): {report['summary']['medium_reachable']}")
    print(f"Low (limited usage): {report['summary']['low_reachable']}")
    print(f"Not reachable: {report['summary']['not_reachable']}")
    print()

    # Show critical vulnerabilities
    for vuln in report["vulnerabilities"]:
        if vuln["criticality"] in ["CRITICAL", "HIGH"]:
            print(f"🚨 {vuln['criticality']}: {vuln['package_name']} v{vuln['installed_version']}")
            print(f"   Reason: {vuln['risk_reason']}")
            print(f"   Upgrade to: {vuln['recommended_version']}")
            for ctx in vuln["usage_details"]["usage_contexts"][:3]:  # Show first 3 usages
                print(f"   📍 {ctx['file']}:{ctx['line']} - {ctx['code']}")
            if len(vuln["usage_details"]["usage_contexts"]) > 3:
                remaining = len(vuln["usage_details"]["usage_contexts"]) - 3
                print(f"   ... and {remaining} more usages")
            print()


if __name__ == "__main__":
    run_reachability_analysis(".", "consolidated.json")
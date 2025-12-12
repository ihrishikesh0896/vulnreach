#!/usr/bin/env python3
"""
Python Vulnerability Reachability Analyzer

Analyzes whether vulnerable Python packages are actually used in the codebase,
providing intelligent risk assessment beyond simple version checking.
"""

import ast
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
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
    usage_type: str  # "import", "from_import", "function_call", "attribute_access"


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str


class PythonReachabilityAnalyzer:
    """Analyzer for Python project vulnerability reachability"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)

    def find_python_files(self) -> List[Path]:
        """Find all Python source files in the project."""
        python_files = []

        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', '__pycache__', '.venv', 'venv', 'env', '.tox',
                'dist', 'build', '.eggs', '*.egg-info', '.pytest_cache',
                '.mypy_cache', '.idea', '.vscode'
            }]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)

        return python_files

    def extract_imports_and_usage(self, file_path: Path) -> Dict[str, List[UsageContext]]:
        """Extract import statements and usage patterns from a Python file using AST."""
        usage_map = {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return usage_map

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError as e:
            print(f"Warning: Syntax error in {file_path}: {e}")
            return usage_map

        # Track imported modules and their aliases
        imported_modules = {}  # module_name -> alias or None

        for node in ast.walk(tree):
            relative_path = str(file_path.relative_to(self.project_root))

            # Import statements: import requests
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name
                    module_alias = alias.asname if alias.asname else alias.name
                    imported_modules[module_alias] = module_name

                    # Get the line content
                    line_num = node.lineno
                    context_line = lines[line_num - 1] if line_num <= len(lines) else ""

                    root_package = module_name.split('.')[0]
                    if root_package not in usage_map:
                        usage_map[root_package] = []

                    usage_map[root_package].append(UsageContext(
                        file_path=relative_path,
                        line_number=line_num,
                        context_line=context_line.strip(),
                        usage_type="import"
                    ))

            # From imports: from flask import Flask
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_name = node.module
                    root_package = module_name.split('.')[0]

                    # Track imported names
                    for alias in node.names:
                        imported_name = alias.name
                        imported_alias = alias.asname if alias.asname else alias.name
                        imported_modules[imported_alias] = module_name

                    # Get the line content
                    line_num = node.lineno
                    context_line = lines[line_num - 1] if line_num <= len(lines) else ""

                    if root_package not in usage_map:
                        usage_map[root_package] = []

                    usage_map[root_package].append(UsageContext(
                        file_path=relative_path,
                        line_number=line_num,
                        context_line=context_line.strip(),
                        usage_type="from_import"
                    ))

            # Function calls: requests.get(), Flask()
            elif isinstance(node, ast.Call):
                line_num = node.lineno
                context_line = lines[line_num - 1] if line_num <= len(lines) else ""

                # Direct function call: Flask()
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in imported_modules:
                        original_module = imported_modules[func_name]
                        root_package = original_module.split('.')[0]

                        if root_package not in usage_map:
                            usage_map[root_package] = []

                        usage_map[root_package].append(UsageContext(
                            file_path=relative_path,
                            line_number=line_num,
                            context_line=context_line.strip(),
                            usage_type="function_call"
                        ))

                # Attribute call: requests.get()
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id
                        if module_name in imported_modules:
                            original_module = imported_modules[module_name]
                            root_package = original_module.split('.')[0]

                            if root_package not in usage_map:
                                usage_map[root_package] = []

                            usage_map[root_package].append(UsageContext(
                                file_path=relative_path,
                                line_number=line_num,
                                context_line=context_line.strip(),
                                usage_type="function_call"
                            ))

            # Attribute access: app.config
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    var_name = node.value.id
                    if var_name in imported_modules:
                        line_num = node.lineno
                        context_line = lines[line_num - 1] if line_num <= len(lines) else ""

                        original_module = imported_modules[var_name]
                        root_package = original_module.split('.')[0]

                        if root_package not in usage_map:
                            usage_map[root_package] = []

                        usage_map[root_package].append(UsageContext(
                            file_path=relative_path,
                            line_number=line_num,
                            context_line=context_line.strip(),
                            usage_type="attribute_access"
                        ))

        return usage_map

    def normalize_package_name(self, package_name: str) -> str:
        """Normalize Python package name (lowercase, replace underscores with hyphens)."""
        return package_name.lower().replace('_', '-')

    def get_declared_dependencies(self) -> Dict[str, str]:
        """Parse requirements.txt, setup.py, or pyproject.toml for declared dependencies."""
        dependencies = {}

        # Check requirements.txt
        req_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements/base.txt',
            'requirements/production.txt'
        ]

        for req_file in req_files:
            req_path = self.project_root / req_file
            if req_path.exists():
                try:
                    with open(req_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Parse package==version or package>=version
                                match = re.match(r'^([a-zA-Z0-9_-]+)([>=<~!]+)(.+)$', line)
                                if match:
                                    pkg_name = self.normalize_package_name(match.group(1))
                                    version = match.group(3).strip()
                                    dependencies[pkg_name] = version
                except Exception as e:
                    print(f"Warning: Could not parse {req_path}: {e}")

        # Check pyproject.toml
        pyproject_path = self.project_root / 'pyproject.toml'
        if pyproject_path.exists():
            try:
                with open(pyproject_path, 'r') as f:
                    content = f.read()
                    # Simple regex-based parsing (not full TOML parser)
                    for match in re.finditer(r'([a-zA-Z0-9_-]+)\s*=\s*["\']([^"\']+)["\']', content):
                        pkg_name = self.normalize_package_name(match.group(1))
                        version = match.group(2)
                        dependencies[pkg_name] = version
            except Exception as e:
                print(f"Warning: Could not parse pyproject.toml: {e}")

        return dependencies

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        """Find all usages of a specific package in the codebase."""
        all_usages = []
        normalized_package = self.normalize_package_name(package_name)

        python_files = self.find_python_files()
        print(f"  Scanning {len(python_files)} Python files for '{package_name}' usage...")

        for file_path in python_files:
            usage_map = self.extract_imports_and_usage(file_path)

            # Check if this package is used
            for pkg, contexts in usage_map.items():
                if self.normalize_package_name(pkg) == normalized_package:
                    all_usages.extend(contexts)

        return all_usages

    def assess_risk(self, package_name: str, usage_contexts: List[UsageContext],
                   is_declared: bool) -> tuple[CriticalityLevel, str]:
        """Assess the risk level based on usage patterns."""

        if not usage_contexts:
            if is_declared:
                return (CriticalityLevel.NOT_REACHABLE,
                       "Package declared but not actively used in scanned code")
            else:
                return (CriticalityLevel.NOT_REACHABLE,
                       "Package not found in codebase")

        # Count different types of usage
        imports_only = sum(1 for ctx in usage_contexts
                          if ctx.usage_type in ('import', 'from_import'))
        function_calls = sum(1 for ctx in usage_contexts
                           if ctx.usage_type == 'function_call')
        attribute_access = sum(1 for ctx in usage_contexts
                             if ctx.usage_type == 'attribute_access')

        # Count unique files
        files_with_usage = len(set(ctx.file_path for ctx in usage_contexts))

        # Risk assessment logic
        if function_calls >= 5 and files_with_usage >= 3:
            return (CriticalityLevel.CRITICAL,
                   f"Package is actively used with {function_calls} function calls across "
                   f"{files_with_usage} files - high impact if vulnerable")

        elif function_calls > 0:
            return (CriticalityLevel.HIGH,
                   f"Package has {function_calls} direct function calls across "
                   f"{files_with_usage} file(s) - actively used")

        elif files_with_usage >= 3:
            return (CriticalityLevel.MEDIUM,
                   f"Package imported across {files_with_usage} files but limited "
                   f"direct usage detected")

        elif imports_only > 0:
            return (CriticalityLevel.LOW,
                   f"Package imported in {files_with_usage} file(s) but no direct "
                   f"function calls detected")

        else:
            return (CriticalityLevel.NOT_REACHABLE,
                   "Package present but usage patterns unclear")

    def analyze_vulnerability_reachability(self, vuln_data: List[Dict]) -> List[VulnAnalysis]:
        """Analyze reachability for all vulnerabilities."""
        analyses = []
        declared_deps = self.get_declared_dependencies()

        print(f"\n🔍 Analyzing Python vulnerability reachability...")
        print(f"   Found {len(declared_deps)} declared dependencies")

        for vuln in vuln_data:
            package_name = vuln.get('package_name', '')
            installed_version = vuln.get('installed_version', vuln.get('package_version', ''))
            recommended_version = vuln.get('recommended_fixed_version', vuln.get('fixed_version', 'latest'))

            if not package_name:
                continue

            print(f"\n   Analyzing: {package_name} @ {installed_version}")

            # Find usage
            usage_contexts = self.find_package_usage(package_name)
            is_declared = self.normalize_package_name(package_name) in declared_deps

            # Assess risk
            criticality, risk_reason = self.assess_risk(package_name, usage_contexts, is_declared)

            analysis = VulnAnalysis(
                package_name=package_name,
                installed_version=installed_version,
                recommended_version=recommended_version,
                is_used=len(usage_contexts) > 0,
                usage_contexts=usage_contexts[:10],  # Limit to first 10 for brevity
                criticality=criticality,
                risk_reason=risk_reason
            )

            analyses.append(analysis)
            print(f"      Risk: {criticality.value} - {len(usage_contexts)} usage(s) found")

        return analyses

    def generate_report(self, analyses: List[VulnAnalysis]) -> Dict:
        """Generate a JSON report of the analysis."""
        # Calculate summary statistics
        total = len(analyses)
        critical = sum(1 for a in analyses if a.criticality == CriticalityLevel.CRITICAL)
        high = sum(1 for a in analyses if a.criticality == CriticalityLevel.HIGH)
        medium = sum(1 for a in analyses if a.criticality == CriticalityLevel.MEDIUM)
        low = sum(1 for a in analyses if a.criticality == CriticalityLevel.LOW)
        not_reachable = sum(1 for a in analyses if a.criticality == CriticalityLevel.NOT_REACHABLE)

        report = {
            "summary": {
                "total_vulnerabilities": total,
                "critical_reachable": critical,
                "high_reachable": high,
                "medium_reachable": medium,
                "low_reachable": low,
                "not_reachable": not_reachable,
                "analysis_timestamp": __import__('datetime').datetime.now().isoformat()
            },
            "vulnerabilities": []
        }

        for analysis in analyses:
            vuln_dict = {
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
            report["vulnerabilities"].append(vuln_dict)

        return report


def run_python_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    """
    Main entry point for Python reachability analysis.

    Args:
        project_root: Path to the project root directory
        consolidated_path: Path to consolidated vulnerability JSON
        output_path: Path to save the analysis report
    """
    print(f"\n{'='*70}")
    print("🐍 PYTHON VULNERABILITY REACHABILITY ANALYSIS")
    print(f"{'='*70}")

    # Load vulnerability data
    try:
        with open(consolidated_path, 'r') as f:
            vuln_data = json.load(f)
            if not isinstance(vuln_data, list):
                vuln_data = [vuln_data]
    except Exception as e:
        print(f"Error: Could not load vulnerability data from {consolidated_path}: {e}")
        return

    # Run analysis
    analyzer = PythonReachabilityAnalyzer(project_root)
    analyses = analyzer.analyze_vulnerability_reachability(vuln_data)

    # Generate and save report
    report = analyzer.generate_report(analyses)

    try:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n✅ Analysis complete! Report saved to: {output_path}")
        print(f"\n📊 Summary:")
        print(f"   🔴 Critical: {report['summary']['critical_reachable']}")
        print(f"   🟠 High: {report['summary']['high_reachable']}")
        print(f"   🟡 Medium: {report['summary']['medium_reachable']}")
        print(f"   🟢 Low: {report['summary']['low_reachable']}")
        print(f"   ⚪ Not Reachable: {report['summary']['not_reachable']}")
        print(f"\n{'='*70}\n")
    except Exception as e:
        print(f"Error: Could not save report to {output_path}: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python python_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        print("\nExample:")
        print("  python python_reachability_analyzer.py ./my-python-app security_findings/consolidated.json python_report.json")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "python_vulnerability_reachability_report.json"

    run_python_reachability_analysis(project_root, consolidated_path, output_path)


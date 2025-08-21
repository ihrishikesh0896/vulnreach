#!/usr/bin/env python3
"""
Java Vulnerability Reachability Analyzer

Analyzes whether vulnerable Java packages are actually used in the codebase,
providing intelligent risk assessment beyond simple version checking.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass
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
    usage_type: str  # "import", "method_call", "instantiation"


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str


class JavaReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        # Common Java package patterns
        self.import_patterns = [
            re.compile(r'^\s*import\s+(?:static\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)\s*;'),
            re.compile(r'^\s*import\s+(?:static\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)\.\*\s*;')
        ]
        # Method call patterns
        self.method_call_patterns = [
            re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\('),
            re.compile(r'new\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*\(')
        ]

    def scan_java_files(self) -> List[Path]:
        """Find all Java files in the project."""
        java_files = []
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'target', 'build', '.gradle', 'node_modules', 
                '.idea', '.vscode', 'bin', 'out'
            }]

            for file in files:
                if file.endswith('.java'):
                    java_files.append(Path(root) / file)
        return java_files

    def extract_imports_and_usage(self, file_path: Path) -> Dict[str, List[UsageContext]]:
        """Extract import statements and usage patterns from a Java file."""
        usage_map = {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return usage_map

        imported_classes = {}  # Maps simple class name to full package
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Extract imports
            for pattern in self.import_patterns:
                match = pattern.match(line_stripped)
                if match:
                    full_import = match.group(1)
                    # Extract package name (everything before the last dot)
                    if '.' in full_import:
                        package_parts = full_import.split('.')
                        # Get root package (first 2-3 parts typically)
                        root_package = self._extract_root_package(full_import)
                        class_name = package_parts[-1]
                        
                        imported_classes[class_name] = full_import
                        
                        if root_package not in usage_map:
                            usage_map[root_package] = []
                        
                        usage_map[root_package].append(UsageContext(
                            file_path=str(file_path),
                            line_number=line_num,
                            context_line=line_stripped,
                            usage_type="import"
                        ))

            # Extract method calls and instantiations
            for pattern in self.method_call_patterns:
                matches = pattern.finditer(line_stripped)
                for match in matches:
                    class_or_var = match.group(1)
                    
                    # Check if this is a known imported class
                    if class_or_var in imported_classes:
                        full_class = imported_classes[class_or_var]
                        root_package = self._extract_root_package(full_class)
                        
                        if root_package in usage_map:
                            usage_type = "instantiation" if "new" in match.group(0) else "method_call"
                            usage_map[root_package].append(UsageContext(
                                file_path=str(file_path),
                                line_number=line_num,
                                context_line=line_stripped,
                                usage_type=usage_type
                            ))

        return usage_map

    def _extract_root_package(self, full_package: str) -> str:
        """Extract root package from full package name."""
        parts = full_package.split('.')
        
        # Common Java package patterns
        if len(parts) >= 2:
            # Handle common patterns like com.company, org.apache, etc.
            if parts[0] in ['com', 'org', 'net', 'io', 'gov']:
                return '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]
            # Handle patterns like apache.commons, google.guava
            elif len(parts) >= 2:
                return '.'.join(parts[:2])
        
        return parts[0] if parts else full_package

    def package_to_artifact_name(self, package_name: str) -> str:
        """Convert Java package name to likely Maven artifact name."""
        # Common mappings
        mappings = {
            'org.apache': 'apache',
            'com.google': 'google',
            'com.fasterxml': 'fasterxml',
            'org.springframework': 'springframework',
            'org.junit': 'junit',
            'org.slf4j': 'slf4j',
            'ch.qos': 'logback',
            'org.hibernate': 'hibernate',
            'com.mysql': 'mysql',
            'org.postgresql': 'postgresql'
        }
        
        # Check direct mappings first
        for pkg_prefix, artifact in mappings.items():
            if package_name.startswith(pkg_prefix):
                return artifact
        
        # Extract likely artifact name from package
        parts = package_name.split('.')
        if len(parts) >= 2:
            return parts[1]  # Usually com.company -> company
        
        return package_name.lower()

    def analyze_vulnerability_reachability(self, vuln_data: List[Dict]) -> List[VulnAnalysis]:
        """Analyze if vulnerable Java packages are actually used in the codebase."""
        java_files = self.scan_java_files()

        # Build comprehensive usage map
        all_usage = {}
        for file_path in java_files:
            file_usage = self.extract_imports_and_usage(file_path)
            for package_name, contexts in file_usage.items():
                if package_name not in all_usage:
                    all_usage[package_name] = []
                all_usage[package_name].extend(contexts)

        analyses = []

        for vuln in vuln_data:
            pkg_name = vuln['package_name'].lower()
            installed_version = vuln['installed_version']
            recommended_version = vuln.get('recommended_fixed_version', 'latest')

            # Check if package is actually used
            # Try multiple matching strategies
            is_used = False
            usage_contexts = []
            
            # Direct match
            if pkg_name in all_usage:
                is_used = True
                usage_contexts = all_usage[pkg_name]
            else:
                # Try artifact name matching
                for package_name, contexts in all_usage.items():
                    artifact_name = self.package_to_artifact_name(package_name)
                    if artifact_name == pkg_name or pkg_name in package_name.lower():
                        is_used = True
                        usage_contexts.extend(contexts)

            # Determine criticality
            if not is_used:
                criticality = CriticalityLevel.NOT_REACHABLE
                risk_reason = f"Package {pkg_name} is not imported or used in the codebase"
            else:
                # Analyze usage patterns
                has_method_calls = any(ctx.usage_type in ["method_call", "instantiation"] for ctx in usage_contexts)
                num_files = len(set(ctx.file_path for ctx in usage_contexts))

                if has_method_calls and num_files > 1:
                    criticality = CriticalityLevel.CRITICAL
                    risk_reason = f"Package {pkg_name} is actively used across {num_files} files with method calls/instantiations"
                elif has_method_calls:
                    criticality = CriticalityLevel.HIGH
                    risk_reason = f"Package {pkg_name} is actively used with method calls/instantiations"
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

        # Sort by criticality
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


def run_java_reachability_analysis(project_root: str, consolidated_path: str, output_path: str = None):
    """Run Java vulnerability reachability analysis"""
    if not output_path:
        output_path = "java_vulnerability_reachability_report.json"

    analyzer = JavaReachabilityAnalyzer(project_root)

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
    print("=== Java Vulnerability Reachability Analysis ===")
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
    run_java_reachability_analysis(".", "consolidated.json")
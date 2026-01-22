#!/usr/bin/env python3
"""
JavaScript/TypeScript Vulnerability Reachability Analyzer

Analyzes whether vulnerable JavaScript/TypeScript packages are actually used in the codebase,
providing intelligent risk assessment beyond simple version checking.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass, asdict
from enum import Enum


try:
    from .javascript_call_graph import JavaScriptCallGraphBuilder
    HAS_CALL_GRAPH = True
except ImportError:
    HAS_CALL_GRAPH = False


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
    usage_type: str  # "import", "require", "dynamic_import"
    enclosing_function: str = None  # Function where usage occurs


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str
    call_chain_graph: str = None  # Mermaid graph definition


class JavaScriptReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        # Common JavaScript/TypeScript import patterns
        self.import_patterns = [
            # ES6 imports
            re.compile(r'^\s*import\s+.*\s+from\s+["\']([^"\']+)["\']'),
            re.compile(r'^\s*import\s+["\']([^"\']+)["\']'),
            # CommonJS require
            re.compile(r'require\(["\']([^"\']+)["\']\)'),
            # Dynamic imports
            re.compile(r'import\(["\']([^"\']+)["\']\)'),
        ]
        
        # Initialize Call Graph Builder
        self.call_graph_builder = None
        if HAS_CALL_GRAPH:
            try:
                print(f"🕸️  Building static call graph for {self.project_root}...")
                self.call_graph_builder = JavaScriptCallGraphBuilder(str(self.project_root))
                self.call_graph_builder.build_graph()
                print(f"   Graph built: {len(self.call_graph_builder.graph)} functions, {len(self.call_graph_builder.entry_points)} entry points")
            except Exception as e:
                print(f"Warning: Could not build call graph: {e}")

    def find_js_files(self) -> List[Path]:
        """Find all JavaScript/TypeScript source files in the project."""
        js_files = []
        extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}

        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', 'out'
            }]
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    js_files.append(Path(root) / file)
        return js_files

    def extract_imports(self, file_path: Path) -> Set[str]:
        """Extract import statements from a JavaScript/TypeScript file."""
        imports = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for pattern in self.import_patterns:
                    for match in pattern.finditer(content):
                        imports.add(match.group(1))
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")
        return imports

    def normalize_package_name(self, import_path: str) -> str:
        """Extract package name from import path."""
        # Handle scoped packages (@org/package)
        if import_path.startswith('@'):
            parts = import_path.split('/')
            if len(parts) >= 2:
                return '/'.join(parts[:2])
        # Handle regular packages
        else:
            parts = import_path.split('/')
            if parts[0] and not parts[0].startswith('.'):
                return parts[0]
        return import_path

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        """Find all usages of a package in the codebase."""
        usage_contexts = []
        js_files = self.find_js_files()

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.splitlines()
                    
                    # Track function scope manually (simple heuristic)
                    current_function = None
                    brace_balance = 0
                    scope_stack = [] # (name, push_level)
                    
                    # Function definition regex (reused from Call Graph Builder for consistency)
                    func_regex = re.compile(r'(?:function\s+([a-zA-Z0-9_$]+)\s*\(|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:function\s*\(|\(?.*?\)?\s*=>))')

                    for line_num, line in enumerate(lines, 1):
                        line_stripped = line.strip()
                        
                        # Brace tracking
                        # Note: This is brittle but sufficient for "enclosing function" heuristic
                        brace_balance += line.count('{')
                        brace_balance -= line.count('}')
                        
                        # Check function entry
                        match = func_regex.search(line)
                        if match:
                            func_name = match.group(1) or match.group(2)
                            if func_name:
                                scope_stack.append({'name': func_name, 'level': brace_balance})
                                current_function = func_name
                                
                        # Check function exit
                        if scope_stack:
                            # If brace balance drops below definition level
                            if brace_balance < scope_stack[-1]['level']:
                                scope_stack.pop()
                                current_function = scope_stack[-1]['name'] if scope_stack else None

                        # Check imports/usage
                        for pattern in self.import_patterns:
                            match = pattern.search(line)
                            if match:
                                imported_package = self.normalize_package_name(match.group(1))
                                if imported_package == package_name or imported_package.startswith(f"{package_name}/"):
                                    usage_type = "import"
                                    if "require" in line:
                                        usage_type = "require"
                                    elif "import(" in line:
                                        usage_type = "dynamic_import"

                                    usage_contexts.append(UsageContext(
                                        file_path=str(js_file.relative_to(self.project_root)),
                                        line_number=line_num,
                                        context_line=line.strip(),
                                        usage_type=usage_type,
                                        enclosing_function=current_function
                                    ))
                                    break
            except Exception as e:
                print(f"Warning: Could not read {js_file}: {e}")

        return usage_contexts

    def parse_package_json(self) -> Dict[str, str]:
        """Parse dependencies from package.json."""
        dependencies = {}
        package_file = self.project_root / "package.json"

        if not package_file.exists():
            return dependencies

        try:
            with open(package_file, 'r', encoding='utf-8') as f:
                package_data = json.load(f)

                # Get all dependency types
                for section in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                    if section in package_data:
                        for package, version in package_data[section].items():
                            dependencies[package] = version
        except Exception as e:
            print(f"Warning: Could not parse package.json: {e}")

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

        # Generate Call Graph Trace
        call_graph_mermaid = None
        if self.call_graph_builder and is_used:
            target_funcs = {ctx.enclosing_function for ctx in usage_contexts if ctx.enclosing_function}
            if target_funcs:
                traces = self.call_graph_builder.find_trace_to_usage(list(target_funcs))
                if traces:
                    call_graph_mermaid = self.call_graph_builder.get_mermaid_graph(traces)
                    path_count = len(traces)
                    risk_reason += f" [VERIFIED: {path_count} paths from routes]"
                    
                    # Risk uplift
                    if criticality == CriticalityLevel.HIGH or criticality == CriticalityLevel.MEDIUM:
                        criticality = CriticalityLevel.CRITICAL

        return VulnAnalysis(
            package_name=package_name,
            installed_version=installed_version,
            recommended_version=recommended_version,
            is_used=is_used,
            usage_contexts=usage_contexts,
            criticality=criticality,
            risk_reason=risk_reason,
            call_chain_graph=call_graph_mermaid
        )


def run_javascript_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    """Main entry point for JavaScript/TypeScript reachability analysis."""
    print(f"\n{'='*60}")
    print("JavaScript/TypeScript Vulnerability Reachability Analysis")
    print(f"{'='*60}\n")

    # Load consolidated vulnerabilities
    try:
        with open(consolidated_path, 'r') as f:
            consolidated_data = json.load(f)
    except Exception as e:
        print(f"Error loading consolidated data: {e}")
        return

    analyzer = JavaScriptReachabilityAnalyzer(project_root)

    # Get installed dependencies
    installed_deps = analyzer.parse_package_json()
    print(f"📦 Found {len(installed_deps)} JavaScript packages")

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
        "language": "javascript",
        "total_vulnerabilities": len(vulnerabilities),
        "reachable_vulnerabilities": sum(1 for a in analyses if a.is_used),
        "not_reachable_vulnerabilities": sum(1 for a in analyses if not a.is_used),
        "analyses": [
            {
                **{k: v for k, v in asdict(a).items() if k not in {'usage_contexts', 'call_chain_graph'}},
                'criticality': a.criticality.value,
                'call_chain_graph': a.call_chain_graph,
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
        print("Usage: python javascript_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "javascript_vulnerability_reachability_report.json"

    run_javascript_reachability_analysis(project_root, consolidated_path, output_path)


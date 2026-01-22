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
from dataclasses import dataclass, asdict, field
from enum import Enum

# Import dependency tree analyzer for transitive dependency detection
try:
    from .dependency_tree_analyzer import PythonDependencyTreeAnalyzer
    HAS_DEP_TREE_ANALYZER = True
except ImportError:
    HAS_DEP_TREE_ANALYZER = False
    print("Warning: dependency_tree_analyzer not available, transitive dependency detection disabled")

try:
    from .python_call_graph import PythonCallGraphBuilder
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
    usage_type: str  # "import", "from_import", "function_call", "attribute_access"
    enclosing_function: Optional[str] = None  # Function name where this usage occurs


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str
    is_direct_dependency: bool = True  # True if directly declared, False if transitive
    dependency_depth: int = 0  # 0 for direct, 1+ for transitive
    required_by: List[str] = None  # List of parent packages (for transitive deps)
    call_chain_graph: Optional[str] = None  # Mermaid graph definition of reachable paths

    def __post_init__(self):
        if self.required_by is None:
            self.required_by = []


class PythonReachabilityAnalyzer:
    """Analyzer for Python project vulnerability reachability"""
    
    # Maximum number of files to scan (DoS prevention)
    MAX_FILES_DEFAULT = 10000

    def __init__(self, project_root: str, max_files: int = MAX_FILES_DEFAULT):
        # Validate and resolve project root path
        try:
            root = Path(project_root).resolve(strict=True)
        except (OSError, ValueError) as e:
            raise ValueError(f"Invalid project_root path: {project_root}. Error: {e}")
        
        # Ensure project_root is a directory
        if not root.is_dir():
            raise ValueError(f"project_root must be a directory: {project_root}")
        
        # Security: Validate project_root is not a system directory
        # Disallow scanning system-critical paths
        forbidden_paths = ['/', '/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/lib64']
        if str(root) in forbidden_paths or str(root).startswith('/etc/'):
            raise ValueError(f"Scanning system directories is not allowed: {project_root}")
        
        self.project_root = root
        self.max_files = max_files
        self.files_scanned = 0

        # Initialize dependency tree analyzer for transitive dependency detection
        self.dep_tree_analyzer = None
        if HAS_DEP_TREE_ANALYZER:
            try:
                self.dep_tree_analyzer = PythonDependencyTreeAnalyzer(str(self.project_root))
            except Exception as e:
                print(f"Warning: Could not initialize dependency tree analyzer: {e}")
        
        # Initialize Call Graph Builder
        self.call_graph_builder = None
        if HAS_CALL_GRAPH:
            try:
                print(f"🕸️  Building static call graph for {self.project_root}...")
                self.call_graph_builder = PythonCallGraphBuilder(str(self.project_root))
                self.call_graph_builder.build_graph()
                print(f"   Graph built: {len(self.call_graph_builder.graph)} functions, {len(self.call_graph_builder.entry_points)} entry points")
            except Exception as e:
                print(f"Warning: Could not build call graph: {e}")

    def find_python_files(self, max_files: Optional[int] = None) -> List[Path]:
        """Find all Python source files in the project.
        
        Args:
            max_files: Maximum number of files to return (default: self.max_files)
                       Used to prevent resource exhaustion attacks.
        
        Returns:
            List of Path objects to Python files.
            
        Raises:
            ValueError: If too many files are found (exceeds max_files limit).
        
        Security:
            - Symlinks are NOT followed (prevents path traversal)
            - File count is limited (prevents DoS)
            - Resolved paths are validated to be within project_root
        """
        if max_files is None:
            max_files = self.max_files
            
        python_files = []
        file_count = 0

        # Security: followlinks=False prevents path traversal via symlinks
        for root, dirs, files in os.walk(self.project_root, followlinks=False):
            # Security: Validate that the current directory is still under project_root
            # This prevents escaping via directory traversal tricks
            try:
                resolved_root = Path(root).resolve()
                if not resolved_root.is_relative_to(self.project_root):
                    # Skip directories that resolve outside project_root
                    dirs[:] = []  # Don't descend into subdirectories
                    continue
            except (OSError, ValueError):
                # Skip paths that can't be resolved
                dirs[:] = []
                continue
            
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', '__pycache__', '.venv', 'venv', 'env', '.env', '.tox',
                'dist', 'build', '.eggs', '*.egg-info', '.pytest_cache',
                '.mypy_cache', '.idea', '.vscode'
            }]

            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    
                    # Security: Skip symlinked files
                    if file_path.is_symlink():
                        continue
                    
                    python_files.append(file_path)
                    file_count += 1
                    
                    # Security: Enforce file count limit to prevent resource exhaustion
                    if file_count > max_files:
                        raise ValueError(
                            f"Too many Python files found (>{max_files}). "
                            f"This limit exists to prevent resource exhaustion. "
                            f"Use max_files parameter to increase if needed."
                        )

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

        class UsageVisitor(ast.NodeVisitor):
            def __init__(self, outer):
                self.outer = outer
                self.scope_stack = []  # Stack of function names

            def visit_FunctionDef(self, node):
                self.scope_stack.append(node.name)
                self.generic_visit(node)
                self.scope_stack.pop()

            def visit_AsyncFunctionDef(self, node):
                self.scope_stack.append(node.name)
                self.generic_visit(node)
                self.scope_stack.pop()

            def _get_current_scope(self):
                return self.scope_stack[-1] if self.scope_stack else None

            def _add_usage(self, root_pkg, line_num, usage_type):
                if root_pkg not in usage_map:
                    usage_map[root_pkg] = []
                
                context_line = lines[line_num - 1] if line_num <= len(lines) else ""
                
                usage_map[root_pkg].append(UsageContext(
                    file_path=str(file_path.relative_to(self.outer.project_root)),
                    line_number=line_num,
                    context_line=context_line.strip(),
                    usage_type=usage_type,
                    enclosing_function=self._get_current_scope()
                ))

            def visit_Import(self, node):
                for alias in node.names:
                    module_name = alias.name
                    module_alias = alias.asname if alias.asname else alias.name
                    imported_modules[module_alias] = module_name
                    
                    root_package = module_name.split('.')[0]
                    self._add_usage(root_package, node.lineno, "import")

            def visit_ImportFrom(self, node):
                if node.module:
                    module_name = node.module
                    root_package = module_name.split('.')[0]
                    
                    for alias in node.names:
                        imported_name = alias.name
                        imported_alias = alias.asname if alias.asname else alias.name
                        imported_modules[imported_alias] = module_name
                    
                    self._add_usage(root_package, node.lineno, "from_import")

            def visit_Call(self, node):
                # Direct function call: Flask()
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in imported_modules:
                        original_module = imported_modules[func_name]
                        root_package = original_module.split('.')[0]
                        self._add_usage(root_package, node.lineno, "function_call")

                # Attribute call: requests.get()
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id
                        if module_name in imported_modules:
                            original_module = imported_modules[module_name]
                            root_package = original_module.split('.')[0]
                            self._add_usage(root_package, node.lineno, "function_call")
                
                self.generic_visit(node)

            def visit_Attribute(self, node):
                if isinstance(node.value, ast.Name):
                    var_name = node.value.id
                    if var_name in imported_modules:
                        original_module = imported_modules[var_name]
                        root_package = original_module.split('.')[0]
                        self._add_usage(root_package, node.lineno, "attribute_access")
                self.generic_visit(node)

        UsageVisitor(self).visit(tree)

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

        # Get dependency tree information for transitive detection
        all_dep_info = {}
        if self.dep_tree_analyzer:
            try:
                all_dep_info = self.dep_tree_analyzer.get_all_dependencies()
                transitive_count = sum(1 for dep in all_dep_info.values() if not dep.is_direct)
                print(f"\n🔗 Dependency Tree Analysis:")
                print(f"   Direct dependencies: {len(declared_deps)}")
                print(f"   Transitive dependencies: {transitive_count}")
            except Exception as e:
                print(f"   Warning: Could not analyze dependency tree: {e}")
        else:
            print(f"\n📦 Basic Dependency Analysis:")
            print(f"   Found {len(declared_deps)} declared dependencies")
            print(f"   (Install 'pipdeptree' for transitive dependency detection)")

        print(f"\n🔍 Analyzing Python vulnerability reachability...")

        for vuln in vuln_data:
            package_name = vuln.get('package_name', '')
            installed_version = vuln.get('installed_version', vuln.get('package_version', ''))
            recommended_version = vuln.get('recommended_fixed_version', vuln.get('fixed_version', 'latest'))

            if not package_name:
                continue

            normalized_name = self.normalize_package_name(package_name)
            print(f"\n   Analyzing: {package_name} @ {installed_version}")

            # Find usage
            usage_contexts = self.find_package_usage(package_name)
            is_declared = normalized_name in declared_deps

            # Get dependency information (direct vs transitive)
            is_direct = True
            depth = 0
            required_by = []

            if self.dep_tree_analyzer and normalized_name in all_dep_info:
                dep_info = all_dep_info[normalized_name]
                is_direct = dep_info.is_direct
                depth = dep_info.depth
                required_by = dep_info.parent_dependencies

                if not is_direct:
                    parents_str = ', '.join(required_by[:3])
                    if len(required_by) > 3:
                        parents_str += f", +{len(required_by)-3} more"
                    print(f"      ⚠️  TRANSITIVE dependency (required by: {parents_str})")
                else:
                    print(f"      ✓ Direct dependency")
            elif is_declared:
                print(f"      ✓ Direct dependency (declared)")
            else:
                print(f"      ? Dependency type unknown")

            # Assess risk
            criticality, risk_reason = self.assess_risk(package_name, usage_contexts, is_declared)

            # Adjust risk message for transitive dependencies
            if not is_direct and depth > 0:
                risk_reason += f" [TRANSITIVE: depth={depth}, required by {len(required_by)} package(s)]"

            # Generate Call Graph if available
            call_graph_mermaid = None
            if self.call_graph_builder and usage_contexts:
                # Get unique enclosing functions from usage
                target_funcs = {ctx.enclosing_function for ctx in usage_contexts if ctx.enclosing_function}
                
                if target_funcs:
                    try:
                        traces = self.call_graph_builder.find_trace_to_usage(list(target_funcs))
                        if traces:
                            call_graph_mermaid = self.call_graph_builder.get_mermaid_graph(traces)
                            path_count = len(traces)
                            print(f"      🕸️  Call Graph: Found {path_count} execution paths from entry points!")
                            
                            # If we found a trace from an entry point (e.g. route) to the usage, this is high confidence
                            risk_reason += f" [VERIFIED: {path_count} call paths from entry points]"
                            
                            # Upgrade validation confidence
                            if criticality == CriticalityLevel.HIGH or criticality == CriticalityLevel.MEDIUM:
                                criticality = CriticalityLevel.CRITICAL
                    except Exception as e:
                        print(f"      Warning: Error tracing call graph: {e}")

            analysis = VulnAnalysis(
                package_name=package_name,
                installed_version=installed_version,
                recommended_version=recommended_version,
                is_used=len(usage_contexts) > 0,
                usage_contexts=usage_contexts[:10],  # Limit to first 10 for brevity
                criticality=criticality,
                risk_reason=risk_reason,
                is_direct_dependency=is_direct,
                dependency_depth=depth,
                required_by=required_by,
                call_chain_graph=call_graph_mermaid
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

        # Transitive dependency statistics
        direct_deps = sum(1 for a in analyses if a.is_direct_dependency)
        transitive_deps = sum(1 for a in analyses if not a.is_direct_dependency)

        report = {
            "summary": {
                "total_vulnerabilities": total,
                "critical_reachable": critical,
                "high_reachable": high,
                "medium_reachable": medium,
                "low_reachable": low,
                "not_reachable": not_reachable,
                "direct_dependencies": direct_deps,
                "transitive_dependencies": transitive_deps,
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
                "dependency_info": {
                    "is_direct": analysis.is_direct_dependency,
                    "depth": analysis.dependency_depth,
                    "required_by": analysis.required_by if analysis.required_by else []
                },
                "call_chain_graph": analysis.call_chain_graph,
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
        print(f"   Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
        print(f"   🔴 Critical: {report['summary']['critical_reachable']}")
        print(f"   🟠 High: {report['summary']['high_reachable']}")
        print(f"   🟡 Medium: {report['summary']['medium_reachable']}")
        print(f"   🟢 Low: {report['summary']['low_reachable']}")
        print(f"   ⚪ Not Reachable: {report['summary']['not_reachable']}")

        # Show transitive dependency statistics
        if 'direct_dependencies' in report['summary']:
            print(f"\n🔗 Dependency Type:")
            print(f"   📦 Direct: {report['summary']['direct_dependencies']}")
            print(f"   ⚠️  Transitive: {report['summary']['transitive_dependencies']}")

            # Show which transitive deps have vulnerabilities
            transitive_vulns = [v for v in report['vulnerabilities']
                              if not v.get('dependency_info', {}).get('is_direct', True)]
            if transitive_vulns:
                print(f"\n⚠️  Transitive Dependencies with Vulnerabilities:")
                for vuln in transitive_vulns[:5]:  # Show first 5
                    pkg = vuln['package_name']
                    required_by = vuln.get('dependency_info', {}).get('required_by', [])
                    if required_by:
                        parents = ', '.join(required_by[:2])
                        if len(required_by) > 2:
                            parents += f", +{len(required_by)-2} more"
                        print(f"      • {pkg} (required by: {parents})")
                    else:
                        print(f"      • {pkg} (indirect)")

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


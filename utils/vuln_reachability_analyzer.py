#!/usr/bin/env python3
"""
Vulnerability Reachability Analyzer

Analyzes whether vulnerable packages are actually used in the codebase,
providing intelligent risk assessment beyond simple version checking.
"""

import ast
import json
import os
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
    usage_type: str  # "import", "function_call", "attribute_access", "usage"


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str


class LanguageAnalyzer(ABC):
    """Abstract base class for language-specific analyzers"""

    def __init__(self, project_root: Path):
        self.project_root = project_root

    @abstractmethod
    def get_source_files(self) -> List[Path]:
        """Get all source files for this language"""
        pass

    @abstractmethod
    def extract_usage(self, file_path: Path) -> Dict[str, List[UsageContext]]:
        """Extract package usage from a source file"""
        pass

    @abstractmethod
    def get_declared_dependencies(self) -> Dict[str, str]:
        """Get dependencies declared in build files"""
        pass

    @abstractmethod
    def normalize_package_name(self, package_name: str) -> str:
        """Normalize package name for comparison"""
        pass


class PythonAnalyzer(LanguageAnalyzer):
    """Analyzer for Python projects"""

    def __init__(self, project_root: Path):
        super().__init__(project_root)
        self.import_to_dist = get_package_mappings()

    def get_source_files(self) -> List[Path]:
        """Find all Python files in the project."""
        python_files = []
        exclude_dirs = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', '.pytest_cache'}

        for root, dirs, files in os.walk(self.project_root):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)

        return python_files

    def extract_usage(self, file_path: Path) -> Dict[str, List[UsageContext]]:
        """Extract import statements and usage patterns from a Python file."""
        usage_map = {}

        try:
            content = self._read_file_safely(file_path)
            if not content:
                return usage_map

            lines = content.splitlines()
            tree = ast.parse(content)

            # Process AST nodes
            for node in ast.walk(tree):
                self._process_ast_node(node, lines, file_path, usage_map)

        except SyntaxError as e:
            print(f"Warning: Syntax error in {file_path}: {e}")
        except Exception as e:
            print(f"Warning: Could not analyze {file_path}: {e}")

        return usage_map

    def _read_file_safely(self, file_path: Path) -> Optional[str]:
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return None

    def _process_ast_node(self, node, lines: List[str], file_path: Path, usage_map: Dict):
        """Process individual AST nodes for import and usage patterns"""
        if isinstance(node, ast.Import):
            self._handle_import(node, lines, file_path, usage_map)
        elif isinstance(node, ast.ImportFrom):
            self._handle_import_from(node, lines, file_path, usage_map)
        elif isinstance(node, ast.Call):
            self._handle_function_call(node, lines, file_path, usage_map)

    def _handle_import(self, node: ast.Import, lines: List[str], file_path: Path, usage_map: Dict):
        """Handle regular import statements"""
        for alias in node.names:
            pkg_name = alias.name.split('.')[0]
            dist_name = self._import_to_distribution_name(pkg_name)
            self._add_usage_context(usage_map, dist_name, file_path, node.lineno, lines, "import")

    def _handle_import_from(self, node: ast.ImportFrom, lines: List[str], file_path: Path, usage_map: Dict):
        """Handle from...import statements"""
        if node.module:
            pkg_name = node.module.split('.')[0]
            dist_name = self._import_to_distribution_name(pkg_name)
            self._add_usage_context(usage_map, dist_name, file_path, node.lineno, lines, "import")

    def _handle_function_call(self, node: ast.Call, lines: List[str], file_path: Path, usage_map: Dict):
        """Handle function calls that might be package-related"""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            dist_name = self._import_to_distribution_name(func_name)
            if dist_name in usage_map:
                self._add_usage_context(usage_map, dist_name, file_path, node.lineno, lines, "function_call")

        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            pkg_name = node.func.value.id
            dist_name = self._import_to_distribution_name(pkg_name)
            if dist_name in usage_map:
                self._add_usage_context(usage_map, dist_name, file_path, node.lineno, lines, "function_call")

    def _add_usage_context(self, usage_map: Dict, dist_name: str, file_path: Path,
                           line_no: int, lines: List[str], usage_type: str):
        """Add usage context to the usage map"""
        if dist_name not in usage_map:
            usage_map[dist_name] = []

        context_line = lines[line_no - 1].strip() if line_no <= len(lines) else ""
        usage_map[dist_name].append(UsageContext(
            file_path=str(file_path),
            line_number=line_no,
            context_line=context_line,
            usage_type=usage_type
        ))

    def _import_to_distribution_name(self, import_name: str) -> str:
        """Convert import name to distribution name using dynamic mappings."""
        import_name_lower = import_name.lower()
        return self.import_to_dist.get(import_name_lower, import_name_lower)

    def get_declared_dependencies(self) -> Dict[str, str]:
        """Get dependencies from Python package files"""
        # This could be extended to parse requirements.txt, setup.py, pyproject.toml, etc.
        dependencies = {}

        # Parse requirements.txt
        req_file = self.project_root / "requirements.txt"
        if req_file.exists():
            dependencies.update(self._parse_requirements_txt(req_file))

        return dependencies

    def _parse_requirements_txt(self, req_file: Path) -> Dict[str, str]:
        """Parse requirements.txt file"""
        dependencies = {}
        try:
            with open(req_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple parsing - could be enhanced
                        if '==' in line:
                            name, version = line.split('==', 1)
                            dependencies[name.strip()] = version.strip()
                        elif '>=' in line:
                            name = line.split('>=')[0].strip()
                            dependencies[name] = "unknown"
        except Exception as e:
            print(f"Warning: Could not parse {req_file}: {e}")

        return dependencies

    def normalize_package_name(self, package_name: str) -> str:
        """Normalize Python package name"""
        return package_name.lower().replace('_', '-')


class JavaAnalyzer(LanguageAnalyzer):
    """Analyzer for Java projects"""

    def __init__(self, project_root: Path):
        super().__init__(project_root)
        self.java_extensions = {'.java', '.kt', '.scala', '.groovy'}
        self.package_mappings = self._init_package_mappings()
        self.class_mappings = self._init_class_mappings()

    def get_source_files(self) -> List[Path]:
        """Scan for Java source files"""
        java_files = []
        exclude_patterns = {'/test/', '/tests/', '/target/', '/build/', '.test'}

        for ext in self.java_extensions:
            for file_path in self.project_root.rglob(f"*{ext}"):
                path_str = str(file_path).lower()
                if not any(exclude in path_str for exclude in exclude_patterns):
                    java_files.append(file_path)

        return java_files

    def extract_usage(self, file_path: Path) -> Dict[str, List[UsageContext]]:
        """Extract imports and usage from Java files"""
        usage_map = {}

        try:
            content = self._read_file_safely(file_path)
            if not content:
                return usage_map

            lines = content.split('\n')

            # Extract imports and usage
            for line_num, line in enumerate(lines, 1):
                self._process_java_line(line, line_num, file_path, usage_map)

        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")

        return usage_map

    def _read_file_safely(self, file_path: Path) -> Optional[str]:
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return None

    def _process_java_line(self, line: str, line_num: int, file_path: Path, usage_map: Dict):
        """Process a single line of Java code"""
        line_stripped = line.strip()

        # Handle imports
        import_match = re.match(r'^\s*import\s+(static\s+)?([a-zA-Z_][a-zA-Z0-9_.]*(?:\.\*)?)\s*;', line_stripped)
        if import_match:
            full_import = import_match.group(2)
            package_name = self._extract_java_package_name(full_import)
            if package_name:
                self._add_usage_context(usage_map, package_name, file_path, line_num, line_stripped, "import")

        # Handle usage patterns
        self._find_java_usage_in_line(line_stripped, line_num, file_path, usage_map)

    def _extract_java_package_name(self, import_statement: str) -> Optional[str]:
        """Extract package name from Java import statement"""
        # Try exact matches first
        for pattern, package in self.package_mappings.items():
            if import_statement.startswith(pattern):
                return package

        # Try to extract from common patterns
        parts = import_statement.split('.')
        if len(parts) >= 3:
            group = '.'.join(parts[:2])  # org.springframework
            artifact = parts[2]  # web, boot, etc.

            # Common Spring patterns
            if group == 'org.springframework' and artifact != 'boot':
                return f"spring-{artifact}"
            elif group == 'org.springframework' and artifact == 'boot':
                return "spring-boot"

        return None

    def _find_java_usage_in_line(self, line: str, line_num: int, file_path: Path, usage_map: Dict):
        """Find package usage in a line of Java code"""
        usage_patterns = [
            r'@([A-Z][a-zA-Z0-9]*)',  # Annotations
            r'new\s+([A-Z][a-zA-Z0-9]*)',  # Object instantiation
            r'([A-Z][a-zA-Z0-9]*)\s*\.',  # Static method calls
            r'([A-Z][a-zA-Z0-9]*)\s+\w+\s*=',  # Variable declarations
        ]

        for pattern in usage_patterns:
            for match in re.finditer(pattern, line):
                class_name = match.group(1)
                package_name = self.class_mappings.get(class_name)

                if package_name and package_name in usage_map:
                    self._add_usage_context(usage_map, package_name, file_path, line_num, line, "usage")

    def _add_usage_context(self, usage_map: Dict, package_name: str, file_path: Path,
                           line_num: int, line: str, usage_type: str):
        """Add usage context to the usage map"""
        if package_name not in usage_map:
            usage_map[package_name] = []

        usage_map[package_name].append(UsageContext(
            file_path=str(file_path),
            line_number=line_num,
            context_line=line,
            usage_type=usage_type
        ))

    def get_declared_dependencies(self) -> Dict[str, str]:
        """Parse build files for dependency information"""
        dependencies = {}
        dependencies.update(self._parse_maven_dependencies())
        dependencies.update(self._parse_gradle_dependencies())
        return dependencies

    def _parse_maven_dependencies(self) -> Dict[str, str]:
        """Parse Maven pom.xml for dependency information"""
        pom_path = self.project_root / 'pom.xml'
        if not pom_path.exists():
            return {}

        dependencies = {}
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Handle namespace
            namespace = {}
            if root.tag.startswith('{'):
                ns_uri = root.tag.split('}')[0][1:]
                namespace = {'maven': ns_uri}

            # Find dependencies
            xpath = './/maven:dependency' if namespace else './/dependency'
            for dependency in root.findall(xpath, namespace):
                group_elem = dependency.find('maven:groupId' if namespace else 'groupId', namespace)
                artifact_elem = dependency.find('maven:artifactId' if namespace else 'artifactId', namespace)
                version_elem = dependency.find('maven:version' if namespace else 'version', namespace)

                if group_elem is not None and artifact_elem is not None:
                    key = f"{group_elem.text}:{artifact_elem.text}"
                    version = version_elem.text if version_elem is not None else "unknown"
                    dependencies[key] = version

        except Exception as e:
            print(f"Warning: Could not parse pom.xml: {e}")

        return dependencies

    def _parse_gradle_dependencies(self) -> Dict[str, str]:
        """Parse Gradle build files for dependency information"""
        gradle_files = ['build.gradle', 'build.gradle.kts']
        dependencies = {}

        for gradle_file in gradle_files:
            gradle_path = self.project_root / gradle_file
            if not gradle_path.exists():
                continue

            try:
                with open(gradle_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                patterns = [
                    r"(?:implementation|compile|api|testImplementation)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                ]

                for pattern in patterns:
                    for match in re.finditer(pattern, content):
                        group_id, artifact_id, version = match.groups()
                        key = f"{group_id}:{artifact_id}"
                        dependencies[key] = version

            except Exception as e:
                print(f"Warning: Could not parse {gradle_path}: {e}")

        return dependencies

    def normalize_package_name(self, package_name: str) -> str:
        """Normalize Java package names"""
        if ':' in package_name:
            return package_name.lower()
        return package_name.lower()

    def _init_package_mappings(self) -> Dict[str, str]:
        """Initialize Java package to artifact mappings"""
        return {
            'org.springframework.boot': 'spring-boot',
            'org.springframework.web': 'spring-web',
            'org.springframework.webmvc': 'spring-webmvc',
            'org.springframework.context': 'spring-context',
            'org.springframework.core': 'spring-core',
            'org.springframework.beans': 'spring-beans',
            'org.springframework.security': 'spring-security-core',
            'org.springframework.data.jpa': 'spring-data-jpa',
            'org.apache.tomcat.embed': 'tomcat-embed-core',
            'ch.qos.logback': 'logback-classic',
            'io.netty': 'netty-common',
            'com.fasterxml.jackson.core': 'jackson-core',
            'com.fasterxml.jackson.databind': 'jackson-databind',
            'org.slf4j': 'slf4j-api',
            'org.apache.commons.lang3': 'commons-lang3',
            'org.hibernate': 'hibernate-core',
        }

    def _init_class_mappings(self) -> Dict[str, str]:
        """Initialize Java class to package mappings"""
        return {
            'SpringApplication': 'spring-boot',
            'RestController': 'spring-web',
            'Controller': 'spring-webmvc',
            'Service': 'spring-context',
            'Component': 'spring-context',
            'Autowired': 'spring-beans',
            'RequestMapping': 'spring-web',
            'GetMapping': 'spring-web',
            'PostMapping': 'spring-web',
            'Logger': 'logback-classic',
            'LoggerFactory': 'slf4j-api',
            'ObjectMapper': 'jackson-databind',
            'JsonNode': 'jackson-databind',
        }


class RiskAssessment:
    """Handles risk assessment logic"""

    @staticmethod
    def assess_risk(usage_contexts: List[UsageContext], is_declared: bool,
                    pkg_name: str) -> Tuple[CriticalityLevel, str]:
        """Assess risk level based on usage patterns"""
        if not usage_contexts and not is_declared:
            return (CriticalityLevel.NOT_REACHABLE,
                    f"Package {pkg_name} is not imported or used in the codebase")

        if not usage_contexts and is_declared:
            return (CriticalityLevel.LOW,
                    f"Package {pkg_name} is declared in build file but not used in source code")

        # Analyze usage patterns
        files_with_usage = len(set(ctx.file_path for ctx in usage_contexts))
        function_calls = len([ctx for ctx in usage_contexts
                              if ctx.usage_type in ['usage', 'function_call']])
        imports_only = len([ctx for ctx in usage_contexts if ctx.usage_type == 'import'])

        if function_calls >= 5 and files_with_usage >= 3:
            return (CriticalityLevel.CRITICAL,
                    f"Package {pkg_name} is actively used with {function_calls} function calls across {files_with_usage} files")
        elif function_calls > 0:
            return (CriticalityLevel.HIGH,
                    f"Package {pkg_name} is used with {function_calls} direct function calls")
        elif files_with_usage >= 3:
            return (CriticalityLevel.MEDIUM,
                    f"Package {pkg_name} is imported across {files_with_usage} files")
        elif imports_only > 0:
            return (CriticalityLevel.LOW,
                    f"Package {pkg_name} is imported but has limited usage")
        else:
            return (CriticalityLevel.LOW,
                    f"Package {pkg_name} has minimal usage detected")


class VulnReachabilityAnalyzer:
    """Main analyzer class that coordinates language-specific analyzers"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.analyzers: List[LanguageAnalyzer] = []
        self._initialize_analyzers()

    def _initialize_analyzers(self):
        """Initialize language-specific analyzers based on project structure"""
        # Check for Python project
        if self._has_python_files():
            self.analyzers.append(PythonAnalyzer(self.project_root))

        # Check for Java project
        if self._has_java_files():
            self.analyzers.append(JavaAnalyzer(self.project_root))

    def _has_python_files(self) -> bool:
        """Check if project has Python files"""
        return any(self.project_root.rglob("*.py"))

    def _has_java_files(self) -> bool:
        """Check if project has Java files"""
        java_extensions = ["*.java", "*.kt", "*.scala"]
        return any(self.project_root.rglob(ext) for ext in java_extensions)

    def analyze_vulnerability_reachability(self, vuln_data: List[Dict]) -> List[VulnAnalysis]:
        """Analyze if vulnerable packages are actually used in the codebase."""
        if not self.analyzers:
            print("Warning: No supported language analyzers found")
            return []

        # Collect usage data from all analyzers
        all_usage = {}
        all_declared_deps = {}

        for analyzer in self.analyzers:
            print(f"🔍 Analyzing {type(analyzer).__name__}...")

            # Get source files and analyze usage
            source_files = analyzer.get_source_files()
            for file_path in source_files:
                file_usage = analyzer.extract_usage(file_path)
                for pkg, contexts in file_usage.items():
                    all_usage.setdefault(pkg, []).extend(contexts)

            # Get declared dependencies
            declared_deps = analyzer.get_declared_dependencies()
            all_declared_deps.update(declared_deps)

        # Analyze each vulnerability
        analyses = []
        for vuln in vuln_data:
            analysis = self._analyze_single_vulnerability(
                vuln, all_usage, all_declared_deps
            )
            analyses.append(analysis)

        return analyses

    def _analyze_single_vulnerability(self, vuln: Dict, all_usage: Dict,
                                      all_declared_deps: Dict) -> VulnAnalysis:
        """Analyze a single vulnerability"""
        pkg_name = vuln.get('package_name', '')
        installed_version = vuln.get('installed_version', '')
        recommended_version = vuln.get('recommended_fixed_version', 'latest')

        # Normalize package name and check for usage
        normalized_variations = self._get_package_name_variations(pkg_name)
        usage_contexts = []

        for variation in normalized_variations:
            usage_contexts.extend(all_usage.get(variation, []))

        # Check if declared in build files
        is_declared = any(variation in all_declared_deps for variation in normalized_variations)

        # Get version from build files if not provided
        if not installed_version:
            for variation in normalized_variations:
                if variation in all_declared_deps:
                    installed_version = all_declared_deps[variation]
                    break

        # Assess risk
        criticality, risk_reason = RiskAssessment.assess_risk(
            usage_contexts, is_declared, pkg_name
        )

        return VulnAnalysis(
            package_name=pkg_name,
            installed_version=installed_version or "unknown",
            recommended_version=recommended_version,
            is_used=len(usage_contexts) > 0 or is_declared,
            usage_contexts=usage_contexts,
            criticality=criticality,
            risk_reason=risk_reason
        )

    def _get_package_name_variations(self, pkg_name: str) -> List[str]:
        """Get different variations of package name for lookup"""
        variations = [pkg_name, pkg_name.lower()]

        # Add normalized variations
        for analyzer in self.analyzers:
            normalized = analyzer.normalize_package_name(pkg_name)
            variations.append(normalized)

        # Remove duplicates while preserving order
        return list(dict.fromkeys(variations))

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
        criticality_order = [
            CriticalityLevel.CRITICAL, CriticalityLevel.HIGH,
            CriticalityLevel.MEDIUM, CriticalityLevel.LOW, CriticalityLevel.NOT_REACHABLE
        ]
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
    _print_analysis_summary(report)


def _print_analysis_summary(report: Dict):
    """Print analysis summary to console"""
    summary = report['summary']

    print("=== Vulnerability Reachability Analysis ===")
    print(f"Total vulnerabilities analyzed: {summary['total_vulnerabilities']}")
    print(f"Critical (actively used): {summary['critical_reachable']}")
    print(f"High (used with calls): {summary['high_reachable']}")
    print(f"Medium (imported): {summary['medium_reachable']}")
    print(f"Low (limited usage): {summary['low_reachable']}")
    print(f"Not reachable: {summary['not_reachable']}")
    print()

    # Show critical and high vulnerabilities
    for vuln in report["vulnerabilities"]:
        if vuln["critprimeicality"] in ["CRITICAL", "HIGH"]:
            print(f"🚨 {vuln['criticality']}: {vuln['package_name']} v{vuln['installed_version']}")
            print(f"   Reason: {vuln['risk_reason']}")
            print(f"   Upgrade to: {vuln['recommended_version']}")

            # Show first 3 usage examples
            contexts = vuln["usage_details"]["usage_contexts"][:3]
            for ctx in contexts:
                print(f"   📍 {ctx['file']}:{ctx['line']} - {ctx['code']}")

            if len(vuln["usage_details"]["usage_contexts"]) > 3:
                remaining = len(vuln["usage_details"]["usage_contexts"]) - 3
                print(f"   ... and {remaining} more usages")
            print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyze vulnerability reachability in codebase")
    parser.add_argument("project_root", help="Path to project root directory")
    parser.add_argument("consolidated_json", help="Path to consolidated vulnerability JSON file")
    parser.add_argument("--output", "-o", help="Output report file path",
                        default="vulnerability_reachability_report.json")

    args = parser.parse_args()

    run_reachability_analysis(args.project_root, args.consolidated_json, args.output)
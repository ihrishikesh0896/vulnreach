"""Static Taint Analysis

Finds taint flows in Python code by:
1. Identifying taint sources (HTTP inputs, file reads, env vars)
2. Identifying taint sinks (SQL, exec, file writes, etc.)
3. Tracing dataflow from sources to sinks
4. Mapping flows to vulnerable packages from SCA results
"""

import ast
import os
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import json


@dataclass
class TaintSource:
    """Represents a taint source in the code"""
    source_expr: str  # e.g., "request.args['user']"
    source_type: str  # HTTP_INPUT, FILE_READ, ENV_VAR, CLI_ARG
    file_path: str
    line_number: int
    function_name: Optional[str] = None
    variable_name: Optional[str] = None


@dataclass
class TaintSink:
    """Represents a taint sink in the code"""
    sink_expr: str  # e.g., "cursor.execute(sql)"
    sink_function: str  # execute, eval, open, etc.
    sink_type: str  # SQL_QUERY, CODE_EVAL, FILE_WRITE, etc.
    vulnerability_type: str  # SQL_INJECTION, CODE_INJECTION, etc.
    cwe: str  # CWE-89, CWE-78, etc.
    file_path: str
    line_number: int
    function_name: Optional[str] = None


@dataclass
class TaintFlow:
    """Represents a complete taint flow from source to sink"""
    source: TaintSource
    sink: TaintSink
    confidence: str  # HIGH, MEDIUM, LOW
    path: List[str]  # List of function/method names in the flow
    package_name: Optional[str] = None  # Mapped from vulnerable packages


class SourceDetector(ast.NodeVisitor):
    """AST visitor to detect taint sources"""
    
    # Known source patterns for different frameworks
    SOURCE_PATTERNS = {
        # Flask
        'request.args': 'HTTP_INPUT',
        'request.form': 'HTTP_INPUT',
        'request.json': 'HTTP_INPUT',
        'request.data': 'HTTP_INPUT',
        'request.files': 'HTTP_INPUT',
        'request.values': 'HTTP_INPUT',
        'request.cookies': 'HTTP_INPUT',
        'request.headers': 'HTTP_INPUT',
        
        # Django
        'request.GET': 'HTTP_INPUT',
        'request.POST': 'HTTP_INPUT',
        'request.body': 'HTTP_INPUT',
        'request.FILES': 'HTTP_INPUT',
        'request.COOKIES': 'HTTP_INPUT',
        'request.META': 'HTTP_INPUT',
        
        # FastAPI
        'request.query_params': 'HTTP_INPUT',
        'request.path_params': 'HTTP_INPUT',
        'request.body': 'HTTP_INPUT',
        
        # File operations
        'open': 'FILE_READ',
        'read': 'FILE_READ',
        'readlines': 'FILE_READ',
        
        # Environment
        'os.environ': 'ENV_VAR',
        'os.getenv': 'ENV_VAR',
        
        # CLI arguments
        'sys.argv': 'CLI_ARG',
        'argparse': 'CLI_ARG',
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.sources: List[TaintSource] = []
        self.current_function = None
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Attribute(self, node: ast.Attribute):
        """Detect attribute access like request.args"""
        source_str = self._get_source_string(node)
        
        for pattern, source_type in self.SOURCE_PATTERNS.items():
            if source_str.startswith(pattern):
                self.sources.append(TaintSource(
                    source_expr=source_str,
                    source_type=source_type,
                    file_path=self.file_path,
                    line_number=node.lineno,
                    function_name=self.current_function
                ))
                break
        
        self.generic_visit(node)
    
    def visit_Subscript(self, node: ast.Subscript):
        """Detect subscript access like request.args['user']"""
        source_str = self._get_source_string(node)
        
        for pattern, source_type in self.SOURCE_PATTERNS.items():
            if pattern in source_str:
                # Extract variable name from subscript if available
                var_name = None
                if isinstance(node.slice, ast.Constant):
                    var_name = str(node.slice.value)
                
                self.sources.append(TaintSource(
                    source_expr=source_str,
                    source_type=source_type,
                    file_path=self.file_path,
                    line_number=node.lineno,
                    function_name=self.current_function,
                    variable_name=var_name
                ))
                break
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Detect function calls like os.getenv()"""
        call_str = self._get_source_string(node.func)
        
        for pattern, source_type in self.SOURCE_PATTERNS.items():
            if call_str.endswith(pattern) or pattern in call_str:
                self.sources.append(TaintSource(
                    source_expr=call_str,
                    source_type=source_type,
                    file_path=self.file_path,
                    line_number=node.lineno,
                    function_name=self.current_function
                ))
                break
        
        self.generic_visit(node)
    
    def _get_source_string(self, node: ast.AST) -> str:
        """Convert AST node to source string"""
        try:
            if isinstance(node, ast.Attribute):
                value_str = self._get_source_string(node.value)
                return f"{value_str}.{node.attr}"
            elif isinstance(node, ast.Name):
                return node.id
            elif isinstance(node, ast.Subscript):
                value_str = self._get_source_string(node.value)
                if isinstance(node.slice, ast.Constant):
                    return f"{value_str}[{repr(node.slice.value)}]"
                return f"{value_str}[...]"
            elif isinstance(node, ast.Call):
                func_str = self._get_source_string(node.func)
                return f"{func_str}()"
            elif isinstance(node, ast.Constant):
                return repr(node.value)
            else:
                return "unknown"
        except:
            return "unknown"


class SinkDetector(ast.NodeVisitor):
    """AST visitor to detect taint sinks"""
    
    # Known sink patterns
    SINK_PATTERNS = {
        # SQL sinks
        'execute': {'type': 'SQL_QUERY', 'vuln': 'SQL_INJECTION', 'cwe': 'CWE-89'},
        'executemany': {'type': 'SQL_QUERY', 'vuln': 'SQL_INJECTION', 'cwe': 'CWE-89'},
        'raw': {'type': 'SQL_QUERY', 'vuln': 'SQL_INJECTION', 'cwe': 'CWE-89'},
        
        # Command execution sinks
        'exec': {'type': 'CODE_EVAL', 'vuln': 'CODE_INJECTION', 'cwe': 'CWE-94'},
        'eval': {'type': 'CODE_EVAL', 'vuln': 'CODE_INJECTION', 'cwe': 'CWE-95'},
        'compile': {'type': 'CODE_EVAL', 'vuln': 'CODE_INJECTION', 'cwe': 'CWE-94'},
        '__import__': {'type': 'CODE_EVAL', 'vuln': 'CODE_INJECTION', 'cwe': 'CWE-94'},
        
        # OS command sinks
        'system': {'type': 'OS_COMMAND', 'vuln': 'COMMAND_INJECTION', 'cwe': 'CWE-78'},
        'popen': {'type': 'OS_COMMAND', 'vuln': 'COMMAND_INJECTION', 'cwe': 'CWE-78'},
        'subprocess': {'type': 'OS_COMMAND', 'vuln': 'COMMAND_INJECTION', 'cwe': 'CWE-78'},
        
        # File operation sinks
        'open': {'type': 'FILE_WRITE', 'vuln': 'PATH_TRAVERSAL', 'cwe': 'CWE-22'},
        'write': {'type': 'FILE_WRITE', 'vuln': 'PATH_TRAVERSAL', 'cwe': 'CWE-22'},
        
        # Deserialization sinks
        'pickle.loads': {'type': 'DESERIALIZE', 'vuln': 'DESERIALIZATION', 'cwe': 'CWE-502'},
        'yaml.load': {'type': 'DESERIALIZE', 'vuln': 'DESERIALIZATION', 'cwe': 'CWE-502'},
        'marshal.loads': {'type': 'DESERIALIZE', 'vuln': 'DESERIALIZATION', 'cwe': 'CWE-502'},
        
        # Template sinks (SSTI)
        'render_template_string': {'type': 'TEMPLATE', 'vuln': 'SSTI', 'cwe': 'CWE-94'},
        'Template': {'type': 'TEMPLATE', 'vuln': 'SSTI', 'cwe': 'CWE-94'},
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.sinks: List[TaintSink] = []
        self.current_function = None
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Call(self, node: ast.Call):
        """Detect function calls that are sinks"""
        call_str = self._get_call_string(node.func)
        
        # Check against sink patterns
        for pattern, info in self.SINK_PATTERNS.items():
            if call_str.endswith(pattern) or pattern in call_str:
                self.sinks.append(TaintSink(
                    sink_expr=call_str,
                    sink_function=pattern,
                    sink_type=info['type'],
                    vulnerability_type=info['vuln'],
                    cwe=info['cwe'],
                    file_path=self.file_path,
                    line_number=node.lineno,
                    function_name=self.current_function
                ))
                break
        
        self.generic_visit(node)
    
    def _get_call_string(self, node: ast.AST) -> str:
        """Convert call AST node to string"""
        try:
            if isinstance(node, ast.Attribute):
                value_str = self._get_call_string(node.value)
                return f"{value_str}.{node.attr}"
            elif isinstance(node, ast.Name):
                return node.id
            else:
                return "unknown"
        except:
            return "unknown"


class StaticTaintAnalyzer:
    """Main static taint analyzer"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
        self.sources: List[TaintSource] = []
        self.sinks: List[TaintSink] = []
        self.flows: List[TaintFlow] = []
    
    def analyze_project(self, vulnerabilities: List[Dict[str, Any]] = None) -> Dict[str, List[TaintFlow]]:
        """
        Analyze the project for taint flows
        
        Args:
            vulnerabilities: Optional list of vulnerabilities from SCA to map flows to packages
            
        Returns:
            Dictionary mapping package names to their taint flows
        """
        print("\n🔬 Running static taint analysis...")
        
        # Find all Python files
        python_files = self._find_python_files()
        print(f"📁 Found {len(python_files)} Python files")
        
        # Detect sources and sinks
        for file_path in python_files:
            self._analyze_file(file_path)
        
        print(f"✅ Found {len(self.sources)} taint sources")
        print(f"✅ Found {len(self.sinks)} taint sinks")
        
        # Build taint flows
        self._build_flows()
        print(f"✅ Identified {len(self.flows)} potential taint flows")
        
        # Map flows to vulnerable packages
        if vulnerabilities:
            flows_by_package = self._map_flows_to_packages(vulnerabilities)
        else:
            # Group by file if no vulnerabilities provided
            flows_by_package = self._group_flows_by_file()
        
        return flows_by_package
    
    def _find_python_files(self) -> List[Path]:
        """Find all Python files in the project"""
        python_files = []
        exclude_dirs = {'.venv', 'venv', 'env', '__pycache__', '.git', 'node_modules', 'dist', 'build'}
        
        for root, dirs, files in os.walk(self.project_root):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith('.py'):
                    python_files.append(Path(root) / file)
        
        return python_files
    
    def _analyze_file(self, file_path: Path):
        """Analyze a single Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            tree = ast.parse(source_code, filename=str(file_path))
            
            # Detect sources
            source_detector = SourceDetector(str(file_path))
            source_detector.visit(tree)
            self.sources.extend(source_detector.sources)
            
            # Detect sinks
            sink_detector = SinkDetector(str(file_path))
            sink_detector.visit(tree)
            self.sinks.extend(sink_detector.sinks)
            
        except Exception as e:
            # Skip files that can't be parsed
            pass
    
    def _build_flows(self):
        """Build taint flows by connecting sources to sinks"""
        # Simple heuristic: connect sources and sinks in the same function or file
        for source in self.sources:
            for sink in self.sinks:
                # Check if in same file
                if source.file_path == sink.file_path:
                    confidence = self._calculate_confidence(source, sink)
                    
                    # Build path
                    path = []
                    if source.function_name:
                        path.append(source.function_name)
                    if sink.function_name and sink.function_name != source.function_name:
                        path.append(sink.function_name)
                    
                    if confidence != 'NONE':
                        flow = TaintFlow(
                            source=source,
                            sink=sink,
                            confidence=confidence,
                            path=path if path else [os.path.basename(source.file_path)]
                        )
                        self.flows.append(flow)
    
    def _calculate_confidence(self, source: TaintSource, sink: TaintSink) -> str:
        """Calculate confidence of a taint flow"""
        # HIGH: Same function
        if source.function_name and source.function_name == sink.function_name:
            return 'HIGH'
        
        # MEDIUM: Same file, different functions
        if source.file_path == sink.file_path:
            return 'MEDIUM'
        
        # LOW: Different files (would need call graph analysis)
        return 'LOW'
    
    def _map_flows_to_packages(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[TaintFlow]]:
        """Map taint flows to vulnerable packages"""
        flows_by_package = {}
        
        # Extract vulnerable packages
        vuln_packages = {v.get('pkg_name', '').lower() for v in vulnerabilities}
        
        for flow in self.flows:
            # Extract potential package name from file path or sink function
            package_name = self._extract_package_name(flow, vuln_packages)
            
            if package_name:
                flow.package_name = package_name
                if package_name not in flows_by_package:
                    flows_by_package[package_name] = []
                flows_by_package[package_name].append(flow)
        
        return flows_by_package
    
    def _extract_package_name(self, flow: TaintFlow, vuln_packages: Set[str]) -> Optional[str]:
        """Try to extract package name from taint flow"""
        # Check if any vulnerable package name appears in the file path
        file_path_lower = flow.sink.file_path.lower()
        
        for pkg in vuln_packages:
            if pkg in file_path_lower:
                return pkg
        
        # Default to 'unknown' if can't determine
        return None
    
    def _group_flows_by_file(self) -> Dict[str, List[TaintFlow]]:
        """Group flows by file when no vulnerabilities provided"""
        flows_by_file = {}
        
        for flow in self.flows:
            file_name = os.path.basename(flow.sink.file_path)
            if file_name not in flows_by_file:
                flows_by_file[file_name] = []
            flows_by_file[file_name].append(flow)
        
        return flows_by_file
    
    def export_flows_to_dict(self, flows_by_package: Dict[str, List[TaintFlow]]) -> Dict[str, Any]:
        """Export flows to dictionary format"""
        result = {}
        
        for package, flows in flows_by_package.items():
            result[package] = []
            for flow in flows:
                result[package].append({
                    'source': flow.source.source_expr,
                    'source_file': flow.source.file_path,
                    'source_line': flow.source.line_number,
                    'source_type': flow.source.source_type,
                    'sink': flow.sink.sink_expr,
                    'sink_file': flow.sink.file_path,
                    'sink_line': flow.sink.line_number,
                    'sink_type': flow.sink.sink_type,
                    'vulnerability_type': flow.sink.vulnerability_type,
                    'cwe': flow.sink.cwe,
                    'confidence': flow.confidence,
                    'path': flow.path
                })
        
        return result
    
    def save_results(self, flows_by_package: Dict[str, List[TaintFlow]], output_path: str):
        """Save taint analysis results to JSON"""
        result = {
            'metadata': {
                'project_root': str(self.project_root),
                'total_sources': len(self.sources),
                'total_sinks': len(self.sinks),
                'total_flows': len(self.flows),
                'packages_analyzed': len(flows_by_package)
            },
            'taint_flows': self.export_flows_to_dict(flows_by_package)
        }
        
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"💾 Taint analysis results saved to: {output_path}")


def analyze_project_taint(project_root: str, vulnerabilities: List[Dict[str, Any]] = None, 
                         output_path: str = None) -> Dict[str, List[TaintFlow]]:
    """
    Convenience function to run static taint analysis
    
    Args:
        project_root: Root directory of the project
        vulnerabilities: Optional list of vulnerabilities from SCA
        output_path: Optional path to save results
        
    Returns:
        Dictionary mapping packages to taint flows
    """
    analyzer = StaticTaintAnalyzer(project_root)
    flows_by_package = analyzer.analyze_project(vulnerabilities)
    
    if output_path:
        analyzer.save_results(flows_by_package, output_path)
    
    return flows_by_package

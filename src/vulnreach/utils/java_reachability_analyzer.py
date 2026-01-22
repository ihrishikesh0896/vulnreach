"""
Java Vulnerability Reachability Analyzer

Analyzes whether vulnerable Java libraries are used in the codebase.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
from enum import Enum

try:
    from .java_call_graph import JavaCallGraphBuilder
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
    usage_type: str  # "import", "instantiation", "method_call"
    enclosing_method: str = None

@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str
    call_chain_graph: str = None

class JavaReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.import_pattern = re.compile(r'import\s+([\w\.]+);')
        
        # Initialize Call Graph
        self.call_graph_builder = None
        if HAS_CALL_GRAPH:
            try:
                print(f"🕸️  Building static call graph for {self.project_root}...")
                self.call_graph_builder = JavaCallGraphBuilder(str(self.project_root))
                self.call_graph_builder.build_graph()
                print(f"   Graph built: {len(self.call_graph_builder.graph)} functions, {len(self.call_graph_builder.entry_points)} entry points")
            except Exception as e:
                print(f"Warning: Could not build call graph: {e}")

    def find_java_files(self) -> List[Path]:
        java_files = []
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(Path(root) / file)
        return java_files

    def find_package_usage(self, package_group: str, package_artifact: str) -> List[UsageContext]:
        """
        Find usage of a Java package.
        Java packages are often group:artifact (e.g. org.apache.logging.log4j:log4j-core).
        Usage is typically 'import org.apache.logging.log4j.Logger'.
        """
        usage_contexts = []
        java_files = self.find_java_files()
        
        # Simple heuristic mappings from artifactId to package prefix
        # e.g. "log4j-core" -> "org.apache.logging.log4j"
        # Since we don't have the JAR to inspect, we check if the import PATH
        # contains the artifact's signature words.
        
        # For artifacts like "spring-web", we look for "org.springframework.web"
        # We search for the artifact name parts in the import.
        keywords = package_artifact.replace('-', '.').split('.')
        
        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.splitlines()
                    
                    # Scope tracking for enclosing method
                    method_def_pattern = re.compile(r'(?:public|private|protected|static|final|native|synchronized|abstract|transient|\s)+[\w<>\[\]]+\s+([a-zA-Z0-9_$]+)\s*\([^\)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{')
                    brace_balance = 0
                    scope_stack = [] # (name, level)
                    current_method = None
                    
                    for line_num, line in enumerate(lines, 1):
                        strip_line = line.strip()
                        
                        # Brace tracking
                        brace_balance += line.count('{')
                        brace_balance -= line.count('}')
                        
                        # Enter scope
                        match = method_def_pattern.search(strip_line)
                        if match:
                            method_name = match.group(1)
                            # filter keywords
                            if method_name not in {'if', 'for', 'switch', 'while', 'catch'}:
                                scope_stack.append({'name': method_name, 'level': brace_balance})
                                current_method = method_name
                        
                        # Exit scope
                        if scope_stack:
                            if brace_balance < scope_stack[-1]['level']:
                                scope_stack.pop()
                                current_method = scope_stack[-1]['name'] if scope_stack else None

                        # Check Usage (Import)
                        import_match = self.import_pattern.search(strip_line)
                        is_usage = False
                        
                        if import_match:
                            imported_pkg = import_match.group(1)
                            # Check if all keywords are present? or just significant overlap
                            # e.g. log4j -> log4j
                            if any(k in imported_pkg for k in keywords if len(k) > 3):
                                # Heuristic: match if artifact keyword is in import
                                usage_contexts.append(UsageContext(
                                    file_path=str(java_file.relative_to(self.project_root)),
                                    line_number=line_num,
                                    context_line=strip_line,
                                    usage_type="import",
                                    enclosing_method=current_method
                                ))
                        
                        # Check direct class usage if we know the class name?
                        # This is harder without mapping classes to packages.
                        # We stick to imports for now as primary signal.
                        
            except Exception:
                pass
                
        return usage_contexts

    def analyze_vulnerability(self, vuln_data: Dict) -> VulnAnalysis:
        pkg_name = vuln_data.get('package_name', '') # e.g. org.apache.logging.log4j:log4j-core
        version = vuln_data.get('installed_version', '')
        fixed = vuln_data.get('fixed_version', '')
        
        # Parse group vs artifact
        group = ""
        artifact = pkg_name
        if ':' in pkg_name:
            group, artifact = pkg_name.split(':')
            
        usage_contexts = self.find_package_usage(group, artifact)
        is_used = len(usage_contexts) > 0
        
        criticality = CriticalityLevel.NOT_REACHABLE
        risk_reason = "Library not imported in source code"
        
        if is_used:
            sev = vuln_data.get('severity', 'MEDIUM')
            if sev == 'CRITICAL': criticality = CriticalityLevel.CRITICAL
            elif sev == 'HIGH': criticality = CriticalityLevel.HIGH
            elif sev == 'MEDIUM': criticality = CriticalityLevel.MEDIUM
            else: criticality = CriticalityLevel.LOW
            
            risk_reason = f"Library imported in {len(usage_contexts)} files"

        # Generate Call Graph Trace
        call_graph_mermaid = None
        if self.call_graph_builder and is_used:
            target_methods = {ctx.enclosing_method for ctx in usage_contexts if ctx.enclosing_method}
            if target_methods:
                traces = self.call_graph_builder.find_trace_to_usage(list(target_methods))
                if traces:
                    call_graph_mermaid = self.call_graph_builder.get_mermaid_graph(traces)
                    path_count = len(traces)
                    risk_reason += f" [VERIFIED: {path_count} paths from endpoints]"
                    
                    if criticality in [CriticalityLevel.HIGH, CriticalityLevel.MEDIUM]:
                        criticality = CriticalityLevel.CRITICAL

        return VulnAnalysis(pkg_name, version, fixed, is_used, usage_contexts, criticality, risk_reason, call_graph_mermaid)

def run_java_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    print(f"\n{'='*60}")
    print("☕ JAVA VULNERABILITY REACHABILITY ANALYSIS")
    print(f"{'='*60}\n")
    
    try:
        with open(consolidated_path, 'r') as f:
            data = json.load(f)
            vulns = data if isinstance(data, list) else data.get('vulnerabilities', [])
    except Exception as e:
        print(f"Error loading data: {e}")
        return

    analyzer = JavaReachabilityAnalyzer(project_root)
    analyses = []
    
    for v in vulns:
        res = analyzer.analyze_vulnerability(v)
        analyses.append(res)
        status = "✓ USED" if res.is_used else "✗ NOT USED"
        print(f"{status} | {res.package_name:40} | {res.criticality.value:15} | {res.risk_reason}")

    report = {
        "project_root": project_root,
        "language": "java",
        "analyses": [
            {
                **{k: v for k, v in asdict(a).items() if k not in {'usage_contexts', 'call_chain_graph'}},
                'criticality': a.criticality.value,
                'call_chain_graph': a.call_chain_graph,
                'usage_count': len(a.usage_contexts),
                'usage_contexts': [asdict(uc) for uc in a.usage_contexts[:5]]
            }
            for a in analyses
        ]
    }
    
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved report to {output_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python java_reachability_analyzer.py <root> <vulns.json> <out.json>")
        sys.exit(1)
    run_java_reachability_analysis(sys.argv[1], sys.argv[2], sys.argv[3])
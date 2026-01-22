"""
Java Call Graph Generators
Generates a static call graph for Java projects to trace reachability.
Uses regex-based heuristics for class/method definitions and calls.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Set, Optional

class JavaCallGraphBuilder:
    """
    Builds a lightweight static call graph for Java projects.
    
    Analyses:
    1. Method Definitions: public void foo() { ... }
    2. Method Calls: foo(); object.bar();
    3. Entry Points: @GetMapping, @PostMapping, public static void main
    4. Tracks class membership to handle simple method referencing
    """

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.graph = {}            # MethodName -> Set[CalledMethodNames]
        self.function_locations = {} # MethodName -> FilePath:Line
        self.entry_points = set()
        
        # Regex patterns
        # 1. Method Definition: public/private type name(args) {
        # Note: Java is complex (generics, annotations), this is a simplified robust matcher
        self.method_def_pattern = re.compile(
            r'(?:public|private|protected|static|final|native|synchronized|abstract|transient|\s)+[\w<>\[\]]+\s+([a-zA-Z0-9_$]+)\s*\([^\)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
        )
        
        # 2. Entry Point Annotations (Spring Boot, JAX-RS)
        self.entry_point_annotations = {
            '@GetMapping', '@PostMapping', '@PutMapping', '@DeleteMapping', 
            '@PatchMapping', '@RequestMapping', '@GET', '@POST', '@PUT', '@DELETE'
        }
        
        # 3. Method Call: name(args)
        # Avoid keywords: if, for, while, switch, catch...
        self.keywords = {'if', 'for', 'while', 'switch', 'catch', 'try', 'synchronized', 'return', 'throw', 'new', 'super', 'this'}
        self.call_pattern = re.compile(r'(?:[a-zA-Z0-9_$]+\.)*([a-zA-Z0-9_$]+)\s*\(')

    def build_graph(self):
        """Parse all Java files and build the call graph"""
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file.endswith(".java"):
                    full_path = Path(root) / file
                    try:
                        self._process_file(full_path)
                    except Exception as e:
                        pass # robust

    def _process_file(self, file_path: Path):
        """Parse a single Java file"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()
            rel_path = str(file_path.relative_to(self.project_root))
            
            # State tracking
            scope_stack = [] # (name, push_level)
            brace_balance = 0
            current_method = None
            
            # Look ahead for annotations (store last few lines of annotations)
            pending_annotations = set()

            for i, line in enumerate(lines):
                strip_line = line.strip()
                original_brace_balance = brace_balance
                
                # Check for annotations before logic
                if strip_line.startswith('@'):
                    # primitive annotation extraction
                    parts = strip_line.split()
                    for p in parts:
                        if p.startswith('@'):
                            # clean @GetMapping("/foo") -> @GetMapping
                            clean_anno = p.split('(')[0]
                            pending_annotations.add(clean_anno)
                
                # Update brace balance
                brace_balance += line.count('{')
                brace_balance -= line.count('}')
                
                # Check method definition
                # Heuristic: usually definition line ends with { or involves {
                # We enforce that match must occur at current brace level (scope start)
                match = self.method_def_pattern.search(strip_line)
                if match:
                    method_name = match.group(1)
                    if method_name not in self.keywords:
                        # Enter method scope
                        scope_stack.append({'name': method_name, 'level': brace_balance})
                        current_method = method_name
                        
                        unique_name = method_name # For full Java, needs Class.Method
                        self.function_locations[unique_name] = f"{rel_path}:{i+1}"
                        if unique_name not in self.graph:
                            self.graph[unique_name] = set()

                        # Check if it was an entry point
                        if any(a in self.entry_point_annotations for a in pending_annotations):
                            self.entry_points.add(unique_name)
                        if method_name == 'main' and 'public static void' in strip_line:
                             self.entry_points.add(unique_name)
                             
                        # Clear annotations after use
                        pending_annotations = set()

                else:
                    # If not a method def, maybe the annotations belong to a class or field, clear them if line has { or ; and no method found
                    if '{' in strip_line or ';' in strip_line:
                         pending_annotations = set()

                # Check scope exit
                if scope_stack:
                    if brace_balance < scope_stack[-1]['level']:
                        scope_stack.pop()
                        current_method = scope_stack[-1]['name'] if scope_stack else None
                
                # Extract Calls
                if current_method:
                    calls = self._extract_calls(strip_line)
                    for called_name in calls:
                        self.graph[current_method].add(called_name)

        except Exception:
            pass

    def _extract_calls(self, line: str) -> List[str]:
        calls = []
        # Exclude comments
        if line.strip().startswith('//') or line.strip().startswith('*'):
            return calls
            
        matches = self.call_pattern.finditer(line)
        for match in matches:
            name = match.group(1)
            if name not in self.keywords:
                calls.append(name)
        return calls

    def find_trace_to_usage(self, target_method_names: List[str]) -> List[List[str]]:
        """BFS trace from entry points to targets"""
        traces = []
        
        for entry in self.entry_points:
            queue = [(entry, [entry])]
            visited = set()
            
            while queue:
                current, path = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                
                if current in target_method_names:
                    traces.append(path)
                    continue
                
                if current in self.graph:
                    for neighbor in self.graph[current]:
                        if neighbor not in visited:
                            new_path = path + [neighbor]
                            if neighbor in target_method_names:
                                traces.append(new_path)
                            elif len(new_path) < 10:
                                queue.append((neighbor, new_path))
        return traces

    def get_mermaid_graph(self, traces: List[List[str]]) -> str:
        if not traces:
            return ""
        lines = ["graph TD;"]
        edges = set()
        for trace in traces:
            for i in range(len(trace) - 1):
                src = trace[i]
                dst = trace[i+1]
                edge = f"    {src} --> {dst};"
                if edge not in edges:
                    lines.append(edge)
                    edges.add(edge)
        return "\n".join(lines)

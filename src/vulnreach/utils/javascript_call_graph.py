"""
JavaScript/TypeScript Call Graph Generators
Generates a static call graph for JavaScript/TypeScript projects to trace reachability.
Uses regex-based heuristics for function definitions and calls as a lightweight fallback
where AST parsing libraries for JS/TS are not available in the Python environment.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

class JavaScriptCallGraphBuilder:
    """
    Builds a lightweight static call graph for JS/TS projects.
    
    Uses robust regex patterns to:
    1. Identify function definitions (function foo(), const foo = () => {}, class methods)
    2. Identify function calls within those definitions
    3. Build an adjacency dictionary (caller -> [callees])
    4. Trace paths from entry points (routes, event handlers) to sinks
    """

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.graph = {}  # FuncName -> List[CalledFuncNames]
        self.function_locations = {}  # FuncName -> FilePath:Line
        self.entry_points = set()
        
        # Regex patterns for JS/TS function definitions
        self.function_patterns = [
            # function foo(args) { ... }
            re.compile(r'function\s+([a-zA-Z0-9_$]+)\s*\('),
            # const foo = function(args) { ... } or const foo = (args) => { ... }
            re.compile(r'(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:function\s*\(|\(?.*?\)?\s*=>)'),
            # class method() { ... } (simplified, catches some false positives but robust enough for proto)
            re.compile(r'^\s*([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{'),
            # export function foo()
            re.compile(r'export\s+function\s+([a-zA-Z0-9_$]+)\s*\(')
        ]

        # Route entry point patterns (Express, Fastify, Next.js)
        self.route_patterns = [
            re.compile(r'\.(get|post|put|delete|patch|all)\s*\('),  # app.get('/', handler)
            re.compile(r'router\.(get|post|put|delete|patch|all)\s*\('),
            re.compile(r'export\s+const\s+(GET|POST|PUT|DELETE|PATCH)\s*='), # Next.js Route Handlers
        ]

    def build_graph(self):
        """Parse all JS/TS files and build the call graph"""
        extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
        
        for root, dirs, files in os.walk(self.project_root):
            # Skip node_modules and common build dirs
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', 'dist', 'build', 'coverage', '.next', 'out'
            }]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    full_path = Path(root) / file
                    try:
                        self._process_file(full_path)
                    except Exception as e:
                        pass

    def _process_file(self, file_path: Path):
        """Parse a single file and extract function calls"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.splitlines()
            rel_path = str(file_path.relative_to(self.project_root))
            
            # Simple stack-based parser to track current function scope
            # This is heuristic and assumes relatively standard indentation or formatting
            # For complex minified code, this will fail (but that's out of scope for source analysis)
            
            current_scope = None
            scope_stack = [] # (name, push_by_brace_count)
            brace_balance = 0
            
            for i, line in enumerate(lines):
                line = line.strip()
                original_brace_balance = brace_balance
                
                # Update brace balance
                brace_balance += line.count('{')
                brace_balance -= line.count('}')
                
                # Check if we are starting a new function
                potential_func = self._match_function_def(line)
                if potential_func:
                    func_name = potential_func
                    # We are entering a function
                    scope_stack.append({'name': func_name, 'level': brace_balance})
                    current_scope = func_name
                    
                    unique_name = f"{func_name}" # Could namespace with filename if needed
                    self.function_locations[unique_name] = f"{rel_path}:{i+1}"
                    if unique_name not in self.graph:
                        self.graph[unique_name] = set()
                        
                    # Check if this function definition looks like a route handler?
                    # Hard to tell from just definition line, identifying usage is better.
                
                # Check if we are ending a function scope
                if scope_stack:
                    # If brace balance drops below the level where the current scope started
                    # (Adjust logic: standard JS style keeps opening brace on same line mostly)
                    if brace_balance < scope_stack[-1]['level']: 
                        scope_stack.pop()
                        current_scope = scope_stack[-1]['name'] if scope_stack else None

                # Look for calls within current scope
                calls = self._extract_calls(line)
                if current_scope:
                    for called_func in calls:
                        self.graph[current_scope].add(called_func)
                else:
                    # Top-level calls / Global scope
                    # We can treat this as "execution at module load"
                    # For reachability, maybe map to a pseudo <module_init> node
                    pass

                # Check for entry point registration (app.get('/', handler))
                # This logic connects routes to handlers
                if self._is_route_definition(line):
                    # Extract the handler function name if passed as argument
                    # app.get('/', myHandler) -> entry point is myHandler
                    # app.get('/', (req, res) => { ... }) -> this is harder with regex, identified as anon func
                    
                    # Try to find handler names passed as args
                    # Split by comma, ignore first arg (route path), look for names
                    parts = line.split(',')
                    if len(parts) > 1:
                        possible_handler = parts[1].strip().replace(')', '').replace(';', '')
                        # Heuristic: if it looks like a function name
                        if re.match(r'^[a-zA-Z0-9_$]+$', possible_handler):
                             self.entry_points.add(possible_handler)
                             
            # Also scan for exported explicit route handlers (Next.js App Router)
            for pattern in self.route_patterns:
                match = pattern.search(content)
                if match:
                    # If we found explicit route exports, mark them as entry points
                    # (This part requires more precise line-by-line mapping which we did above simplistically)
                    pass

        except Exception:
            pass

    def _match_function_def(self, line: str) -> Optional[str]:
        for pattern in self.function_patterns:
            match = pattern.search(line)
            if match:
                return match.group(1)
        return None

    def _extract_calls(self, line: str) -> List[str]:
        """Extract function calls from a line: foo(arg), bar.baz()"""
        calls = []
        # Matches foo() or foo.bar()
        # Exclude keyword-like calls (if, for, while, switch, catch)
        keywords = {'if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'typeof', 'await', 'import'}
        
        matches = re.finditer(r'(?:[a-zA-Z0-9_$]+\.)*([a-zA-Z0-9_$]+)\s*\(', line)
        for match in matches:
            name = match.group(1)
            if name not in keywords:
                calls.append(name)
        return calls

    def _is_route_definition(self, line: str) -> bool:
        for pattern in self.route_patterns:
            if pattern.search(line):
                return True
        return False

    def find_trace_to_usage(self, target_function_names: List[str]) -> List[List[str]]:
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
                
                if current in target_function_names:
                    traces.append(path)
                    continue
                
                if current in self.graph:
                    for neighbor in self.graph[current]:
                        if neighbor not in visited:
                            new_path = path + [neighbor]
                            if neighbor in target_function_names:
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

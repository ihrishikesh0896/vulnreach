"""
Python Call Graph Generators
Generates a static call graph for Python projects to trace reachability.
"""

import ast
import os
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

class PythonCallGraphBuilder:
    """
    Builds a lightweight static call graph for Python projects.
    
    This implementation uses AST parsing to:
    1. Identify function definitions
    2. Identify function calls within those definitions
    3. Build an adjacency dictionary (caller -> [callees])
    4. Trace paths from entry points (e.g., Flask routes, main) to sinks (vulnerable usage)
    """

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.graph = {}  # FuncName -> List[CalledFuncNames]
        self.function_locations = {}  # FuncName -> FilePath:Line
        self.entry_points = set()
        
    def _get_func_name(self, node: ast.AST) -> Optional[str]:
        """Helper to extract function name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Recurse for obj.method -> return "method" (simplified)
            # A full implementation would track "obj" type, but for a lightweight demo, 
            # tracking the method name is often a "good enough" heuristic.
            return node.attr
        return None

    def build_graph(self):
        """Parse all python files and build the call graph"""
        for root, dirs, files in os.walk(self.project_root):
            # Prune unwanted directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('venv', 'app_venv', 'env', 'node_modules', 'dist', 'build', '__pycache__')]
            
            for file in files:
                if file.endswith(".py"):
                    full_path = Path(root) / file
                    try:
                        self._process_file(full_path)
                    except Exception as e:
                        # Log error but continue
                        pass

    def _process_file(self, file_path: Path):
        """Parse a single file and extract function calls"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            tree = ast.parse(content, filename=str(file_path))
            rel_path = str(file_path.relative_to(self.project_root))
            
            # 1. Visitor to find function definitions
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                    func_name = node.name
                    unique_name = f"{func_name}" # In a real tool, would include class/module scope
                    
                    self.function_locations[unique_name] = f"{rel_path}:{node.lineno}"
                    self.graph[unique_name] = set()
                    
                    # Heuristic: Check if likely entry point
                    if self._is_entry_point(node):
                        self.entry_points.add(unique_name)

                    # 2. Look for calls inside this function
                    for subnode in ast.walk(node):
                        if isinstance(subnode, ast.Call):
                            called_name = self._get_func_name(subnode.func)
                            if called_name:
                                self.graph[unique_name].add(called_name)
                                
            # Top-Level calls (script entry points)
            # Find calls that are NOT inside a function def (module level)
            # This is a bit complex with ast.walk, simplified here:
            # We treat 'if __name__ == "__main__":' as entry point block
            for node in ast.walk(tree):
                if isinstance(node, ast.If):
                    # Check for __main__ check
                   if self._is_main_check(node):
                       # Collect calls in body
                       for subnode in ast.walk(node):
                           if isinstance(subnode, ast.Call):
                               called_name = self._get_func_name(subnode.func)
                               if called_name:
                                   # Create a pseudo-node for the script main
                                   main_node = f"__main__({rel_path})"
                                   self.entry_points.add(main_node)
                                   if main_node not in self.graph:
                                       self.graph[main_node] = set()
                                   self.graph[main_node].add(called_name)

        except Exception:
            pass

    def _is_entry_point(self, node: ast.FunctionDef) -> bool:
        """Heuristic to detect web framework routes (Flask/FastAPI/Django)"""
        # check decorators
        for decorator in node.decorator_list:
             # Basic check for @app.route, @app.get, etc.
             if isinstance(decorator, ast.Call):
                 func_name = self._get_func_name(decorator.func)
                 if func_name and any(x in func_name for x in ['route', 'get', 'post', 'put', 'delete', 'patch']):
                     return True
             # Check for @cli.command (Click)
             if isinstance(decorator, ast.Attribute) and decorator.attr == 'command':
                 return True
        return False

    def _is_main_check(self, node: ast.If) -> bool:
        """Check for if __name__ == '__main__'"""
        try:
            if isinstance(node.test, ast.Compare):
                # We expect simple comparison
                left = node.test.left
                if isinstance(left, ast.Name) and left.id == "__name__":
                    # Check comparators
                    if len(node.test.comparators) > 0 and isinstance(node.test.comparators[0], ast.Constant):
                        if node.test.comparators[0].value == "__main__":
                            return True
        except:
            pass
        return False

    def find_trace_to_usage(self, target_function_names: List[str]) -> List[List[str]]:
        """
        Find traces from any entry point to any of the target functions.
        Returns a list of traces (each trace is a list of function names strings).
        Uses BFS.
        """
        traces = []
        
        # We search FORWARD from Entry Points -> Targets
        # Alternatively, we could search BACKWARD from Targets -> Entry Points (often more efficient for specific sinks)
        # For this demo, let's do BFS from Entry Points.
        
        for entry in self.entry_points:
            queue = [(entry, [entry])] # (current_node, path)
            visited = set()
            
            while queue:
                current, path = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                
                # Check if current node calls any of our targets
                # Or IS one of our targets (if the entry point calls it directly)
                
                # Simple matching: strict equality
                if current in target_function_names:
                    traces.append(path)
                    # Don't stop, look for other paths? For demo, maybe finding one path per entry is enough.
                    continue
                
                # Neighbors
                if current in self.graph:
                    for neighbor in self.graph[current]:
                        if neighbor not in visited:
                            new_path = path + [neighbor]
                            # Check if neighbor is target
                            if neighbor in target_function_names:
                                traces.append(new_path)
                            else:
                                if len(new_path) < 10: # Limit depth
                                    queue.append((neighbor, new_path))
                                    
        return traces

    def get_mermaid_graph(self, traces: List[List[str]]) -> str:
        """Generate a Mermaid graph definition for the traces"""
        if not traces:
            return ""
            
        lines = ["graph TD;"]
        edges = set()
        nodes = set()
        
        for trace in traces:
            for node in trace:
                clean_node = node.replace(":", "_").replace(".", "_").replace("(", "").replace(")", "").replace("/", "_").replace("-", "_")
                nodes.add(clean_node)
                
            if len(trace) > 1:
                for i in range(len(trace) - 1):
                    src = trace[i].replace(":", "_").replace(".", "_").replace("(", "").replace(")", "").replace("/", "_").replace("-", "_")
                    dst = trace[i+1].replace(":", "_").replace(".", "_").replace("(", "").replace(")", "").replace("/", "_").replace("-", "_")
                    edge = f"    {src} --> {dst};"
                    if edge not in edges:
                        lines.append(edge)
                        edges.add(edge)
        
        # If we have nodes but no edges (single node traces), add them
        if not edges and nodes:
             for node in nodes:
                 lines.append(f"    {node};")
        
        # Add basic styling
        lines.append("    classDef vulnerable fill:#ffcccc,stroke:#ff0000,stroke-width:2px;")
        lines.append("    classDef entry fill:#ccffcc,stroke:#00ff00,stroke-width:2px;")
        
        return "\n".join(lines)

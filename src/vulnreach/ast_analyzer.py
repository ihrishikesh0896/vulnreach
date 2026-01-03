"""
AST-based code analysis module using ast-grep
Foundation for vulnerability reachability analysis
"""

import json
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path


class ASTAnalyzer:
    """Foundation class for AST-based code analysis using ast-grep"""
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.ast_grep_available = self._check_ast_grep()
    
    def _check_ast_grep(self) -> bool:
        """Check if ast-grep is installed"""
        try:
            subprocess.run(['ast-grep', '--version'], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def search_pattern(self, pattern: str, language: str = "python", 
                      path: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for code patterns using ast-grep
        
        Args:
            pattern: AST pattern to search
            language: Programming language (python, javascript, etc)
            path: Optional specific path to search
            
        Returns:
            List of matches with file, line, and code context
        """
        if not self.ast_grep_available:
            raise RuntimeError("ast-grep not installed")
        
        search_path = path if path else str(self.root_path)
        
        cmd = [
            'ast-grep',
            '--pattern', pattern,
            '--lang', language,
            '--json',
            search_path
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, 
                                  text=True, check=False)  # Don't raise on non-zero exit
            
            # ast-grep returns exit code 1 when no matches found (not an error)
            if result.returncode == 0 or result.returncode == 1:
                if result.stdout:
                    try:
                        return json.loads(result.stdout)
                    except json.JSONDecodeError:
                        return []
                return []
            else:
                # Real error (exit code > 1)
                if result.stderr:
                    print(f"ast-grep error: {result.stderr}")
                return []
        except Exception as e:
            print(f"ast-grep exception: {e}")
            return []
    
    def find_function_calls(self, function_name: str, 
                           language: str = "python") -> List[Dict[str, Any]]:
        """Find all calls to a specific function"""
        pattern = f"{function_name}($$$)"
        return self.search_pattern(pattern, language)
    
    def find_imports(self, module_name: str, 
                    language: str = "python") -> List[Dict[str, Any]]:
        """Find imports of a specific module"""
        if language == "python":
            pattern = f"import {module_name}"
            from_pattern = f"from {module_name} import $$$"
            
            imports = self.search_pattern(pattern, language)
            imports.extend(self.search_pattern(from_pattern, language))
            return imports
        return []
    
    def find_class_usage(self, class_name: str, 
                        language: str = "python") -> List[Dict[str, Any]]:
        """Find instantiations and usage of a specific class"""
        pattern = f"{class_name}($$$)"
        return self.search_pattern(pattern, language)
    
    def trace_call_chain(self, start_function: str, 
                        target_function: str,
                        language: str = "python") -> Dict[str, Any]:
        """
        Trace if there's a call chain from start_function to target_function
        
        Returns:
            Dictionary with trace results including path and confidence
        """
        start_calls = self.find_function_calls(start_function, language)
        target_calls = self.find_function_calls(target_function, language)
        
        return {
            'start_function': start_function,
            'target_function': target_function,
            'start_locations': len(start_calls),
            'target_locations': len(target_calls),
            'files_with_start': list(set(m.get('file', '') for m in start_calls)),
            'files_with_target': list(set(m.get('file', '') for m in target_calls)),
            'potential_paths': self._analyze_paths(start_calls, target_calls)
        }
    
    def _analyze_paths(self, start_calls: List[Dict], 
                      target_calls: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze potential call paths between functions"""
        paths = []
        
        start_files = {m.get('file', '') for m in start_calls}
        target_files = {m.get('file', '') for m in target_calls}
        
        common_files = start_files & target_files
        if common_files:
            for file in common_files:
                paths.append({
                    'type': 'direct',
                    'file': file,
                    'confidence': 'high'
                })
        
        return paths


class VulnerabilityTracer:
    """Trace vulnerability reachability using AST analysis"""
    
    def __init__(self, ast_analyzer: ASTAnalyzer):
        self.analyzer = ast_analyzer
    
    def is_vulnerable_function_reachable(self, 
                                        vulnerable_function: str,
                                        entry_points: List[str],
                                        language: str = "python") -> Dict[str, Any]:
        """
        Check if vulnerable function is reachable from entry points
        
        Args:
            vulnerable_function: Name of vulnerable function to trace
            entry_points: List of application entry points (routes, main, etc)
            language: Programming language
            
        Returns:
            Reachability analysis with confidence score
        """
        results = {
            'vulnerable_function': vulnerable_function,
            'reachable': False,
            'confidence': 'none',
            'paths': [],
            'entry_points_checked': entry_points
        }
        
        vuln_usage = self.analyzer.find_function_calls(vulnerable_function, language)
        
        if not vuln_usage:
            results['confidence'] = 'low'
            results['note'] = 'Function not found in codebase'
            return results
        
        for entry in entry_points:
            trace = self.analyzer.trace_call_chain(entry, vulnerable_function, language)
            if trace['potential_paths']:
                results['reachable'] = True
                results['confidence'] = 'high'
                results['paths'].extend(trace['potential_paths'])
        
        if vuln_usage and not results['reachable']:
            results['confidence'] = 'medium'
            results['note'] = 'Function used but no direct path from entry points found'
        
        return results
    
    def analyze_package_usage(self, package_name: str, 
                             vulnerable_functions: List[str],
                             language: str = "python") -> Dict[str, Any]:
        """
        Analyze if a vulnerable package's functions are actually used
        
        Args:
            package_name: Name of the vulnerable package
            vulnerable_functions: List of known vulnerable functions
            language: Programming language
            
        Returns:
            Usage analysis with recommendations
        """
        imports = self.analyzer.find_imports(package_name, language)
        
        results = {
            'package': package_name,
            'imported': len(imports) > 0,
            'import_locations': [m.get('file', '') for m in imports],
            'vulnerable_functions_used': [],
            'risk_level': 'none'
        }
        
        if not imports:
            results['risk_level'] = 'none'
            results['recommendation'] = 'Package not imported - safe to keep or remove'
            return results
        
        for vuln_func in vulnerable_functions:
            usage = self.analyzer.find_function_calls(vuln_func, language)
            if usage:
                results['vulnerable_functions_used'].append({
                    'function': vuln_func,
                    'locations': [m.get('file', '') for m in usage]
                })
        
        if results['vulnerable_functions_used']:
            results['risk_level'] = 'high'
            results['recommendation'] = 'Vulnerable functions are used - immediate action required'
        else:
            results['risk_level'] = 'low'
            results['recommendation'] = 'Package imported but vulnerable functions not used'
        
        return results

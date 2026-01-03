"""
AST Analysis Agent - specialized agent for code structure analysis
"""

from typing import Dict, List, Any, Optional
from ..ast_analyzer import ASTAnalyzer, VulnerabilityTracer


class ASTAgent:
    """
    Agent specialized in AST-based code analysis
    Foundation for agent-based reachability analysis
    """
    
    def __init__(self, root_path: str):
        self.analyzer = ASTAnalyzer(root_path)
        self.tracer = VulnerabilityTracer(self.analyzer)
        self.root_path = root_path
    
    def analyze(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis entry point
        
        Task format:
        {
            'type': 'find_calls' | 'trace_reachability' | 'analyze_package',
            'params': {...}
        }
        """
        task_type = task.get('type')
        params = task.get('params', {})
        
        if task_type == 'find_calls':
            return self._find_calls(params)
        elif task_type == 'trace_reachability':
            return self._trace_reachability(params)
        elif task_type == 'analyze_package':
            return self._analyze_package(params)
        else:
            return {'error': f'Unknown task type: {task_type}'}
    
    def _find_calls(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Find function calls in codebase"""
        function_name = params.get('function_name')
        language = params.get('language', 'python')
        
        if not function_name:
            return {'error': 'function_name required'}
        
        results = self.analyzer.find_function_calls(function_name, language)
        
        return {
            'task': 'find_calls',
            'function': function_name,
            'found': len(results),
            'locations': results
        }
    
    def _trace_reachability(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Trace reachability of vulnerable function"""
        vulnerable_function = params.get('vulnerable_function')
        entry_points = params.get('entry_points', [])
        language = params.get('language', 'python')
        
        if not vulnerable_function:
            return {'error': 'vulnerable_function required'}
        
        results = self.tracer.is_vulnerable_function_reachable(
            vulnerable_function, entry_points, language
        )
        
        return {
            'task': 'trace_reachability',
            **results
        }
    
    def _analyze_package(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze package usage and vulnerability exposure"""
        package_name = params.get('package_name')
        vulnerable_functions = params.get('vulnerable_functions', [])
        language = params.get('language', 'python')
        
        if not package_name:
            return {'error': 'package_name required'}
        
        results = self.tracer.analyze_package_usage(
            package_name, vulnerable_functions, language
        )
        
        return {
            'task': 'analyze_package',
            **results
        }
    
    def get_capabilities(self) -> List[str]:
        """Return list of agent capabilities"""
        return [
            'find_function_calls',
            'find_imports',
            'find_class_usage',
            'trace_call_chain',
            'trace_reachability',
            'analyze_package_usage'
        ]

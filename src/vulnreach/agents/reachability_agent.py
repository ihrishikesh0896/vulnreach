"""
Reachability Agent - Orchestrates reachability analysis
Combines AST, Dependency, and Vulnerability agents
"""

from typing import Dict, List, Any, Optional
from pathlib import Path
from .ast_agent import ASTAgent
from .dependency_agent import DependencyAgent
from .vulnerability_agent import VulnerabilityAgent


class ReachabilityAgent:
    """
    Orchestrator agent that combines AST, dependency, and vulnerability analysis
    to determine if vulnerabilities are reachable from application entry points
    """
    
    def __init__(self, root_path: str):
        self.root_path = root_path
        self.ast_agent = ASTAgent(root_path)
        self.dep_agent = DependencyAgent(root_path)
        self.vuln_agent = VulnerabilityAgent()
    
    def analyze(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis entry point
        
        Task format:
        {
            'type': 'analyze_project' | 'analyze_package' | 'analyze_cve',
            'params': {...}
        }
        """
        task_type = task.get('type')
        params = task.get('params', {})
        
        if task_type == 'analyze_project':
            return self._analyze_project(params)
        elif task_type == 'analyze_package':
            return self._analyze_single_package(params)
        elif task_type == 'analyze_cve':
            return self._analyze_cve(params)
        else:
            return {'error': f'Unknown task type: {task_type}'}
    
    def _analyze_project(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full project analysis:
        1. Get all dependencies
        2. Query vulnerabilities for each
        3. Check reachability via AST
        """
        entry_points = params.get('entry_points', ['app.route', 'main'])
        language = params.get('language', 'python')
        ecosystem = params.get('ecosystem', 'PyPI')
        
        # Step 1: Get dependencies
        dep_result = self.dep_agent.analyze({
            'type': 'get_dependencies',
            'params': {}
        })
        
        if 'error' in dep_result:
            return {
                'task': 'analyze_project',
                'error': f"Dependency analysis failed: {dep_result['error']}"
            }
        
        dependencies = dep_result.get('dependencies', {})
        
        # Step 2: Query vulnerabilities for all packages
        packages_to_check = [
            {'name': name, 'version': info['version']}
            for name, info in dependencies.items()
        ]
        
        vuln_result = self.vuln_agent.analyze({
            'type': 'batch_query',
            'params': {
                'packages': packages_to_check,
                'ecosystem': ecosystem
            }
        })
        
        if 'error' in vuln_result:
            return {
                'task': 'analyze_project',
                'error': f"Vulnerability query failed: {vuln_result['error']}"
            }
        
        vuln_results = vuln_result.get('results', {})
        
        # Step 3: Analyze reachability for each vulnerability
        reachability_findings = []
        
        for package_name, vuln_data in vuln_results.items():
            if vuln_data['vulnerability_count'] > 0:
                for vuln in vuln_data['vulnerabilities']:
                    finding = self._analyze_vulnerability_reachability(
                        package_name,
                        vuln,
                        entry_points,
                        language
                    )
                    reachability_findings.append(finding)
        
        # Step 4: Compute summary statistics
        total_vulns = sum(v['vulnerability_count'] for v in vuln_results.values())
        reachable_vulns = sum(1 for f in reachability_findings if f['reachable'])
        high_confidence = sum(1 for f in reachability_findings if f['reachable'] and f['confidence'] == 'high')
        
        return {
            'task': 'analyze_project',
            'project_path': self.root_path,
            'package_manager': dep_result.get('package_manager'),
            'dependencies_checked': len(dependencies),
            'total_vulnerabilities': total_vulns,
            'reachable_vulnerabilities': reachable_vulns,
            'high_confidence_reachable': high_confidence,
            'findings': reachability_findings,
            'summary': {
                'risk_level': self._compute_risk_level(reachable_vulns, high_confidence),
                'recommendation': self._generate_recommendation(reachable_vulns, high_confidence)
            }
        }
    
    def _analyze_single_package(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single package for vulnerabilities and reachability
        """
        package_name = params.get('package_name')
        version = params.get('version')
        entry_points = params.get('entry_points', ['app.route', 'main'])
        language = params.get('language', 'python')
        ecosystem = params.get('ecosystem', 'PyPI')
        
        if not package_name:
            return {'error': 'package_name required'}
        
        # Step 1: Check if package is installed
        dep_check = self.dep_agent.analyze({
            'type': 'check_package',
            'params': {'package_name': package_name}
        })
        
        if not dep_check.get('installed'):
            return {
                'task': 'analyze_package',
                'package': package_name,
                'installed': False,
                'risk_level': 'none',
                'recommendation': 'Package not installed - no risk'
            }
        
        installed_version = dep_check.get('version') or version
        
        # Step 2: Query vulnerabilities
        vuln_result = self.vuln_agent.analyze({
            'type': 'get_package_vulns',
            'params': {
                'package_name': package_name,
                'version': installed_version,
                'ecosystem': ecosystem
            }
        })
        
        vulnerabilities = vuln_result.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return {
                'task': 'analyze_package',
                'package': package_name,
                'version': installed_version,
                'installed': True,
                'vulnerability_count': 0,
                'risk_level': 'none',
                'recommendation': 'No known vulnerabilities found'
            }
        
        # Step 3: Analyze reachability for each vulnerability
        findings = []
        for vuln in vulnerabilities:
            finding = self._analyze_vulnerability_reachability(
                package_name,
                vuln,
                entry_points,
                language
            )
            findings.append(finding)
        
        reachable_count = sum(1 for f in findings if f['reachable'])
        high_conf_count = sum(1 for f in findings if f['reachable'] and f['confidence'] == 'high')
        
        return {
            'task': 'analyze_package',
            'package': package_name,
            'version': installed_version,
            'installed': True,
            'vulnerability_count': len(vulnerabilities),
            'reachable_vulnerabilities': reachable_count,
            'high_confidence_reachable': high_conf_count,
            'findings': findings,
            'risk_level': self._compute_risk_level(reachable_count, high_conf_count),
            'recommendation': self._generate_recommendation(reachable_count, high_conf_count)
        }
    
    def _analyze_cve(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a specific CVE for reachability
        """
        cve_id = params.get('cve_id')
        entry_points = params.get('entry_points', ['app.route', 'main'])
        language = params.get('language', 'python')
        
        if not cve_id:
            return {'error': 'cve_id required'}
        
        # Get CVE details
        cve_result = self.vuln_agent.analyze({
            'type': 'get_cve',
            'params': {'cve_id': cve_id}
        })
        
        if 'error' in cve_result:
            return {
                'task': 'analyze_cve',
                'cve_id': cve_id,
                'error': cve_result['error']
            }
        
        vuln_data = cve_result.get('data', {})
        
        # Try to extract package name from CVE (if available)
        # This is a simplified approach - real implementation would need more logic
        package_name = params.get('package_name')
        
        if not package_name:
            return {
                'task': 'analyze_cve',
                'cve_id': cve_id,
                'error': 'Cannot determine affected package - please provide package_name'
            }
        
        finding = self._analyze_vulnerability_reachability(
            package_name,
            vuln_data,
            entry_points,
            language
        )
        
        return {
            'task': 'analyze_cve',
            'cve_id': cve_id,
            **finding
        }
    
    def _analyze_vulnerability_reachability(self, package_name: str,
                                           vuln: Dict[str, Any],
                                           entry_points: List[str],
                                           language: str) -> Dict[str, Any]:
        """
        Core reachability analysis for a single vulnerability
        """
        vuln_id = vuln.get('id', 'UNKNOWN')
        
        # Step 1: Check if package is imported
        import_check = self.ast_agent.analyzer.find_imports(package_name, language)
        
        if not import_check:
            return {
                'vulnerability_id': vuln_id,
                'package': package_name,
                'reachable': False,
                'confidence': 'high',
                'reason': 'Package not imported in codebase',
                'severity': vuln.get('severity', 'UNKNOWN'),
                'summary': vuln.get('summary', '')
            }
        
        # Step 2: Try to extract vulnerable function names
        # This is heuristic - real implementation would need vulnerability database mapping
        vulnerable_functions = self._extract_vulnerable_functions(vuln)
        
        if not vulnerable_functions:
            return {
                'vulnerability_id': vuln_id,
                'package': package_name,
                'reachable': True,
                'confidence': 'low',
                'reason': 'Package imported but cannot determine specific vulnerable functions',
                'import_locations': [loc.get('file', '') for loc in import_check],
                'severity': vuln.get('severity', 'UNKNOWN'),
                'summary': vuln.get('summary', '')
            }
        
        # Step 3: Check if vulnerable functions are called
        function_usage = []
        for func_name in vulnerable_functions:
            usage = self.ast_agent.analyzer.find_function_calls(func_name, language)
            if usage:
                function_usage.extend(usage)
        
        if not function_usage:
            return {
                'vulnerability_id': vuln_id,
                'package': package_name,
                'reachable': False,
                'confidence': 'medium',
                'reason': 'Package imported but vulnerable functions not used',
                'vulnerable_functions': vulnerable_functions,
                'severity': vuln.get('severity', 'UNKNOWN'),
                'summary': vuln.get('summary', '')
            }
        
        # Step 4: Trace from entry points to vulnerable functions
        reachable_from_entry = False
        paths = []
        
        for entry in entry_points:
            for func in vulnerable_functions:
                trace = self.ast_agent.analyzer.trace_call_chain(entry, func, language)
                if trace.get('potential_paths'):
                    reachable_from_entry = True
                    paths.extend(trace['potential_paths'])
        
        if reachable_from_entry:
            return {
                'vulnerability_id': vuln_id,
                'package': package_name,
                'reachable': True,
                'confidence': 'high',
                'reason': 'Vulnerable function reachable from entry points',
                'vulnerable_functions': vulnerable_functions,
                'entry_points': entry_points,
                'paths': paths,
                'severity': vuln.get('severity', 'UNKNOWN'),
                'summary': vuln.get('summary', '')
            }
        else:
            return {
                'vulnerability_id': vuln_id,
                'package': package_name,
                'reachable': True,
                'confidence': 'medium',
                'reason': 'Vulnerable function used but no direct path from entry points detected',
                'vulnerable_functions': vulnerable_functions,
                'usage_locations': [loc.get('file', '') for loc in function_usage],
                'severity': vuln.get('severity', 'UNKNOWN'),
                'summary': vuln.get('summary', '')
            }
    
    def _extract_vulnerable_functions(self, vuln: Dict[str, Any]) -> List[str]:
        """
        Extract vulnerable function names from vulnerability data
        This is a heuristic approach - real implementation needs proper CVE-to-function mapping
        """
        functions = []
        
        # Try to extract from summary/details
        details = vuln.get('details', '') + ' ' + vuln.get('summary', '')
        
        # Common patterns for function names in vulnerability descriptions
        import re
        
        # Match patterns like "vulnerable function `func_name`"
        pattern1 = r'`([a-zA-Z_][a-zA-Z0-9_\.]*)\(`'
        matches = re.findall(pattern1, details)
        functions.extend(matches)
        
        # Match patterns like "function func_name()"
        pattern2 = r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        matches = re.findall(pattern2, details)
        functions.extend(matches)
        
        return list(set(functions))
    
    def _compute_risk_level(self, reachable_count: int, 
                           high_confidence_count: int) -> str:
        """Compute overall risk level"""
        if high_confidence_count > 0:
            return 'critical'
        elif reachable_count > 0:
            return 'high'
        else:
            return 'low'
    
    def _generate_recommendation(self, reachable_count: int,
                                high_confidence_count: int) -> str:
        """Generate action recommendation"""
        if high_confidence_count > 0:
            return f'IMMEDIATE ACTION REQUIRED: {high_confidence_count} high-confidence reachable vulnerabilities detected'
        elif reachable_count > 0:
            return f'ACTION RECOMMENDED: {reachable_count} potentially reachable vulnerabilities detected'
        else:
            return 'No immediately reachable vulnerabilities detected - continue monitoring'
    
    def get_capabilities(self) -> List[str]:
        """Return list of agent capabilities"""
        return [
            'analyze_project',
            'analyze_package',
            'analyze_cve',
            'trace_vulnerability_reachability'
        ]

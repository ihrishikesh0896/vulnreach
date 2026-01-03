"""
Agent Coordinator - Central orchestrator for all agents
"""

from typing import Dict, List, Any, Optional
from pathlib import Path
import json
from datetime import datetime

from .ast_agent import ASTAgent
from .dependency_agent import DependencyAgent
from .vulnerability_agent import VulnerabilityAgent
from .reachability_agent import ReachabilityAgent


class AgentCoordinator:
    """
    Central coordinator that manages all specialized agents
    Provides unified interface for vulnerability reachability analysis
    """
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        
        # Initialize all agents
        self.agents = {
            'ast': ASTAgent(str(root_path)),
            'dependency': DependencyAgent(str(root_path)),
            'vulnerability': VulnerabilityAgent(),
            'reachability': ReachabilityAgent(str(root_path))
        }
        
        self.analysis_history = []
    
    def analyze_project(self, entry_points: Optional[List[str]] = None,
                       language: str = 'python',
                       ecosystem: str = 'PyPI') -> Dict[str, Any]:
        """
        Run full project analysis with all agents
        
        Args:
            entry_points: Application entry points (routes, main, etc)
            language: Programming language
            ecosystem: Package ecosystem (PyPI, npm, Maven, etc)
            
        Returns:
            Comprehensive reachability analysis report
        """
        if entry_points is None:
            entry_points = self._detect_entry_points(language)
        
        print(f"[Coordinator] Starting project analysis...")
        print(f"[Coordinator] Root path: {self.root_path}")
        print(f"[Coordinator] Entry points: {entry_points}")
        
        # Delegate to reachability agent (which orchestrates other agents)
        result = self.agents['reachability'].analyze({
            'type': 'analyze_project',
            'params': {
                'entry_points': entry_points,
                'language': language,
                'ecosystem': ecosystem
            }
        })
        
        # Add metadata
        result['analysis_timestamp'] = datetime.now().isoformat()
        result['coordinator_version'] = '1.0.0'
        
        # Store in history
        self.analysis_history.append({
            'timestamp': result['analysis_timestamp'],
            'type': 'project_analysis',
            'findings_count': result.get('reachable_vulnerabilities', 0)
        })
        
        return result
    
    def analyze_package(self, package_name: str,
                       version: Optional[str] = None,
                       entry_points: Optional[List[str]] = None,
                       language: str = 'python',
                       ecosystem: str = 'PyPI') -> Dict[str, Any]:
        """
        Analyze a single package for vulnerabilities and reachability
        
        Args:
            package_name: Name of package to analyze
            version: Optional specific version
            entry_points: Application entry points
            language: Programming language
            ecosystem: Package ecosystem
            
        Returns:
            Package-specific reachability analysis
        """
        if entry_points is None:
            entry_points = self._detect_entry_points(language)
        
        print(f"[Coordinator] Analyzing package: {package_name}")
        
        result = self.agents['reachability'].analyze({
            'type': 'analyze_package',
            'params': {
                'package_name': package_name,
                'version': version,
                'entry_points': entry_points,
                'language': language,
                'ecosystem': ecosystem
            }
        })
        
        result['analysis_timestamp'] = datetime.now().isoformat()
        
        return result
    
    def analyze_cve(self, cve_id: str,
                   package_name: Optional[str] = None,
                   entry_points: Optional[List[str]] = None,
                   language: str = 'python') -> Dict[str, Any]:
        """
        Analyze a specific CVE for reachability
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2023-12345)
            package_name: Optional package name
            entry_points: Application entry points
            language: Programming language
            
        Returns:
            CVE-specific reachability analysis
        """
        if entry_points is None:
            entry_points = self._detect_entry_points(language)
        
        print(f"[Coordinator] Analyzing CVE: {cve_id}")
        
        result = self.agents['reachability'].analyze({
            'type': 'analyze_cve',
            'params': {
                'cve_id': cve_id,
                'package_name': package_name,
                'entry_points': entry_points,
                'language': language
            }
        })
        
        result['analysis_timestamp'] = datetime.now().isoformat()
        
        return result
    
    def get_dependencies(self) -> Dict[str, Any]:
        """Get all project dependencies"""
        return self.agents['dependency'].analyze({
            'type': 'get_dependencies',
            'params': {}
        })
    
    def get_vulnerabilities(self, package_name: str,
                           version: Optional[str] = None,
                           ecosystem: str = 'PyPI') -> Dict[str, Any]:
        """Get vulnerabilities for a specific package"""
        return self.agents['vulnerability'].analyze({
            'type': 'get_package_vulns',
            'params': {
                'package_name': package_name,
                'version': version,
                'ecosystem': ecosystem
            }
        })
    
    def find_function_usage(self, function_name: str,
                           language: str = 'python') -> Dict[str, Any]:
        """Find where a function is used in the codebase"""
        return self.agents['ast'].analyze({
            'type': 'find_calls',
            'params': {
                'function_name': function_name,
                'language': language
            }
        })
    
    def export_report(self, analysis_result: Dict[str, Any],
                     output_path: Optional[str] = None,
                     format: str = 'json') -> str:
        """
        Export analysis report to file
        
        Args:
            analysis_result: Analysis result from any analyze_* method
            output_path: Optional output file path
            format: Output format (json, html, markdown)
            
        Returns:
            Path to exported report
        """
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = self.root_path / f"reachability_report_{timestamp}.{format}"
        else:
            output_path = Path(output_path)
        
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(analysis_result, f, indent=2)
        elif format == 'markdown':
            content = self._generate_markdown_report(analysis_result)
            with open(output_path, 'w') as f:
                f.write(content)
        elif format == 'html':
            # TODO: Implement HTML report generation
            raise NotImplementedError("HTML format not yet implemented")
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        print(f"[Coordinator] Report exported to: {output_path}")
        return str(output_path)
    
    def _detect_entry_points(self, language: str) -> List[str]:
        """Auto-detect common entry points based on language"""
        entry_points = {
            'python': ['app.route', 'api_view', 'main', 'handler'],
            'javascript': ['app.get', 'app.post', 'router.get', 'router.post', 'exports'],
            'java': ['@RequestMapping', '@GetMapping', '@PostMapping', 'main']
        }
        
        return entry_points.get(language, ['main'])
    
    def _generate_markdown_report(self, result: Dict[str, Any]) -> str:
        """Generate markdown format report"""
        lines = []
        
        lines.append("# Vulnerability Reachability Analysis Report")
        lines.append("")
        lines.append(f"**Generated:** {result.get('analysis_timestamp', 'N/A')}")
        lines.append(f"**Project:** {result.get('project_path', 'N/A')}")
        lines.append("")
        
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Dependencies:** {result.get('dependencies_checked', 0)}")
        lines.append(f"- **Total Vulnerabilities:** {result.get('total_vulnerabilities', 0)}")
        lines.append(f"- **Reachable Vulnerabilities:** {result.get('reachable_vulnerabilities', 0)}")
        lines.append(f"- **High Confidence Reachable:** {result.get('high_confidence_reachable', 0)}")
        lines.append("")
        
        summary = result.get('summary', {})
        lines.append(f"**Risk Level:** {summary.get('risk_level', 'unknown').upper()}")
        lines.append("")
        lines.append(f"**Recommendation:** {summary.get('recommendation', 'N/A')}")
        lines.append("")
        
        findings = result.get('findings', [])
        if findings:
            lines.append("## Detailed Findings")
            lines.append("")
            
            for i, finding in enumerate(findings, 1):
                lines.append(f"### {i}. {finding.get('vulnerability_id', 'UNKNOWN')}")
                lines.append("")
                lines.append(f"- **Package:** {finding.get('package', 'N/A')}")
                lines.append(f"- **Severity:** {finding.get('severity', 'UNKNOWN')}")
                lines.append(f"- **Reachable:** {'✅ Yes' if finding.get('reachable') else '❌ No'}")
                lines.append(f"- **Confidence:** {finding.get('confidence', 'N/A')}")
                lines.append(f"- **Reason:** {finding.get('reason', 'N/A')}")
                
                if finding.get('summary'):
                    lines.append(f"- **Summary:** {finding['summary']}")
                
                lines.append("")
        
        return "\n".join(lines)
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get status of all agents"""
        return {
            'agents': {
                name: {
                    'capabilities': agent.get_capabilities(),
                    'status': 'active'
                }
                for name, agent in self.agents.items()
            },
            'analysis_history_count': len(self.analysis_history)
        }

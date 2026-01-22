"""
Tainter Agent - Integrates tainter CLI for taint analysis
"""

import json
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path


class TainterAgent:
    """
    Agent that wraps the tainter CLI tool for comprehensive taint analysis.
    Provides source-to-sink vulnerability flow detection.
    """

    # Map tainter vuln classes to CWE IDs
    VULN_CLASS_TO_CWE = {
        'SQLI': 'CWE-89',
        'RCE': 'CWE-78',
        'SSTI': 'CWE-94',
        'SSRF': 'CWE-918',
        'DESERIALIZE': 'CWE-502',
        'PATH_TRAVERSAL': 'CWE-22',
        'XSS': 'CWE-79',
    }

    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self._verify_tainter_installed()

    def _verify_tainter_installed(self):
        """Check if tainter CLI is available"""
        try:
            result = subprocess.run(
                ['tainter', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("Tainter CLI not found or not working")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise RuntimeError(f"Tainter CLI not available: {e}")

    def analyze(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute tainter analysis task

        Supported task types:
        - scan_project: Full project scan
        - scan_package: Scan specific package/module
        - scan_vuln_class: Scan for specific vulnerability class
        - check_cve_reachability: Check if CVE is reachable via taint flows
        """
        task_type = task.get('type')
        params = task.get('params', {})

        if task_type == 'scan_project':
            return self._scan_project(params)
        elif task_type == 'scan_package':
            return self._scan_package(params)
        elif task_type == 'scan_vuln_class':
            return self._scan_vuln_class(params)
        elif task_type == 'check_cve_reachability':
            return self._check_cve_reachability(params)
        elif task_type == 'list_sources':
            return self._list_sources()
        elif task_type == 'list_sinks':
            return self._list_sinks()
        else:
            raise ValueError(f"Unknown task type: {task_type}")

    def _scan_project(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run full tainter scan on project

        Args:
            params:
                - path: Optional custom path (defaults to root_path)
                - vuln_classes: Optional list of vuln classes to scan
                - include_tests: Whether to include test files
                - max_files: Maximum files to analyze
        """
        scan_path = params.get('path', str(self.root_path))
        vuln_classes = params.get('vuln_classes', [])
        include_tests = params.get('include_tests', False)
        max_files = params.get('max_files')

        cmd = ['tainter', 'scan', scan_path, '--format', 'json']

        if vuln_classes:
            for vc in vuln_classes:
                cmd.extend(['--vuln-class', vc.lower()])

        if include_tests:
            cmd.append('--include-tests')
        else:
            cmd.append('--no-include-tests')

        if max_files:
            cmd.extend(['--max-files', str(max_files)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Tainter returns exit code 1 when vulnerabilities are found
            # So we check if we have valid JSON output rather than just exit code
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If we can't parse JSON, then it's a real error
                return {
                    'agent': 'TainterAgent',
                    'success': False,
                    'error': result.stderr or result.stdout or 'Failed to parse tainter output',
                    'flows': []
                }


            return {
                'agent': 'TainterAgent',
                'success': True,
                'summary': data.get('summary', {}),
                'flows': data.get('flows', []),
                'total_flows': data.get('summary', {}).get('flows_detected', 0),
                'files_analyzed': data.get('summary', {}).get('files_analyzed', 0)
            }

        except subprocess.TimeoutExpired:
            return {
                'agent': 'TainterAgent',
                'success': False,
                'error': 'Tainter scan timeout after 5 minutes',
                'flows': []
            }
        except Exception as e:
            return {
                'agent': 'TainterAgent',
                'success': False,
                'error': f'Unexpected error during tainter scan: {e}',
                'flows': []
            }

    def _scan_package(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan specific package/module directory

        Args:
            params:
                - package_path: Path to package directory
                - vuln_classes: Optional list of vuln classes
        """
        package_path = params.get('package_path')
        if not package_path:
            return {
                'agent': 'TainterAgent',
                'success': False,
                'error': 'package_path required',
                'flows': []
            }

        return self._scan_project({
            'path': package_path,
            'vuln_classes': params.get('vuln_classes', [])
        })

    def _scan_vuln_class(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan for specific vulnerability class

        Args:
            params:
                - vuln_class: Vulnerability class (SQLI, XSS, etc.)
                - path: Optional path
        """
        vuln_class = params.get('vuln_class')
        if not vuln_class:
            return {
                'agent': 'TainterAgent',
                'success': False,
                'error': 'vuln_class required',
                'flows': []
            }

        return self._scan_project({
            'path': params.get('path', str(self.root_path)),
            'vuln_classes': [vuln_class]
        })

    def _check_cve_reachability(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if a CVE's vulnerability pattern is reachable via taint flows

        Args:
            params:
                - cve_details: CVE information including CWE
                - package_name: Package name
                - vulnerable_functions: List of vulnerable function names
        """
        cve_details = params.get('cve_details', {})
        package_name = params.get('package_name')
        vulnerable_functions = params.get('vulnerable_functions', [])

        # Map CWE to tainter vuln class
        cwe_id = cve_details.get('cwe_id', '')
        vuln_class = None

        for vc, cwe in self.VULN_CLASS_TO_CWE.items():
            if cwe == cwe_id:
                vuln_class = vc
                break

        if not vuln_class:
            # Run full scan if CWE mapping not found
            scan_result = self._scan_project({})
        else:
            # Scan for specific vuln class
            scan_result = self._scan_vuln_class({
                'vuln_class': vuln_class
            })

        if not scan_result.get('success'):
            return scan_result

        # Filter flows relevant to the CVE
        relevant_flows = []
        all_flows = scan_result.get('flows', [])

        for flow in all_flows:
            # Check if flow involves vulnerable functions
            if vulnerable_functions:
                call_chain = flow.get('call_chain', [])
                if any(vf in str(call_chain) for vf in vulnerable_functions):
                    relevant_flows.append(flow)
            # Check if flow matches vulnerability class
            elif vuln_class and flow.get('vulnerability_class') == vuln_class:
                relevant_flows.append(flow)

        return {
            'agent': 'TainterAgent',
            'success': True,
            'cve_id': cve_details.get('cve_id'),
            'package_name': package_name,
            'reachable': len(relevant_flows) > 0,
            'confidence': self._calculate_confidence(relevant_flows),
            'relevant_flows': relevant_flows,
            'total_flows_checked': len(all_flows)
        }

    def _calculate_confidence(self, flows: List[Dict]) -> str:
        """
        Calculate confidence level based on flow analysis

        Returns: 'high', 'medium', 'low', or 'none'
        """
        if not flows:
            return 'none'

        high_confidence_count = sum(
            1 for flow in flows
            if flow.get('confidence', '').upper() == 'HIGH'
        )

        if high_confidence_count > 0:
            return 'high'
        elif len(flows) > 2:
            return 'medium'
        else:
            return 'low'

    def _list_sources(self) -> Dict[str, Any]:
        """List all available taint sources"""
        try:
            result = subprocess.run(
                ['tainter', 'list-sources'],
                capture_output=True,
                text=True,
                timeout=10
            )

            return {
                'agent': 'TainterAgent',
                'success': True,
                'sources': result.stdout
            }
        except Exception as e:
            return {
                'agent': 'TainterAgent',
                'success': False,
                'error': str(e)
            }

    def _list_sinks(self) -> Dict[str, Any]:
        """List all available taint sinks"""
        try:
            result = subprocess.run(
                ['tainter', 'list-sinks'],
                capture_output=True,
                text=True,
                timeout=10
            )

            return {
                'agent': 'TainterAgent',
                'success': True,
                'sinks': result.stdout
            }
        except Exception as e:
            return {
                'agent': 'TainterAgent',
                'success': False,
                'error': str(e)
            }

    def get_capabilities(self) -> List[str]:
        """Return list of agent capabilities"""
        return [
            'scan_project',
            'scan_package',
            'scan_vuln_class',
            'check_cve_reachability',
            'list_sources',
            'list_sinks'
        ]

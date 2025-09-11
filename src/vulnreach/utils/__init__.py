# utils/__init__.py
from .get_metadata import get_package_mappings
from .vuln_reachability_analyzer import run_reachability_analysis, VulnReachabilityAnalyzer
from .exploitability_analyzer import ExploitabilityAnalyzer

def run_exploitability_analysis(vulnerabilities, output_path):
    """Run exploitability analysis on a list of vulnerabilities"""
    analyzer = ExploitabilityAnalyzer()
    analyses = analyzer.analyze_vulnerability_batch(vulnerabilities)
    report = analyzer.generate_exploitability_report(analyses, output_path)
    analyzer.print_exploitability_summary(analyses)
    return report

__all__ = ['get_package_mappings', 'run_reachability_analysis', 'VulnReachabilityAnalyzer', 'run_exploitability_analysis', 'ExploitabilityAnalyzer']
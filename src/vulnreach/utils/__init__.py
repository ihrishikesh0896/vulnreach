# utils/__init__.py
from .get_metadata import get_package_mappings
from .python_reachability_analyzer import run_python_reachability_analysis, PythonReachabilityAnalyzer
from .exploitability_analyzer import ExploitabilityAnalyzer
from .csharp_reachability_analyzer import run_csharp_reachability_analysis, CSharpReachabilityAnalyzer
from .go_reachability_analyzer import run_go_reachability_analysis, GoReachabilityAnalyzer
from .java_reachability_analyzer import run_java_reachability_analysis, JavaReachabilityAnalyzer
from .javascript_reachability_analyzer import run_javascript_reachability_analysis, JavaScriptReachabilityAnalyzer
from .php_reachability_analyzer import run_php_reachability_analysis, PHPReachabilityAnalyzer


# Keep backward compatibility aliases
run_reachability_analysis = run_python_reachability_analysis
# VulnReachabilityAnalyzer = PythonReachab ilityAnalyzer

def run_exploitability_analysis(vulnerabilities, output_path):
    """Run exploitability analysis on a list of vulnerabilities"""
    analyzer = ExploitabilityAnalyzer()
    analyses = analyzer.analyze_vulnerability_batch(vulnerabilities)
    report = analyzer.generate_exploitability_report(analyses, output_path)
    analyzer.print_exploitability_summary(analyses)
    return report

__all__ = [
    'get_package_mappings',
    'run_reachability_analysis',  # Backward compatibility
    'run_python_reachability_analysis',  # New name
    'run_exploitability_analysis',
    'ExploitabilityAnalyzer',
    'go_reachability_analyzer',
    'java_reachability_analyzer',
    'javascript_reachability_analyzer',
    'python_reachability_analyzer',
    'csharp_reachability_analyzer',
    'php_reachability_analyzer',
]

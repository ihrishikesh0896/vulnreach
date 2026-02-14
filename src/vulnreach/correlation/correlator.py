"""Correlation Engine for Static and Dynamic Findings

This module correlates:
1. Static findings (vulnerabilities from Trivy/Semgrep)
2. Dynamic findings (runtime behavior from hooks)

The correlation reduces false positives by:
- Confirming vulnerable packages are actually loaded at runtime
- Identifying if vulnerable code paths are executed
- Detecting if vulnerable functions are called
- Validating exploit conditions are met

Verdict categories:
- CONFIRMED: Strong evidence from both static and dynamic
- LIKELY: Evidence from one source, indicators from another
- POSSIBLE: Static finding only, no runtime evidence
- UNLIKELY: Static finding contradicted by runtime behavior
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class CorrelatedFinding:
    """Represents a correlated static + dynamic finding"""
    vulnerability_id: str
    package_name: str
    package_version: str
    severity: str
    verdict: str  # CONFIRMED, LIKELY, POSSIBLE, UNLIKELY
    confidence: str  # HIGH, MEDIUM, LOW
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW
    
    # Static evidence
    static_evidence: Dict[str, Any]
    
    # Dynamic evidence (if any)
    dynamic_evidence: Optional[Dict[str, Any]] = None
    
    # Correlation metadata
    correlation_reason: Optional[str] = None
    runtime_loaded: bool = False
    sink_executed: bool = False
    exploit_path_active: bool = False


class FindingCorrelator:
    """Correlates static and dynamic findings"""
    
    # Mapping from PyPI package names to import names
    PACKAGE_IMPORT_MAP = {
        'pyyaml': ['yaml'],
        'pillow': ['PIL'],
        'beautifulsoup4': ['bs4'],
        'python-dateutil': ['dateutil'],
        'msgpack-python': ['msgpack'],
        'pyopenssl': ['OpenSSL'],
        'pycrypto': ['Crypto'],
        'scikit-learn': ['sklearn'],
        'protobuf': ['google.protobuf'],
        'attrs': ['attr'],
    }

    def __init__(self, project_findings_dir: str):
        self.project_findings_dir = Path(project_findings_dir)
        
    def correlate_findings(
        self,
        static_findings: List[Dict[str, Any]],
        dynamic_findings: Optional[Dict[str, Any]] = None
    ) -> List[CorrelatedFinding]:
        """
        Correlate static vulnerabilities with dynamic runtime data
        
        Args:
            static_findings: List of vulnerabilities from Trivy/Semgrep
            dynamic_findings: Optional dynamic analysis results
            
        Returns:
            List of correlated findings with verdicts
        """
        correlated = []
        
        # Extract runtime context if available
        runtime_packages = set()
        runtime_sinks = {}
        
        if dynamic_findings:
            findings_list = dynamic_findings.get("findings", [])
            
            # Build runtime package set
            for finding in findings_list:
                if finding.get("finding_type") == "import" and finding.get("package_name"):
                    runtime_packages.add(finding["package_name"])
            
            # Build sink execution map
            for finding in findings_list:
                if finding.get("finding_type") == "sink":
                    pkg = finding.get("package_name", "unknown")
                    func = finding.get("function_name", "unknown")
                    key = f"{pkg}:{func}"
                    runtime_sinks[key] = finding
        
        # Process each static finding
        for static_finding in static_findings:
            pkg_name = static_finding.get("pkg_name", "")
            vuln_id = static_finding.get("vulnerability_id", "")
            severity = static_finding.get("severity", "UNKNOWN")
            
            # Correlate with runtime data
            runtime_loaded = self._check_runtime_loaded(pkg_name, runtime_packages)
            sink_executed = self._check_sink_executed(pkg_name, runtime_sinks)
            
            # Determine verdict
            verdict, confidence, priority, reason = self._determine_verdict(
                static_finding, runtime_loaded, sink_executed, dynamic_findings is not None
            )
            
            # Build dynamic evidence
            dynamic_evidence = None
            if runtime_loaded or sink_executed:
                dynamic_evidence = {
                    "package_loaded": runtime_loaded,
                    "sink_executed": sink_executed,
                    "execution_count": len([s for s in runtime_sinks.values() 
                                          if pkg_name in s.get("package_name", "")])
                }
            
            correlated.append(CorrelatedFinding(
                vulnerability_id=vuln_id,
                package_name=pkg_name,
                package_version=static_finding.get("pkg_version", ""),
                severity=severity,
                verdict=verdict,
                confidence=confidence,
                priority=priority,
                static_evidence={
                    "title": static_finding.get("title", ""),
                    "description": static_finding.get("description", ""),
                    "cvss_score": static_finding.get("cvss_score"),
                    "cwe_ids": static_finding.get("cwe_ids", []),
                    "fixed_version": static_finding.get("fixed_version"),
                },
                dynamic_evidence=dynamic_evidence,
                correlation_reason=reason,
                runtime_loaded=runtime_loaded,
                sink_executed=sink_executed,
                exploit_path_active=sink_executed  # Simplified - can be enhanced
            ))
        
        return correlated
    
    def _check_runtime_loaded(self, pkg_name: str, runtime_packages: Set[str]) -> bool:
        """Check if package was loaded at runtime"""
        if not runtime_packages:
            return False
        
        # Direct match
        if pkg_name in runtime_packages:
            return True
        
        # Check package name variations (e.g., "requests" vs "python-requests")
        pkg_normalized = pkg_name.lower().replace("-", "").replace("_", "")
        for runtime_pkg in runtime_packages:
            runtime_normalized = runtime_pkg.lower().replace("-", "").replace("_", "")
            if pkg_normalized == runtime_normalized:
                return True

        # Check import name mapping (e.g., "pyyaml" -> "yaml")
        pkg_lower = pkg_name.lower()
        if pkg_lower in self.PACKAGE_IMPORT_MAP:
            import_names = self.PACKAGE_IMPORT_MAP[pkg_lower]
            for import_name in import_names:
                if import_name in runtime_packages:
                    return True
                # Also check if runtime package starts with import name (for submodules)
                for runtime_pkg in runtime_packages:
                    if runtime_pkg.startswith(import_name + '.'):
                        return True

        return False
    
    def _check_sink_executed(self, pkg_name: str, runtime_sinks: Dict[str, Any]) -> bool:
        """Check if vulnerable sinks were executed"""
        if not runtime_sinks:
            return False
        
        # Check if any sink belongs to this package
        for sink_key, sink_data in runtime_sinks.items():
            if pkg_name in sink_key:
                return True
        
        return False
    
    def _determine_verdict(
        self,
        static_finding: Dict[str, Any],
        runtime_loaded: bool,
        sink_executed: bool,
        has_dynamic_data: bool
    ) -> tuple[str, str, str, str]:
        """
        Determine verdict, confidence, priority, and reasoning
        
        Returns:
            (verdict, confidence, priority, reason)
        """
        severity = static_finding.get("severity", "UNKNOWN")
        
        # No dynamic analysis run - default to POSSIBLE
        if not has_dynamic_data:
            priority = self._severity_to_priority(severity)
            return (
                "POSSIBLE",
                "LOW",
                priority,
                "No dynamic analysis performed - verdict based on static analysis only"
            )
        
        # Strong evidence from both static and dynamic
        if runtime_loaded and sink_executed:
            return (
                "CONFIRMED",
                "HIGH",
                "CRITICAL" if severity in ["CRITICAL", "HIGH"] else "HIGH",
                "Package loaded at runtime AND vulnerable code path executed"
            )
        
        # Package loaded but no sink execution detected
        if runtime_loaded:
            priority = self._severity_to_priority(severity)
            return (
                "LIKELY",
                "MEDIUM",
                priority,
                "Package loaded at runtime but vulnerable code path not observed"
            )
        
        # Package not loaded at runtime
        return (
            "UNLIKELY",
            "MEDIUM",
            "LOW",
            "Package not observed in runtime execution - may be unused or conditionally loaded"
        )
    
    def _severity_to_priority(self, severity: str) -> str:
        """Map CVE severity to priority"""
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "UNKNOWN": "MEDIUM"
        }
        return severity_map.get(severity.upper(), "MEDIUM")
    
    def save_correlated_findings(self, findings: List[CorrelatedFinding], output_path: Optional[str] = None) -> str:
        """Save correlated findings to JSON file"""
        if output_path is None:
            output_path = self.project_findings_dir / "correlated_findings.json"
        else:
            output_path = Path(output_path)
        
        # Convert to dict
        findings_dict = [asdict(f) for f in findings]
        
        # Add metadata
        output_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(findings),
                "verdicts": self._count_verdicts(findings),
                "priorities": self._count_priorities(findings)
            },
            "findings": findings_dict
        }
        
        # Save to file
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        return str(output_path)
    
    def _count_verdicts(self, findings: List[CorrelatedFinding]) -> Dict[str, int]:
        """Count findings by verdict"""
        counts = {}
        for finding in findings:
            verdict = finding.verdict
            counts[verdict] = counts.get(verdict, 0) + 1
        return counts
    
    def _count_priorities(self, findings: List[CorrelatedFinding]) -> Dict[str, int]:
        """Count findings by priority"""
        counts = {}
        for finding in findings:
            priority = finding.priority
            counts[priority] = counts.get(priority, 0) + 1
        return counts


def run_correlation_pipeline(
    project_findings_dir: str,
    static_findings: List[Dict[str, Any]],
    dynamic_results: Optional[Dict[str, Any]] = None,
    skip_correlation: bool = False
) -> Optional[List[CorrelatedFinding]]:
    """
    Run the complete correlation pipeline
    
    Args:
        project_findings_dir: Directory containing findings
        static_findings: List of static vulnerabilities
        dynamic_results: Optional dynamic analysis results
        skip_correlation: If True, skip correlation and return None
        
    Returns:
        List of correlated findings or None if skipped
    """
    if skip_correlation:
        print("\n⚠️  Correlation analysis skipped (--no-correlation flag)")
        return None
    
    print("\n🔗 Running correlation analysis...")
    
    try:
        correlator = FindingCorrelator(project_findings_dir)
        correlated = correlator.correlate_findings(static_findings, dynamic_results)
        
        # Save results
        output_path = correlator.save_correlated_findings(correlated)
        
        # Print summary
        print(f"✅ Correlated {len(correlated)} findings")
        print(f"📁 Saved to: {output_path}")
        
        # Print verdict breakdown
        verdicts = correlator._count_verdicts(correlated)
        priorities = correlator._count_priorities(correlated)
        
        print(f"\n📊 Correlation Summary:")
        print(f"   Verdicts:")
        for verdict, count in verdicts.items():
            print(f"     - {verdict}: {count}")
        
        print(f"   Priorities:")
        for priority, count in priorities.items():
            print(f"     - {priority}: {count}")
        
        return correlated
        
    except Exception as e:
        print(f"❌ Correlation analysis failed: {e}")
        return None

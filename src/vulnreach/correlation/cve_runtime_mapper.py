"""CVE Runtime Mapper - Correlate CVEs with runtime behavior

Maps CVE-affected packages and functions to actual runtime sink events
to determine if vulnerabilities were actually triggered.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from collections import defaultdict

from vulnreach.rbom.schema import (
    Confidence,
    ReachabilityVerdict,
    RuntimeEvidence,
    StaticEvidence,
)


class CVERuntimeMapper:
    """Maps CVEs to runtime behavior for reachability analysis"""

    def __init__(self):
        self.sink_categories = {
            "eval": "CODE_INJECTION",
            "exec": "CODE_INJECTION",
            "subprocess.Popen": "COMMAND_INJECTION",
            "open": "FILE_ACCESS",
            "sqlite3.Cursor.execute": "SQL_INJECTION",
            "urllib.request.urlopen": "SSRF",
            "socket.connect": "NETWORK_ACCESS",
        }

    def calculate_reachability(
        self,
        cve_id: str,
        package_name: str,
        package_version: str,
        runtime_correlation: Optional[Dict[str, Any]],
        static_analysis: Optional[Dict[str, Any]] = None
    ) -> tuple[ReachabilityVerdict, Confidence, RuntimeEvidence, Optional[StaticEvidence]]:
        """Calculate reachability verdict and confidence for a CVE

        Args:
            cve_id: CVE identifier
            package_name: Affected package name
            package_version: Affected package version
            runtime_correlation: Correlation data from event matcher
            static_analysis: Optional static analysis results

        Returns:
            Tuple of (verdict, confidence, runtime_evidence, static_evidence)
        """
        # Initialize evidence
        runtime_evidence = RuntimeEvidence(
            package_loaded=False,
            function_called=False
        )

        static_evidence = None
        if static_analysis:
            static_evidence = StaticEvidence(
                call_chain_exists=static_analysis.get('call_chain_exists', False),
                entry_points=static_analysis.get('entry_points', []),
                call_chains=static_analysis.get('call_chains', []),
                vulnerable_functions=static_analysis.get('vulnerable_functions', []),
                import_detected=static_analysis.get('import_detected', False)
            )

        # Check if package was loaded at runtime
        if not runtime_correlation:
            # No runtime evidence - not loaded
            return (
                ReachabilityVerdict.NOT_REACHABLE,
                Confidence.NONE,
                runtime_evidence,
                static_evidence
            )

        # Package was imported at runtime
        runtime_evidence.package_loaded = True
        runtime_evidence.load_events = runtime_correlation.get('import_events', [])

        # Check if any dangerous functions were called
        sink_events = self._find_relevant_sinks(
            package_name,
            runtime_correlation.get('import_events', [])
        )

        if sink_events:
            runtime_evidence.function_called = True
            runtime_evidence.sink_events = sink_events
            runtime_evidence.stack_traces = [
                event.get('data', {}).get('stack', [])
                for event in sink_events
            ]

        # Calculate verdict and confidence
        verdict, confidence = self._calculate_verdict_and_confidence(
            runtime_evidence,
            static_evidence,
            runtime_correlation.get('confidence', 0.8)
        )

        return verdict, confidence, runtime_evidence, static_evidence

    def _find_relevant_sinks(
        self,
        package_name: str,
        import_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find sink events potentially related to this package

        This is a heuristic - we look for sink events that occurred
        after the package was imported.
        """
        # For now, return empty list
        # In a full implementation, we'd correlate timestamps and stack traces
        return []

    def _calculate_verdict_and_confidence(
        self,
        runtime_evidence: RuntimeEvidence,
        static_evidence: Optional[StaticEvidence],
        import_confidence: float
    ) -> tuple[ReachabilityVerdict, Confidence]:
        """Calculate reachability verdict and confidence level

        Decision matrix:
        - Package not loaded: NOT_REACHABLE, NONE
        - Package loaded + function called + stack trace: REACHABLE, HIGH
        - Package loaded + call chain exists: REACHABLE, MEDIUM
        - Package loaded only: UNKNOWN, LOW
        """
        if not runtime_evidence.package_loaded:
            return ReachabilityVerdict.NOT_REACHABLE, Confidence.NONE

        # Calculate confidence score
        score = 0.0

        # Package loaded (base score)
        score += 0.3

        # Import confidence
        score += import_confidence * 0.2

        # Function called
        if runtime_evidence.function_called:
            score += 0.5

        # Static evidence
        if static_evidence:
            if static_evidence.call_chain_exists:
                score += 0.2
            if static_evidence.import_detected:
                score += 0.1

        # Determine verdict
        if runtime_evidence.function_called:
            verdict = ReachabilityVerdict.REACHABLE
        elif static_evidence and static_evidence.call_chain_exists:
            verdict = ReachabilityVerdict.REACHABLE
        elif runtime_evidence.package_loaded:
            verdict = ReachabilityVerdict.UNKNOWN
        else:
            verdict = ReachabilityVerdict.NOT_REACHABLE

        # Map score to confidence level
        if score >= 0.8:
            confidence = Confidence.HIGH
        elif score >= 0.5:
            confidence = Confidence.MEDIUM
        elif score >= 0.2:
            confidence = Confidence.LOW
        else:
            confidence = Confidence.NONE

        return verdict, confidence

    def batch_calculate_reachability(
        self,
        vulnerabilities: List[Dict[str, Any]],
        correlations: Dict[str, Dict[str, Any]],
        static_results: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Dict[str, tuple[ReachabilityVerdict, Confidence, RuntimeEvidence, Optional[StaticEvidence]]]:
        """Calculate reachability for multiple CVEs

        Args:
            vulnerabilities: List of vulnerability dicts
            correlations: Runtime correlation results (package_name -> correlation_data)
            static_results: Optional static analysis results (package_name -> analysis_data)

        Returns:
            Dict mapping CVE IDs to (verdict, confidence, runtime_evidence, static_evidence)
        """
        results = {}

        for vuln in vulnerabilities:
            cve_id = vuln.get('vulnerability_id', vuln.get('cve_id', ''))
            package_name = vuln.get('pkg_name', vuln.get('package_name', ''))
            package_version = vuln.get('pkg_version', vuln.get('package_version', ''))

            # Get correlation for this package
            correlation = correlations.get(package_name)

            # Get static analysis for this package
            static = None
            if static_results:
                static = static_results.get(package_name)

            # Calculate reachability
            verdict, confidence, runtime_ev, static_ev = self.calculate_reachability(
                cve_id,
                package_name,
                package_version,
                correlation,
                static
            )

            results[cve_id] = (verdict, confidence, runtime_ev, static_ev)

        return results


def correlate_cves_with_runtime(
    vulnerabilities: List[Dict[str, Any]],
    runtime_correlations: Dict[str, Dict[str, Any]],
    static_results: Optional[Dict[str, Dict[str, Any]]] = None
) -> Dict[str, tuple[ReachabilityVerdict, Confidence, RuntimeEvidence, Optional[StaticEvidence]]]:
    """Convenience function to correlate CVEs with runtime behavior

    Args:
        vulnerabilities: List of vulnerabilities
        runtime_correlations: Results from event matcher
        static_results: Optional static analysis results

    Returns:
        Dict mapping CVE IDs to reachability analysis results
    """
    mapper = CVERuntimeMapper()
    return mapper.batch_calculate_reachability(
        vulnerabilities,
        runtime_correlations,
        static_results
    )

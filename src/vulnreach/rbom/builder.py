"""RBOM Builder

Constructs RBOM from various analysis inputs:
- SBOM components
- Trivy vulnerabilities
- Static analysis results
- Runtime events
- Correlation results
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from pathlib import Path
import time

from vulnreach.rbom.schema import (
    RBOM,
    RBOMComponent,
    RBOMTarget,
    VulnerabilityReachability,
    RuntimeEvidence,
    StaticEvidence,
    ExploitEvidence,
    ExecutionSummary,
    Confidence,
    ReachabilityVerdict,
    Priority,
)


class RBOMBuilder:
    """Builds RBOM from analysis inputs"""

    def __init__(self):
        self.rbom = RBOM()
        self._components_map: Dict[str, RBOMComponent] = {}
        self._start_time = time.time()

    def set_target(
        self,
        path: str,
        target_type: str = "directory",
        language: Optional[str] = None,
        framework: Optional[str] = None,
        git_url: Optional[str] = None,
        git_commit: Optional[str] = None
    ) -> 'RBOMBuilder':
        """Set target information"""
        self.rbom.target = RBOMTarget(
            path=path,
            type=target_type,
            language=language,
            framework=framework,
            git_url=git_url,
            git_commit=git_commit
        )
        return self

    def add_sbom_components(self, sbom_components: List[Dict[str, Any]]) -> 'RBOMBuilder':
        """Add components from SBOM

        Args:
            sbom_components: List of components from Syft SBOM
        """
        for component in sbom_components:
            component_name = component.get('name', '')
            component_version = component.get('version', '')

            rbom_component = RBOMComponent(
                name=component_name,
                version=component_version,
                type=component.get('type', 'library'),
                language=component.get('language'),
                purl=component.get('purl'),
                cpe=component.get('cpe'),
                locations=component.get('locations', []),
                sbom_present=True,
                sbom_source="syft"
            )

            key = f"{component_name}@{component_version}"
            self._components_map[key] = rbom_component

        return self

    def add_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> 'RBOMBuilder':
        """Add vulnerabilities from Trivy scan

        Args:
            vulnerabilities: List of vulnerabilities from Trivy
        """
        for vuln in vulnerabilities:
            pkg_name = vuln.get('pkg_name', '')
            pkg_version = vuln.get('pkg_version', '')
            key = f"{pkg_name}@{pkg_version}"

            # Find or create component
            if key not in self._components_map:
                # Create component if not in SBOM (shouldn't happen normally)
                self._components_map[key] = RBOMComponent(
                    name=pkg_name,
                    version=pkg_version,
                    sbom_present=False
                )

            component = self._components_map[key]

            # Create vulnerability reachability entry
            vuln_reach = VulnerabilityReachability(
                cve_id=vuln.get('vulnerability_id', ''),
                package_name=pkg_name,
                package_version=pkg_version,
                severity=vuln.get('severity', 'UNKNOWN'),
                cvss_score=vuln.get('cvss_score'),
                fixed_version=vuln.get('fixed_version'),
                verdict=ReachabilityVerdict.UNKNOWN,  # Will be updated by correlation
                confidence=Confidence.NONE,  # Will be updated by correlation
            )

            component.vulnerabilities.append(vuln_reach)

        return self

    def add_runtime_evidence(
        self,
        runtime_events: List[Dict[str, Any]],
        correlation_map: Optional[Dict[str, List[Dict[str, Any]]]] = None
    ) -> 'RBOMBuilder':
        """Add runtime evidence from runtime_hooks

        Args:
            runtime_events: Events from runtime_hooks/runner.py
            correlation_map: Optional mapping of package names to events
        """
        if not runtime_events:
            return self

        # If no correlation map provided, try to build one
        if correlation_map is None:
            correlation_map = self._build_correlation_map(runtime_events)

        # Update components with runtime evidence
        for key, component in self._components_map.items():
            package_name = component.name

            # Check if this package was loaded at runtime
            if package_name in correlation_map:
                component.runtime_loaded = True
                component.runtime_evidence = correlation_map[package_name]

        return self

    def _build_correlation_map(
        self,
        runtime_events: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Build correlation map from runtime events using sophisticated matching

        Uses the event_matcher from Phase 2 for accurate import → package correlation.
        """
        try:
            from vulnreach.correlation.event_matcher import EventMatcher

            # Get SBOM components from our map
            sbom_components = list(self._components_map.values())

            # Convert to dict format expected by matcher
            sbom_dicts = []
            for component in sbom_components:
                sbom_dicts.append({
                    'name': component.name,
                    'version': component.version,
                    'type': component.type
                })

            # Use event matcher for sophisticated correlation
            matcher = EventMatcher()
            correlations = matcher.match_import_events(runtime_events, sbom_dicts)

            # Convert correlations to the format expected by this builder
            correlation_map: Dict[str, List[Dict[str, Any]]] = {}

            for package_name, correlation_data in correlations.items():
                correlation_map[package_name] = correlation_data['import_events']

            return correlation_map

        except ImportError:
            # Fallback to simple heuristic if event_matcher not available
            correlation_map: Dict[str, List[Dict[str, Any]]] = {}

            for event in runtime_events:
                if event.get('type') == 'import':
                    module_name = event.get('data', {}).get('module', '')
                    if module_name:
                        # Simple heuristic: lowercase and remove underscores
                        normalized = module_name.lower().replace('_', '-')

                        if normalized not in correlation_map:
                            correlation_map[normalized] = []

                        correlation_map[normalized].append(event)

            return correlation_map

    def add_static_analysis(
        self,
        static_results: Dict[str, Any]
    ) -> 'RBOMBuilder':
        """Add static analysis results (call graphs, reachability)

        Args:
            static_results: Results from static analyzers
        """
        # This will be implemented when we integrate with existing
        # reachability analyzers
        # TODO: Parse call chains and update vulnerability reachability
        return self

    def add_exploitability_analysis(
        self,
        exploitability_results: List[Dict[str, Any]]
    ) -> 'RBOMBuilder':
        """Add exploitability analysis results

        Args:
            exploitability_results: Results from ExploitabilityAnalyzer
        """
        for result in exploitability_results:
            cve_id = result.get('vulnerability_id', '')
            pkg_name = result.get('package_name', '')
            pkg_version = result.get('package_version', '')

            # Find vulnerability
            key = f"{pkg_name}@{pkg_version}"
            if key in self._components_map:
                component = self._components_map[key]

                for vuln in component.vulnerabilities:
                    if vuln.cve_id == cve_id:
                        exploit_analysis = result.get('exploit_analysis', {})

                        vuln.exploit_evidence = ExploitEvidence(
                            exploits_available=exploit_analysis.get('exploits_found', 0) > 0,
                            exploit_count=exploit_analysis.get('exploits_found', 0),
                            exploit_sources=exploit_analysis.get('exploit_sources', []),
                            exploit_ids=exploit_analysis.get('exploit_ids', [])
                        )

        return self

    def update_reachability_verdicts(
        self,
        correlation_results: Dict[str, Any]
    ) -> 'RBOMBuilder':
        """Update reachability verdicts based on correlation results

        Uses sophisticated CVE → Runtime correlation from Phase 4.
        """
        try:
            from vulnreach.correlation.cve_runtime_mapper import CVERuntimeMapper
            from vulnreach.correlation.event_matcher import EventMatcher

            # Build runtime correlations if not provided
            runtime_correlations = correlation_results.get('runtime_correlations', {})

            if not runtime_correlations and correlation_results.get('runtime_events'):
                # Build correlations from runtime events
                sbom_dicts = []
                for component in self._components_map.values():
                    sbom_dicts.append({
                        'name': component.name,
                        'version': component.version
                    })

                matcher = EventMatcher()
                runtime_correlations = matcher.match_import_events(
                    correlation_results['runtime_events'],
                    sbom_dicts
                )

            # Use CVE runtime mapper for sophisticated reachability analysis
            mapper = CVERuntimeMapper()

            for component in self._components_map.values():
                # Get runtime correlation for this component
                correlation = runtime_correlations.get(component.name)

                # Update component runtime status
                if correlation:
                    component.runtime_loaded = True
                    component.runtime_evidence = correlation.get('import_events', [])

                # Calculate reachability for each vulnerability
                for vuln in component.vulnerabilities:
                    verdict, confidence, runtime_ev, static_ev = mapper.calculate_reachability(
                        vuln.cve_id,
                        component.name,
                        component.version,
                        correlation,
                        None  # Static analysis not yet integrated
                    )

                    vuln.verdict = verdict
                    vuln.confidence = confidence
                    vuln.dynamic_evidence = runtime_ev
                    vuln.static_evidence = static_ev

                    # Calculate priority
                    vuln.priority = vuln.calculate_priority()

            return self

        except ImportError:
            # Fallback to simple heuristics if correlation modules not available
            for component in self._components_map.values():
                for vuln in component.vulnerabilities:
                    # Simple heuristic
                    if component.runtime_loaded:
                        if component.runtime_evidence:
                            vuln.confidence = Confidence.MEDIUM
                            vuln.verdict = ReachabilityVerdict.REACHABLE
                        else:
                            vuln.confidence = Confidence.LOW
                            vuln.verdict = ReachabilityVerdict.UNKNOWN
                    else:
                        vuln.confidence = Confidence.NONE
                        vuln.verdict = ReachabilityVerdict.NOT_REACHABLE

                    # Calculate priority
                    vuln.priority = vuln.calculate_priority()

            return self

    def set_execution_summary(
        self,
        runtime_performed: bool = False,
        runtime_duration: Optional[float] = None,
        events_captured: Optional[Dict[str, int]] = None,
        errors: Optional[List[str]] = None
    ) -> 'RBOMBuilder':
        """Set execution summary"""
        self.rbom.execution_summary = ExecutionSummary(
            runtime_analysis_performed=runtime_performed,
            runtime_duration_seconds=runtime_duration,
            events_captured=events_captured or {},
            errors=errors or []
        )
        return self

    def build(self) -> RBOM:
        """Build and return the final RBOM"""
        # Set analysis duration
        self.rbom.analysis_duration_seconds = time.time() - self._start_time

        # Add all components to RBOM
        self.rbom.components = list(self._components_map.values())

        return self.rbom


def create_rbom_from_analysis(
    target_path: str,
    sbom_components: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    runtime_events: Optional[List[Dict[str, Any]]] = None,
    static_results: Optional[Dict[str, Any]] = None,
    exploitability_results: Optional[List[Dict[str, Any]]] = None,
    language: Optional[str] = None,
    framework: Optional[str] = None
) -> RBOM:
    """Convenience function to create RBOM from all analysis inputs

    Args:
        target_path: Path to analyzed target
        sbom_components: Components from SBOM
        vulnerabilities: Vulnerabilities from Trivy
        runtime_events: Optional runtime events from runtime_hooks
        static_results: Optional static analysis results
        exploitability_results: Optional exploitability analysis
        language: Optional detected language
        framework: Optional detected framework

    Returns:
        Complete RBOM object
    """
    builder = RBOMBuilder()

    # Set target
    builder.set_target(
        path=target_path,
        target_type="directory",
        language=language,
        framework=framework
    )

    # Add SBOM components
    builder.add_sbom_components(sbom_components)

    # Add vulnerabilities
    builder.add_vulnerabilities(vulnerabilities)

    # Add runtime evidence if available
    if runtime_events:
        builder.add_runtime_evidence(runtime_events)

        # Set execution summary
        event_counts = {}
        for event in runtime_events:
            event_type = event.get('type', 'unknown')
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

        builder.set_execution_summary(
            runtime_performed=True,
            events_captured=event_counts
        )

    # Add static analysis if available
    if static_results:
        builder.add_static_analysis(static_results)

    # Add exploitability if available
    if exploitability_results:
        builder.add_exploitability_analysis(exploitability_results)

    # Update reachability verdicts
    builder.update_reachability_verdicts({})

    return builder.build()

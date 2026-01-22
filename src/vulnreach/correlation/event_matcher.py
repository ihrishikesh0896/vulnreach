"""Event Matcher - Correlate runtime events with SBOM components

Matches runtime import events from runtime_hooks to SBOM components,
handling namespace packages and complex import patterns.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional, Set
from collections import defaultdict

from vulnreach.correlation.package_resolver import PackageResolver


class EventMatcher:
    """Matches runtime events to SBOM components"""

    def __init__(self):
        self.resolver = PackageResolver()
        self.match_cache: Dict[str, tuple[Optional[str], float]] = {}

    def match_import_events(
        self,
        runtime_events: List[Dict[str, Any]],
        sbom_components: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Match runtime import events to SBOM components

        Args:
            runtime_events: Events from runtime_hooks (JSON array)
            sbom_components: Components from SBOM

        Returns:
            Dict mapping package names to correlation data:
            {
                "Flask": {
                    "component": {...},
                    "import_events": [...],
                    "confidence": 1.0,
                    "match_type": "direct"
                }
            }
        """
        # Build SBOM lookup by normalized name
        sbom_lookup = self._build_sbom_lookup(sbom_components)

        # Extract import events
        import_events = [e for e in runtime_events if e.get('type') == 'import']

        # Group events by module
        events_by_module = defaultdict(list)
        for event in import_events:
            module_name = event.get('data', {}).get('module', '')
            if module_name:
                events_by_module[module_name].append(event)

        # Match each module to SBOM components
        correlations = {}

        for module_name, events in events_by_module.items():
            # Try to match this module to a package
            matched_pkg, confidence = self._match_module_to_package(
                module_name,
                sbom_lookup
            )

            if matched_pkg:
                # Get the component
                component = sbom_lookup[self.resolver.normalize_package_name(matched_pkg)]

                # Determine match type
                match_type = self._determine_match_type(confidence)

                correlations[matched_pkg] = {
                    "component": component,
                    "import_events": events,
                    "confidence": confidence,
                    "match_type": match_type,
                    "module_names": [module_name]
                }

        return correlations

    def _build_sbom_lookup(
        self,
        sbom_components: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Build a lookup dict of SBOM components by normalized name

        Returns:
            Dict mapping normalized package names to components
        """
        lookup = {}
        for component in sbom_components:
            name = component.get('name', '')
            if name:
                normalized = self.resolver.normalize_package_name(name)
                lookup[normalized] = component
        return lookup

    def _match_module_to_package(
        self,
        module_name: str,
        sbom_lookup: Dict[str, Dict[str, Any]]
    ) -> tuple[Optional[str], float]:
        """Match a module name to an SBOM package

        Returns:
            Tuple of (package_name, confidence_score)
        """
        # Check cache first
        if module_name in self.match_cache:
            return self.match_cache[module_name]

        # Use resolver to match
        result = self.resolver.match_package(module_name, sbom_lookup)

        # Cache the result
        self.match_cache[module_name] = result

        return result

    def _determine_match_type(self, confidence: float) -> str:
        """Determine match type from confidence score

        Returns:
            "direct", "submodule", "fuzzy", or "none"
        """
        if confidence >= 0.9:
            return "direct"
        elif confidence >= 0.7:
            return "submodule"
        elif confidence >= 0.5:
            return "fuzzy"
        else:
            return "none"

    def get_match_statistics(
        self,
        correlations: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate statistics about the matches

        Returns:
            Dict with match statistics
        """
        total_packages = len(correlations)

        match_types = defaultdict(int)
        confidence_sum = 0.0

        for correlation in correlations.values():
            match_type = correlation['match_type']
            confidence = correlation['confidence']

            match_types[match_type] += 1
            confidence_sum += confidence

        avg_confidence = confidence_sum / total_packages if total_packages > 0 else 0.0

        return {
            "total_packages_matched": total_packages,
            "match_types": dict(match_types),
            "average_confidence": avg_confidence,
            "high_confidence_matches": match_types.get('direct', 0) + match_types.get('submodule', 0)
        }

    def enrich_components_with_runtime_data(
        self,
        components: List[Dict[str, Any]],
        correlations: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich SBOM components with runtime correlation data

        Args:
            components: Original SBOM components
            correlations: Correlation results from match_import_events

        Returns:
            Enriched components with runtime_loaded and runtime_evidence fields
        """
        enriched = []

        for component in components:
            enriched_component = component.copy()
            package_name = component.get('name', '')

            # Check if this component has runtime correlation
            if package_name in correlations:
                correlation = correlations[package_name]

                enriched_component['runtime_loaded'] = True
                enriched_component['runtime_evidence'] = correlation['import_events']
                enriched_component['runtime_confidence'] = correlation['confidence']
                enriched_component['runtime_match_type'] = correlation['match_type']
            else:
                enriched_component['runtime_loaded'] = False
                enriched_component['runtime_evidence'] = []

            enriched.append(enriched_component)

        return enriched


def match_runtime_to_sbom(
    runtime_events: List[Dict[str, Any]],
    sbom_components: List[Dict[str, Any]]
) -> tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Convenience function to match runtime events to SBOM

    Args:
        runtime_events: Events from runtime_hooks
        sbom_components: Components from SBOM

    Returns:
        Tuple of (correlations, statistics)
    """
    matcher = EventMatcher()
    correlations = matcher.match_import_events(runtime_events, sbom_components)
    statistics = matcher.get_match_statistics(correlations)

    return correlations, statistics

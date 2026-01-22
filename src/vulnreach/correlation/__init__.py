"""Correlation Package

Static-Dynamic correlation logic for RBOM generation.

Modules:
- event_matcher: Match runtime imports to SBOM components
- package_resolver: Normalize package names
- cve_runtime_mapper: Map CVEs to runtime events
"""

from vulnreach.correlation.event_matcher import EventMatcher, match_runtime_to_sbom
from vulnreach.correlation.package_resolver import PackageResolver, resolve_import, match_import_to_sbom
from vulnreach.correlation.cve_runtime_mapper import CVERuntimeMapper, correlate_cves_with_runtime

__all__ = [
    "EventMatcher",
    "match_runtime_to_sbom",
    "PackageResolver",
    "resolve_import",
    "match_import_to_sbom",
    "CVERuntimeMapper",
    "correlate_cves_with_runtime",
]



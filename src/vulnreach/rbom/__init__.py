"""RBOM (Runtime Bill of Materials) Package

This package provides:
- RBOM schema and data models
- RBOM builder for constructing RBOM from analysis inputs
- RBOM serializer for JSON and Markdown output

Usage:
    from vulnreach.rbom import create_rbom_from_analysis, save_rbom

    rbom = create_rbom_from_analysis(
        target_path="/path/to/project",
        sbom_components=components,
        vulnerabilities=vulns,
        runtime_events=events
    )

    save_rbom(rbom, output_dir="security_findings")
"""

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

from vulnreach.rbom.builder import (
    RBOMBuilder,
    create_rbom_from_analysis,
)

from vulnreach.rbom.serializer import (
    RBOMSerializer,
    save_rbom,
)

__all__ = [
    # Schema classes
    "RBOM",
    "RBOMComponent",
    "RBOMTarget",
    "VulnerabilityReachability",
    "RuntimeEvidence",
    "StaticEvidence",
    "ExploitEvidence",
    "ExecutionSummary",
    "Confidence",
    "ReachabilityVerdict",
    "Priority",
    # Builder
    "RBOMBuilder",
    "create_rbom_from_analysis",
    # Serializer
    "RBOMSerializer",
    "save_rbom",
]

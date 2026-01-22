"""RBOM (Runtime Bill of Materials) Schema

This module defines the data models for RBOM - an enhanced SBOM with
runtime evidence and reachability analysis.

RBOM extends traditional SBOM by adding:
- Runtime activation status (was the component loaded?)
- Reachability verdicts (is the vulnerability reachable?)
- Confidence scores (how certain are we?)
- Evidence from static and dynamic analysis
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class Confidence(str, Enum):
    """Reachability confidence levels"""
    HIGH = "HIGH"       # Package imported + Function called + Stack trace
    MEDIUM = "MEDIUM"   # Package imported + Call chain exists
    LOW = "LOW"         # Package imported only
    NONE = "NONE"       # Package not imported


class ReachabilityVerdict(str, Enum):
    """Vulnerability reachability verdict"""
    REACHABLE = "REACHABLE"             # Confirmed reachable
    NOT_REACHABLE = "NOT_REACHABLE"     # Confirmed not reachable
    UNKNOWN = "UNKNOWN"                 # Insufficient evidence


class Priority(str, Enum):
    """Remediation priority based on severity + reachability"""
    CRITICAL = "CRITICAL"  # High severity + High confidence reachable
    HIGH = "HIGH"          # High severity + Medium confidence OR Medium severity + High confidence
    MEDIUM = "MEDIUM"      # Medium severity + Medium confidence
    LOW = "LOW"            # Low severity OR Low/None confidence
    INFO = "INFO"          # No severity OR Not reachable


@dataclass
class RuntimeEvidence:
    """Evidence collected from runtime analysis"""
    package_loaded: bool
    function_called: bool = False
    load_timestamp: Optional[str] = None
    load_events: List[Dict[str, Any]] = field(default_factory=list)
    sink_events: List[Dict[str, Any]] = field(default_factory=list)
    stack_traces: List[List[str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class StaticEvidence:
    """Evidence collected from static analysis"""
    call_chain_exists: bool
    entry_points: List[str] = field(default_factory=list)
    call_chains: List[List[str]] = field(default_factory=list)
    vulnerable_functions: List[str] = field(default_factory=list)
    import_detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class ExploitEvidence:
    """Evidence about public exploits"""
    exploits_available: bool
    exploit_count: int = 0
    exploit_sources: List[str] = field(default_factory=list)
    exploit_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class VulnerabilityReachability:
    """Reachability analysis for a specific vulnerability"""
    cve_id: str
    package_name: str
    package_version: str
    severity: str
    cvss_score: Optional[float] = None

    # Reachability analysis
    verdict: ReachabilityVerdict = ReachabilityVerdict.UNKNOWN
    confidence: Confidence = Confidence.NONE

    # Evidence
    static_evidence: Optional[StaticEvidence] = None
    dynamic_evidence: Optional[RuntimeEvidence] = None
    exploit_evidence: Optional[ExploitEvidence] = None

    # Remediation
    fixed_version: Optional[str] = None
    priority: Priority = Priority.INFO

    # Metadata
    analysis_timestamp: Optional[str] = None

    def calculate_priority(self) -> Priority:
        """Calculate remediation priority based on severity + reachability"""
        severity_score = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "UNKNOWN": 0
        }.get(self.severity.upper(), 0)

        confidence_score = {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.3,
            Confidence.NONE: 0.0
        }.get(self.confidence, 0.0)

        exploit_score = 0.2 if (self.exploit_evidence and self.exploit_evidence.exploits_available) else 0.0

        # Combined score
        combined = (severity_score * 0.5) + (confidence_score * 0.3) + (exploit_score * 0.2)

        # Map to priority
        if combined >= 3.5:
            return Priority.CRITICAL
        elif combined >= 2.5:
            return Priority.HIGH
        elif combined >= 1.5:
            return Priority.MEDIUM
        elif combined >= 0.5:
            return Priority.LOW
        else:
            return Priority.INFO

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = {
            "cve_id": self.cve_id,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "verdict": self.verdict.value,
            "confidence": self.confidence.value,
            "fixed_version": self.fixed_version,
            "priority": self.priority.value,
            "analysis_timestamp": self.analysis_timestamp,
        }

        if self.static_evidence:
            data["static_evidence"] = self.static_evidence.to_dict()

        if self.dynamic_evidence:
            data["dynamic_evidence"] = self.dynamic_evidence.to_dict()

        if self.exploit_evidence:
            data["exploit_evidence"] = self.exploit_evidence.to_dict()

        return data


@dataclass
class RBOMComponent:
    """Component in RBOM with runtime status and reachability"""
    name: str
    version: str
    type: str = "library"
    language: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    locations: List[str] = field(default_factory=list)

    # SBOM presence
    sbom_present: bool = True
    sbom_source: str = "syft"

    # Runtime status
    runtime_loaded: bool = False
    runtime_evidence: List[Dict[str, Any]] = field(default_factory=list)

    # Vulnerabilities
    vulnerabilities: List[VulnerabilityReachability] = field(default_factory=list)

    def get_critical_vulns(self) -> List[VulnerabilityReachability]:
        """Get CRITICAL priority vulnerabilities"""
        return [v for v in self.vulnerabilities if v.priority == Priority.CRITICAL]

    def get_reachable_vulns(self) -> List[VulnerabilityReachability]:
        """Get vulnerabilities with REACHABLE verdict"""
        return [v for v in self.vulnerabilities if v.verdict == ReachabilityVerdict.REACHABLE]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "version": self.version,
            "type": self.type,
            "language": self.language,
            "purl": self.purl,
            "cpe": self.cpe,
            "locations": self.locations,
            "sbom_present": self.sbom_present,
            "sbom_source": self.sbom_source,
            "runtime_loaded": self.runtime_loaded,
            "runtime_evidence": self.runtime_evidence,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical_vulnerabilities": len(self.get_critical_vulns()),
                "reachable_vulnerabilities": len(self.get_reachable_vulns()),
            }
        }


@dataclass
class ExecutionSummary:
    """Summary of runtime execution and analysis"""
    runtime_analysis_performed: bool = False
    runtime_duration_seconds: Optional[float] = None
    events_captured: Dict[str, int] = field(default_factory=dict)
    coverage_info: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class RBOMTarget:
    """Information about the analyzed target"""
    path: str
    type: str  # directory, repository, container
    language: Optional[str] = None
    framework: Optional[str] = None
    git_url: Optional[str] = None
    git_commit: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class RBOM:
    """Runtime Bill of Materials - Enhanced SBOM with reachability analysis"""

    # Metadata
    rbom_version: str = "1.0"
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    tool: str = "vulnreach"
    tool_version: str = "2.1.0"

    # Target information
    target: Optional[RBOMTarget] = None

    # Components
    components: List[RBOMComponent] = field(default_factory=list)

    # Execution summary
    execution_summary: Optional[ExecutionSummary] = None

    # Analysis metadata
    analysis_duration_seconds: Optional[float] = None

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the RBOM"""
        total_components = len(self.components)
        runtime_loaded = sum(1 for c in self.components if c.runtime_loaded)

        all_vulns = []
        for component in self.components:
            all_vulns.extend(component.vulnerabilities)

        reachable_vulns = [v for v in all_vulns if v.verdict == ReachabilityVerdict.REACHABLE]
        high_conf_vulns = [v for v in all_vulns if v.confidence == Confidence.HIGH]
        critical_priority = [v for v in all_vulns if v.priority == Priority.CRITICAL]

        return {
            "total_components": total_components,
            "runtime_loaded_components": runtime_loaded,
            "runtime_load_percentage": (runtime_loaded / total_components * 100) if total_components > 0 else 0,
            "total_vulnerabilities": len(all_vulns),
            "reachable_vulnerabilities": len(reachable_vulns),
            "high_confidence_vulnerabilities": len(high_conf_vulns),
            "critical_priority_vulnerabilities": len(critical_priority),
            "false_positive_reduction": self._calculate_false_positive_reduction(all_vulns, reachable_vulns),
        }

    def _calculate_false_positive_reduction(self, all_vulns: List, reachable_vulns: List) -> float:
        """Calculate false positive reduction percentage"""
        if not all_vulns:
            return 0.0

        not_reachable = len([v for v in all_vulns if v.verdict == ReachabilityVerdict.NOT_REACHABLE])
        return (not_reachable / len(all_vulns)) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert RBOM to dictionary for JSON serialization"""
        data = {
            "rbom_version": self.rbom_version,
            "generated_at": self.generated_at,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "analysis_duration_seconds": self.analysis_duration_seconds,
        }

        if self.target:
            data["target"] = self.target.to_dict()

        data["components"] = [c.to_dict() for c in self.components]

        if self.execution_summary:
            data["execution_summary"] = self.execution_summary.to_dict()

        data["statistics"] = self.get_statistics()

        return data

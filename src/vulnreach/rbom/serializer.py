"""RBOM Serializer

Converts RBOM objects to various output formats:
- JSON (machine-readable)
- Markdown (human-readable report)
- Summary statistics
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from vulnreach.rbom.schema import RBOM, Priority, Confidence, ReachabilityVerdict


class RBOMSerializer:
    """Serializes RBOM to various formats"""

    def __init__(self, rbom: RBOM):
        self.rbom = rbom

    def to_json(self, indent: int = 2) -> str:
        """Convert RBOM to JSON string

        Args:
            indent: JSON indentation level

        Returns:
            JSON string
        """
        return json.dumps(self.rbom.to_dict(), indent=indent)

    def save_json(self, output_path: str | Path) -> None:
        """Save RBOM as JSON file

        Args:
            output_path: Path to output JSON file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            f.write(self.to_json())

        print(f"💾 RBOM saved to: {output_path}")

    def to_markdown(self) -> str:
        """Convert RBOM to Markdown report

        Returns:
            Markdown string
        """
        stats = self.rbom.get_statistics()

        md = []
        md.append("# Runtime Bill of Materials (RBOM) Report")
        md.append("")
        md.append(f"**Generated:** {self.rbom.generated_at}")
        md.append(f"**Tool:** {self.rbom.tool} v{self.rbom.tool_version}")
        md.append("")

        # Target information
        if self.rbom.target:
            md.append("## 📍 Target Information")
            md.append("")
            md.append(f"- **Path:** `{self.rbom.target.path}`")
            md.append(f"- **Type:** {self.rbom.target.type}")
            if self.rbom.target.language:
                md.append(f"- **Language:** {self.rbom.target.language}")
            if self.rbom.target.framework:
                md.append(f"- **Framework:** {self.rbom.target.framework}")
            md.append("")

        # Executive summary
        md.append("## 📊 Executive Summary")
        md.append("")
        md.append(f"- **Total Components:** {stats['total_components']}")
        md.append(f"- **Runtime Loaded:** {stats['runtime_loaded_components']} ({stats['runtime_load_percentage']:.1f}%)")
        md.append(f"- **Total Vulnerabilities:** {stats['total_vulnerabilities']}")
        md.append(f"- **Reachable Vulnerabilities:** {stats['reachable_vulnerabilities']} ⚠️")
        md.append(f"- **High Confidence Reachable:** {stats['high_confidence_vulnerabilities']} 🔴")
        md.append(f"- **Critical Priority:** {stats['critical_priority_vulnerabilities']}")

        if stats['false_positive_reduction'] > 0:
            md.append(f"- **False Positive Reduction:** {stats['false_positive_reduction']:.1f}% ✅")

        md.append("")

        # Runtime execution summary
        if self.rbom.execution_summary and self.rbom.execution_summary.runtime_analysis_performed:
            md.append("## 🔬 Runtime Analysis Summary")
            md.append("")
            summary = self.rbom.execution_summary
            md.append(f"- **Runtime Analysis:** Performed")
            if summary.runtime_duration_seconds:
                md.append(f"- **Duration:** {summary.runtime_duration_seconds:.2f}s")

            if summary.events_captured:
                md.append(f"- **Events Captured:**")
                for event_type, count in summary.events_captured.items():
                    md.append(f"  - {event_type}: {count}")

            md.append("")

        # Critical findings
        critical_components = [c for c in self.rbom.components if c.get_critical_vulns()]
        if critical_components:
            md.append("## 🚨 Critical Findings")
            md.append("")
            md.append("Components with CRITICAL priority vulnerabilities:")
            md.append("")

            for component in critical_components:
                critical_vulns = component.get_critical_vulns()
                md.append(f"### {component.name} v{component.version}")
                md.append("")
                md.append(f"- **Runtime Loaded:** {'Yes ⚠️' if component.runtime_loaded else 'No ✅'}")
                md.append(f"- **Critical Vulnerabilities:** {len(critical_vulns)}")
                md.append("")

                for vuln in critical_vulns:
                    md.append(f"#### {vuln.cve_id}")
                    md.append(f"- **Severity:** {vuln.severity} (CVSS: {vuln.cvss_score or 'N/A'})")
                    md.append(f"- **Verdict:** {vuln.verdict.value}")
                    md.append(f"- **Confidence:** {vuln.confidence.value}")
                    md.append(f"- **Priority:** {vuln.priority.value}")

                    if vuln.fixed_version:
                        md.append(f"- **Fixed In:** {vuln.fixed_version}")

                    # Evidence summary
                    if vuln.dynamic_evidence and vuln.dynamic_evidence.package_loaded:
                        md.append(f"- **Runtime Evidence:** Package loaded ⚠️")
                        if vuln.dynamic_evidence.function_called:
                            md.append(f"  - Vulnerable function called 🔴")

                    if vuln.exploit_evidence and vuln.exploit_evidence.exploits_available:
                        md.append(f"- **Public Exploits:** {vuln.exploit_evidence.exploit_count} available 💣")

                    md.append("")

        # Component inventory
        md.append("## 📦 Component Inventory")
        md.append("")

        # Group by runtime status
        loaded_components = [c for c in self.rbom.components if c.runtime_loaded]
        not_loaded_components = [c for c in self.rbom.components if not c.runtime_loaded]

        md.append(f"### Runtime Loaded Components ({len(loaded_components)})")
        md.append("")

        if loaded_components:
            md.append("| Component | Version | Vulnerabilities | Reachable | Priority |")
            md.append("|-----------|---------|-----------------|-----------|----------|")

            for component in sorted(loaded_components, key=lambda c: len(c.get_critical_vulns()), reverse=True):
                total_vulns = len(component.vulnerabilities)
                reachable = len(component.get_reachable_vulns())
                critical = len(component.get_critical_vulns())

                priority_badge = ""
                if critical > 0:
                    priority_badge = "🔴 CRITICAL"
                elif reachable > 0:
                    priority_badge = "🟠 HIGH"
                elif total_vulns > 0:
                    priority_badge = "🟡 MEDIUM"
                else:
                    priority_badge = "✅ CLEAN"

                md.append(f"| {component.name} | {component.version} | {total_vulns} | {reachable} | {priority_badge} |")
        else:
            md.append("*No components loaded at runtime*")

        md.append("")

        if not_loaded_components and len(not_loaded_components) < 50:
            md.append(f"### Not Loaded at Runtime ({len(not_loaded_components)})")
            md.append("")
            md.append("<details>")
            md.append("<summary>Click to expand</summary>")
            md.append("")
            md.append("| Component | Version | Vulnerabilities |")
            md.append("|-----------|---------|-----------------|")

            for component in sorted(not_loaded_components, key=lambda c: c.name):
                total_vulns = len(component.vulnerabilities)
                md.append(f"| {component.name} | {component.version} | {total_vulns} |")

            md.append("")
            md.append("</details>")
            md.append("")

        # Recommendations
        md.append("## 💡 Recommendations")
        md.append("")

        critical_count = stats['critical_priority_vulnerabilities']
        reachable_count = stats['reachable_vulnerabilities']

        if critical_count > 0:
            md.append(f"1. **Fix {critical_count} CRITICAL priority vulnerabilities immediately** 🚨")

        if reachable_count > critical_count:
            md.append(f"2. **Address {reachable_count - critical_count} additional reachable vulnerabilities**")

        if stats['false_positive_reduction'] > 0:
            md.append(f"3. **{stats['false_positive_reduction']:.0f}% of vulnerabilities are NOT reachable** - deprioritize these")

        md.append("")

        # Footer
        md.append("---")
        md.append("")
        md.append("*This report was generated by VulnReach - Reachability-First Vulnerability Analysis*")
        md.append("")
        md.append(f"*Analysis Duration: {self.rbom.analysis_duration_seconds:.2f}s*")

        return "\n".join(md)

    def save_markdown(self, output_path: str | Path) -> None:
        """Save RBOM as Markdown file

        Args:
            output_path: Path to output Markdown file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            f.write(self.to_markdown())

        print(f"📄 RBOM report saved to: {output_path}")

    def print_summary(self) -> None:
        """Print a brief summary to console"""
        stats = self.rbom.get_statistics()

        print("\n" + "=" * 70)
        print("🛡️  RBOM ANALYSIS RESULTS")
        print("=" * 70)

        if self.rbom.target:
            print(f"📍 Target: {self.rbom.target.path}")

        print(f"📦 Total Components: {stats['total_components']}")
        print(f"🔄 Runtime Loaded: {stats['runtime_loaded_components']} ({stats['runtime_load_percentage']:.1f}%)")
        print(f"⚠️  Total Vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"🔴 Reachable: {stats['reachable_vulnerabilities']}")
        print(f"💣 High Confidence: {stats['high_confidence_vulnerabilities']}")
        print(f"🚨 Critical Priority: {stats['critical_priority_vulnerabilities']}")

        if stats['false_positive_reduction'] > 0:
            print(f"✅ False Positive Reduction: {stats['false_positive_reduction']:.1f}%")

        print("=" * 70)


def save_rbom(
    rbom: RBOM,
    output_dir: str | Path,
    base_name: str = "rbom"
) -> None:
    """Save RBOM in all formats

    Args:
        rbom: RBOM object to save
        output_dir: Output directory
        base_name: Base name for output files (default: "rbom")
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    serializer = RBOMSerializer(rbom)

    # Save JSON
    json_path = output_dir / f"{base_name}.json"
    serializer.save_json(json_path)

    # Save Markdown
    md_path = output_dir / f"{base_name}_report.md"
    serializer.save_markdown(md_path)

    # Print summary
    serializer.print_summary()

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from packaging.version import Version, InvalidVersion
from correlation.engine import Severity

from core.agent import BaseTool
from core.models import AgentResult, ScanContext, VulnerabilityFinding


class TrivyAgent(BaseTool):
    tool_name = "trivy"

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    async def run(self, context: ScanContext) -> AgentResult:
        if not context.repo_path:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "missing_repo_path"},
            )

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "repo_path_not_found", "repo_path": str(repo_path)},
            )

        raw = await self._run_trivy(repo_path)
        if raw is None:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "trivy_execution_failed"},
            )

        findings = [VulnerabilityFinding.model_validate(f).model_dump() for f in self._normalize(raw)]
        trimmed_raw = self._trim_raw(raw)
        return AgentResult.model_validate(
            {
                "tool_name": self.tool_name,
                "findings": findings,
                "metadata": {"status": "ok", "raw": trimmed_raw, "finding_count": len(findings)},
            }
        )

    async def _run_trivy(self, repo_path: Path) -> Optional[Dict[str, Any]]:
        cmd = [
            "trivy",
            "fs",
            "--format",
            "json",
            # Emit every detected package, not just vulnerable ones, so the RBOM
            # can present a full component inventory (Results[].Packages[], each
            # tagged with a Relationship of direct/indirect).
            "--list-all-pkgs",
            str(repo_path),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)
        except asyncio.TimeoutError:
            return None

        if proc.returncode != 0:
            return None

        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError:
            return None

    def _normalize(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        aggregated: Dict[tuple, Dict[str, Any]] = {}
        results = raw.get("Results", []) if isinstance(raw, dict) else []
        for result in results:
            vulns = result.get("Vulnerabilities", []) or []
            for vuln in vulns:
                pkg = vuln.get("PkgName")
                version = vuln.get("InstalledVersion")
                severity = vuln.get("Severity")
                raw_cve = vuln.get("VulnerabilityID")
                cves = self._parse_cves(raw_cve)
                fix = vuln.get("FixedVersion")
                key = (pkg, version)

                entry = aggregated.setdefault(
                    key,
                    {
                        "package": pkg,
                        "version": version,
                        "cve_id": [],
                        "severity": severity,
                        "fix_version": fix,
                    },
                )

                for cve in cves:
                    if cve and cve not in entry["cve_id"]:
                        entry["cve_id"].append(cve)

                entry["fix_version"] = self._newer_fix(entry.get("fix_version"), fix)
                entry["severity"] = self._higher_severity(entry.get("severity"), severity)

        # Normalize ordering of CVEs for determinism
        return [
            {**entry, "cve_id": sorted(entry["cve_id"])}
            for entry in aggregated.values()
        ]

    def _newer_fix(self, current: Optional[str], candidate: Optional[str]) -> Optional[str]:
        if not candidate:
            return current
        if not current:
            return candidate
        try:
            return str(max(Version(current), Version(candidate)))
        except InvalidVersion:
            # Fallback to string comparison if version parsing fails
            return max(current, candidate)

    def _higher_severity(self, current: Optional[str], candidate: Optional[str]) -> Optional[str]:
        order: Dict[Severity, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not candidate:
            return current
        if not current:
            return candidate
        return current if order.get(current, 0) >= order.get(candidate, 0) else candidate

    def _parse_cves(self, raw_cve: Any) -> List[str]:
        if raw_cve is None:
            return []
        if isinstance(raw_cve, list):
            return [str(c).strip() for c in raw_cve if str(c).strip()]
        text = str(raw_cve).strip()
        if text.startswith("{") and text.endswith("}"):
            text = text[1:-1]
        parts = [part.strip() for part in text.split(",") if part.strip()]
        return parts if parts else ([text] if text else [])

    def _trim_raw(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Trim raw Trivy output: References to top 2, VendorSeverity to top 5."""
        import copy
        trimmed = copy.deepcopy(raw)
        for result in trimmed.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                refs = vuln.get("References")
                if isinstance(refs, list) and len(refs) > 2:
                    vuln["References"] = refs[:2]
                vendor_sev = vuln.get("VendorSeverity")
                if isinstance(vendor_sev, dict) and len(vendor_sev) > 5:
                    vuln["VendorSeverity"] = dict(list(vendor_sev.items())[:5])
        return trimmed


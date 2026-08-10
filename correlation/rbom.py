"""RBOM — Reachability Bill of Materials.

A component-keyed view of a scan: every relevant package with its single
reachability verdict and the layered evidence behind it (static, dynamic, and
transitive), plus the CVEs it carries. Where an SBOM says *what is present* and
the scan's per-CVE response says *which vulnerabilities are reachable*, the RBOM
says *for each component, is it reachable and how do we know* — the natural
consumable of everything the reachability pipeline produces.

Assembled from the scan's reachability findings (the per-(CVE, package) records),
which already merge static + dynamic evidence. Optionally enriched with a full
component inventory so non-vulnerable packages appear too. Emittable as native
JSON or CycloneDX-with-VEX (reachability → analysis state).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

# Verdict strength, so a component with several findings takes its strongest.
_VERDICT_RANK = {"CONFIRMED": 3, "LIKELY": 2, "POSSIBLE": 1, "NOT_OBSERVED": 0}
_RBOM_VERSION = "1.0.0"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name or "")).strip().lower()


def _field(finding: Dict[str, Any], key: str, default=None):
    """Read a field from the finding or its nested ``evidence`` dict."""
    if key in finding and finding[key] is not None:
        return finding[key]
    ev = finding.get("evidence")
    if isinstance(ev, dict) and ev.get(key) is not None:
        return ev[key]
    return default


def _stronger(a: str, b: str) -> str:
    return a if _VERDICT_RANK.get(a, 0) >= _VERDICT_RANK.get(b, 0) else b


class _Component:
    __slots__ = ("name", "ecosystem", "version", "verdict", "confidence",
                 "cves", "reachable_via", "static", "dynamic", "direct")

    def __init__(self, name: str, ecosystem: Optional[str]):
        self.name = name
        self.ecosystem = ecosystem
        self.version: Optional[str] = None
        self.verdict = "NOT_OBSERVED"
        self.confidence = 0.0
        self.cves: set = set()
        self.reachable_via: Optional[List[str]] = None
        self.static: Optional[Dict[str, bool]] = None
        self.dynamic: Optional[Dict[str, bool]] = None
        self.direct: Optional[bool] = None

    def absorb(self, finding: Dict[str, Any]) -> None:
        verdict = str(_field(finding, "verdict") or "NOT_OBSERVED").upper()
        self.verdict = _stronger(self.verdict, verdict)
        try:
            self.confidence = max(self.confidence, float(_field(finding, "confidence", 0) or 0))
        except (TypeError, ValueError):
            pass
        cve = _field(finding, "cve_id")
        for c in (cve if isinstance(cve, list) else [cve]):
            if c:
                self.cves.add(str(c))
        if self.version is None:
            self.version = _field(finding, "version") or _field(finding, "installed_version")

        chain = _field(finding, "reachable_via")
        if chain and not self.reachable_via:
            self.reachable_via = list(chain)
            self.direct = False

        etype = str(_field(finding, "evidence_type") or "").lower()
        layer = {
            "import_detected": bool(_field(finding, "import_detected", False)),
            "call_chain_exists": bool(_field(finding, "call_chain_exists", False)),
            "sink_reachable": bool(_field(finding, "sink_reachable", False)),
        }
        if etype == "dynamic":
            # eBPF observer: import_detected == loaded, execution proof lifts to
            # call_chain_exists; expose them in runtime terms.
            self.dynamic = {"loaded": layer["import_detected"],
                            "executed": layer["call_chain_exists"],
                            "sink_reachable": layer["sink_reachable"]}
        elif etype == "static":
            self.static = layer
        else:  # unknown source — keep the raw signals under static
            self.static = self.static or layer

    def as_dict(self) -> Dict[str, Any]:
        evidence: Dict[str, Any] = {}
        if self.static:
            evidence["static"] = self.static
        if self.dynamic:
            evidence["dynamic"] = self.dynamic
        if self.reachable_via:
            evidence["transitive"] = {"reachable_via": self.reachable_via}
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "reachable": self.verdict != "NOT_OBSERVED",
            "direct": self.direct,
            "cve_ids": sorted(self.cves),
            "evidence": evidence,
        }


def build_rbom(
    findings: Iterable[Dict[str, Any]],
    components: Optional[Iterable[Dict[str, Any]]] = None,
    project: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble a component-keyed RBOM from reachability findings.

    Args:
        findings:   per-(CVE, package) reachability records (correlation results
                    or ReachabilityFinding dicts). Grouped by package here.
        components: optional full inventory — {name, ecosystem, version,
                    direct?} — so packages with no finding still appear
                    (verdict NOT_OBSERVED). Without it the RBOM covers only the
                    components the scan analysed.
        project:    optional {name, repo, scan_id, ...} metadata.
    """
    by_key: Dict[str, _Component] = {}

    def _get(name: str, ecosystem: Optional[str]) -> _Component:
        key = _norm(name)
        comp = by_key.get(key)
        if comp is None:
            comp = _Component(name, ecosystem)
            by_key[key] = comp
        elif ecosystem and not comp.ecosystem:
            comp.ecosystem = ecosystem
        return comp

    # Seed from the inventory first so non-vulnerable packages are represented.
    for c in components or []:
        name = c.get("name") or c.get("package")
        if not name:
            continue
        comp = _get(str(name), c.get("ecosystem"))
        if comp.version is None:
            comp.version = c.get("version")
        if c.get("direct") is not None and comp.direct is None:
            comp.direct = bool(c["direct"])

    for f in findings or []:
        name = f.get("package") or f.get("package_name") or f.get("name")
        if not name:
            continue
        _get(str(name), f.get("ecosystem")).absorb(f)

    comps = [c.as_dict() for c in by_key.values()]
    comps.sort(key=lambda x: (-_VERDICT_RANK.get(x["verdict"], 0), x["name"].lower()))

    summary = {"total_components": len(comps), "reachable": 0,
               "vulnerable": 0, "reachable_and_vulnerable": 0,
               "by_verdict": {v: 0 for v in _VERDICT_RANK}}
    for c in comps:
        summary["by_verdict"][c["verdict"]] = summary["by_verdict"].get(c["verdict"], 0) + 1
        vulnerable = bool(c["cve_ids"])
        if c["reachable"]:
            summary["reachable"] += 1
        if vulnerable:
            summary["vulnerable"] += 1
        if vulnerable and c["reachable"]:
            summary["reachable_and_vulnerable"] += 1

    return {
        "rbom_version": _RBOM_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": project or {},
        "summary": summary,
        "components": comps,
    }


# Trivy package-type → our ecosystem label (for the full-inventory seed).
_TRIVY_TYPE_ECO = {
    "pip": "python", "poetry": "python", "pipenv": "python", "python-pkg": "python",
    "uv": "python", "conda": "python",
    "npm": "node", "yarn": "node", "pnpm": "node", "node-pkg": "node", "bun": "node",
    "gomod": "go", "gobinary": "go",
    "pom": "java", "gradle": "java", "jar": "java", "sbt": "java",
    "composer": "php", "composer-installed": "php",
    "nuget": "csharp", "dotnet-core": "csharp", "packages-props": "csharp",
    "gemspec": "ruby", "bundler": "ruby", "cargo": "rust",
}


def components_from_trivy(raw: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Full component inventory from a Trivy `--list-all-pkgs` JSON result.

    Reads every ``Results[].Packages[]`` (all detected packages, not just
    vulnerable ones), mapping Trivy's package Type to an ecosystem and its
    ``Relationship`` to a direct/indirect flag. Returns [] for output produced
    without ``--list-all-pkgs`` (no Packages arrays) — the RBOM then simply
    covers only the analysed components.
    """
    if not isinstance(raw, dict):
        return []
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for result in raw.get("Results") or []:
        eco = _TRIVY_TYPE_ECO.get(str(result.get("Type") or "").lower())
        for pkg in result.get("Packages") or []:
            name = pkg.get("Name")
            if not name:
                continue
            key = (_norm(name), eco)
            if key in seen:
                continue
            seen.add(key)
            rel = str(pkg.get("Relationship") or "").lower()
            direct = (True if rel in ("direct", "root", "workspace")
                      else False if rel == "indirect" else None)
            out.append({"name": name, "version": pkg.get("Version"),
                        "ecosystem": eco, "direct": direct})
    return out


def rbom_from_scan(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Build an RBOM from a stored scan dict (the shape storage.get_scan returns).

    Shared by the API endpoint and package/local mode so both surfaces produce
    an identical RBOM. Seeds the full component inventory from Trivy's
    ``--list-all-pkgs`` output so non-vulnerable packages appear too, then layers
    the scan's merged reachability findings (``correlation``) on top.
    """
    project = {
        "name": scan.get("repo_name") or scan.get("repo_url") or scan.get("scan_id"),
        "repo": scan.get("repo_url"),
        "scan_id": scan.get("scan_id") or scan.get("id"),
    }
    components = components_from_trivy((scan.get("raw") or {}).get("trivy"))
    return build_rbom(scan.get("correlation") or [], components=components, project=project)


# ── CycloneDX (VEX) export ────────────────────────────────────────────────────

# Reachability verdict → CycloneDX VEX analysis state / justification.
_VEX_STATE = {
    "CONFIRMED": ("exploitable", None),
    "LIKELY": ("exploitable", None),
    "POSSIBLE": ("in_triage", None),
    "NOT_OBSERVED": ("not_affected", "code_not_reachable"),
}

_PURL_ECO = {"python": "pypi", "node": "npm", "javascript": "npm", "java": "maven",
             "go": "golang", "php": "composer", "csharp": "nuget"}


def _purl(comp: Dict[str, Any]) -> Optional[str]:
    eco = _PURL_ECO.get(str(comp.get("ecosystem") or "").lower())
    if not eco or not comp.get("name"):
        return None
    ver = f"@{comp['version']}" if comp.get("version") else ""
    return f"pkg:{eco}/{comp['name']}{ver}"


def to_cyclonedx(rbom: Dict[str, Any]) -> Dict[str, Any]:
    """Render an RBOM as CycloneDX 1.5 with reachability in VEX + properties.

    Reachability maps to `vulnerabilities[].analysis.state`
    (exploitable / in_triage / not_affected+code_not_reachable), and the raw
    verdict/evidence ride along as `vulnreach:*` component properties so no
    signal is lost to consumers that don't read VEX.
    """
    components: List[Dict[str, Any]] = []
    vulnerabilities: List[Dict[str, Any]] = []

    for c in rbom.get("components", []):
        purl = _purl(c)
        props = [{"name": "vulnreach:reachability", "value": c["verdict"]},
                 {"name": "vulnreach:confidence", "value": str(c["confidence"])}]
        if c.get("reachable_via") is None and c.get("evidence", {}).get("transitive"):
            props.append({"name": "vulnreach:reachable_via",
                          "value": " -> ".join(c["evidence"]["transitive"]["reachable_via"])})
        comp_entry: Dict[str, Any] = {"type": "library", "name": c["name"]}
        if c.get("version"):
            comp_entry["version"] = c["version"]
        if purl:
            comp_entry["purl"] = purl
        comp_entry["properties"] = props
        components.append(comp_entry)

        if not c["cve_ids"]:
            continue
        state, justification = _VEX_STATE.get(c["verdict"], ("in_triage", None))
        analysis: Dict[str, Any] = {"state": state,
                                    "detail": f"vulnreach reachability: {c['verdict']}"}
        if justification:
            analysis["justification"] = justification
        for cve in c["cve_ids"]:
            vulnerabilities.append({
                "id": cve,
                "affects": [{"ref": purl or c["name"]}],
                "analysis": analysis,
            })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": rbom.get("generated_at"),
            "tools": [{"vendor": "OWASP", "name": "VulnReach", "version": rbom.get("rbom_version")}],
            "component": {"type": "application",
                          "name": (rbom.get("project") or {}).get("name") or "scan-target"},
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

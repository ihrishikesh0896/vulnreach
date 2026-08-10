"""P5 — map eBPF observer reachability onto the canonical verdict pipeline.

Converts the language-agnostic PackageReach output (Rule R1, from
reachability.correlate_opens) into ``ReachabilityFinding`` objects using the
product's canonical Verdict vocabulary (D6: reuse CONFIRMED/LIKELY/POSSIBLE/
NOT_OBSERVED — no parallel enum).

Verdict mapping (D5):
  R2/R5+R4 code ran AND a static taint path reaches it    → CONFIRMED (0.95)
  R5/R6 the runtime executed the package's code           → CONFIRMED (0.85)
  R2 native code mapped PROT_EXEC (compiled code running) → CONFIRMED (0.8)
  R4 package loaded + static taint flow reaches it        → CONFIRMED (0.9)
  R1 openat load (package files loaded, no call proof)    → LIKELY  (import-hit)
  static taint flow but package never loaded              → POSSIBLE
  package never observed                                  → NOT_OBSERVED

R1/R4/POSSIBLE/NOT_OBSERVED are not hand-rolled: they are exactly
``correlation.engine.dynamic_reachability_verdict(has_taint_flow, has_coverage_hit)``,
the product's canonical rule that dynamic evidence + a static taint path ⇒ CONFIRMED.
R2 (native code demonstrably executing) is CONFIRMED on its own evidence.

This mirrors how agents/utils/coverage_correlator treats an import-only hit
(LIKELY, 0.65, import_time_hit=True), so eBPF findings are indistinguishable
downstream from coverage-derived import hits. CONFIRMED is reserved for
function-level evidence (R2 native / Tier B) and static-taint cross-ref (R4),
which land in later phases.
"""
from __future__ import annotations

from typing import Optional

from core.models import ReachabilityFinding
from correlation.engine import dynamic_reachability_verdict
from agents.utils.import_resolver import resolve_import_name as _resolve_import_name
from agents.ebpf.package_index import _norm
from agents.ebpf.reachability import PackageReach, CONFIRMED_REACHABLE
from agents.reachability.transitive import transitive_paths

# Confidence values kept identical to coverage_correlator for consistency.
_CONF_NATIVE_EXEC = 0.8   # R2: native code mapped PROT_EXEC (redesign §6)
_CONF_INTERPRETED_EXEC = 0.85  # R5/R6: the runtime actually executed the package's code
_CONF_EXEC_TAINTED = 0.95  # R2/R5 + R4: code ran AND a taint path reaches it
_CONF_TAINT_CONFIRMED = 0.9  # R4: runtime load + static taint path
_CONF_IMPORT_HIT = 0.65
_CONF_TAINT_ONLY = 0.4    # taint path exists but package never loaded
_CONF_NOT_OBSERVED = 0.1

_VERDICT_CONF = {
    "CONFIRMED": _CONF_TAINT_CONFIRMED,
    "LIKELY": _CONF_IMPORT_HIT,
    "POSSIBLE": _CONF_TAINT_ONLY,
    "NOT_OBSERVED": _CONF_NOT_OBSERVED,
}


def _cve_list(vuln: dict) -> list[Optional[str]]:
    cves = vuln.get("cve_id", [])
    if isinstance(cves, str):
        cves = [cves]
    return list(cves) if cves else [None]


def taint_modules(taint_flows: Optional[list[dict]]) -> set[str]:
    """Return the set of normalized module names that static taint flows reach.

    Reads ``sink.definition.module`` from tainter flow records (e.g. "yaml",
    "flask"), which is the *import* name of the vulnerable package.
    """
    mods: set[str] = set()
    for flow in taint_flows or []:
        sink = flow.get("sink") or {}
        definition = sink.get("definition") or {}
        module = (definition.get("module") or "").strip()
        if module:
            # "yaml.load" / "yaml" → top-level module
            mods.add(_norm(module.split(".")[0]))
    return mods


def to_reachability_findings(
    reach: dict[str, PackageReach],
    vulnerabilities: list[dict],
    import_map: Optional[dict[str, str]] = None,
    taint_flows: Optional[list[dict]] = None,
    requires_graph: Optional[dict] = None,
) -> list[ReachabilityFinding]:
    """Produce canonical ReachabilityFindings from eBPF PackageReach results.

    Args:
        reach:           output of reachability.correlate_opens (keyed pkg → PackageReach)
        vulnerabilities: SCA vuln dicts (need at least ``package`` and ``cve_id``)
        import_map:      optional dist→module map (from MetadataAgent) to bridge
                         PyPI dist names to the import names the observer sees
        taint_flows:     optional static taint flows (ScanContext.taint_flows) for
                         Rule R4 — runtime load + static path to the package ⇒ CONFIRMED
        requires_graph:  optional dependency graph (from the container's installed
                         metadata) for the transitive back-stop: a vuln that never
                         loaded but is reachable via a *loaded* package ⇒ POSSIBLE.
    """
    tainted = taint_modules(taint_flows)
    # Index reached packages by normalized name for dist/import-name matching.
    by_name: dict[str, PackageReach] = {}
    for pr in reach.values():
        by_name[_norm(pr.name)] = pr

    # Transitive back-stop: the loaded packages are the roots; anything reachable
    # from them through the dependency graph is structurally reachable even if it
    # did not load during the observation window.
    transitive: dict = {}
    if requires_graph:
        transitive = transitive_paths(by_name.keys(), requires_graph)

    findings: list[ReachabilityFinding] = []
    for vuln in vulnerabilities:
        pypi = (vuln.get("package") or "").strip()
        if not pypi:
            continue
        import_name = _resolve_import_name(pypi, import_map)
        pr = by_name.get(_norm(import_name)) or by_name.get(_norm(pypi))

        loaded = pr is not None
        has_taint = _norm(import_name) in tainted or _norm(pypi) in tainted
        # Runtime proof of execution: R2 (native code mapped executable) or
        # R5 (interpreter evaluated a frame from the package's source).
        executed = loaded and pr.verdict == CONFIRMED_REACHABLE

        if executed:
            # Execution proof AND a static path reaching it is the strongest
            # evidence we can produce.
            verdict = "CONFIRMED"
            if has_taint:
                confidence = _CONF_EXEC_TAINTED
            elif "R5" in pr.rule or "R6" in pr.rule:
                # Code actually ran — stricter than "was mapped executable".
                # R5: a Python frame was evaluated. R6: the JVM resolved a class,
                # which it only does on first active use.
                confidence = _CONF_INTERPRETED_EXEC
            else:
                confidence = _CONF_NATIVE_EXEC
        else:
            # Canonical rule: taint path + runtime evidence ⇒ CONFIRMED (R4);
            # runtime only ⇒ LIKELY (R1); taint only ⇒ POSSIBLE; neither ⇒ NOT_OBSERVED.
            verdict = dynamic_reachability_verdict(has_taint, loaded)
            confidence = _VERDICT_CONF.get(verdict, _CONF_NOT_OBSERVED)

        # Structural back-stop: a vuln that produced no runtime/taint evidence
        # (NOT_OBSERVED) but is reachable through the dependency graph from a
        # package that DID load is present-and-reachable — POSSIBLE, not absent.
        reachable_via = None
        if verdict == "NOT_OBSERVED":
            chain = transitive.get(_norm(import_name)) or transitive.get(_norm(pypi))
            if chain:
                verdict = "POSSIBLE"
                confidence = _VERDICT_CONF.get("POSSIBLE", _CONF_TAINT_ONLY)
                reachable_via = chain

        for cve in _cve_list(vuln):
            findings.append(ReachabilityFinding(
                cve_id=cve,
                package=vuln.get("package"),
                import_detected=loaded,
                call_chain_exists=executed or (has_taint and loaded),
                sink_reachable=has_taint and loaded,
                import_time_hit=loaded and verdict == "LIKELY",
                verdict=verdict,
                confidence=confidence,
                evidence_type="dynamic",
                files=list(pr.evidence)[:5] if loaded else [],
                reachable_via=reachable_via,
            ))
    return findings

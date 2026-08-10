from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from correlation.engine import (
    apply_policy,
    classify_reachability,
    confidence_from_verdict,
    dynamic_reachability_verdict,
    evidence_basis_from_signals,
    priority_from_score,
    reachability_verdict,
    risk_score,
)


class CorrelationService:
    def correlate(
        self,
        vulnerabilities: List[Dict[str, Any]],
        static_reachability: Dict[tuple[str, str], Dict[str, Any]],
        dynamic_reachability: Dict[tuple[str, str], Dict[str, Any]],
        exposure: str,
        policy_rules: Optional[List[Dict[str, Any]]] = None,
        semgrep_findings: Optional[List[Dict[str, Any]]] = None,
        dast_findings: Optional[List[Dict[str, Any]]] = None,
        # Legacy compatibility: single merged map still accepted
        reachability: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Correlate vulnerability + reachability data into prioritised findings.

        Classification tiers (coverage.json = ground truth):
          1. DYNAMICALLY_REACHABLE  — coverage hit + call chain / function
          2. STATICALLY_REACHABLE   — import / file / function, no coverage
             Sub-types: FUNCTION | FILE | IMPORT | TRANSITIVE
          3. NOT_REACHABLE          — no evidence at all
          4. UNCERTAIN              — taint-only, no call chain, no coverage

        The ``correlation`` list contains all findings tagged with
        ``reachability_class`` and ``finding_type`` for backward compatibility
        with the dashboard. The four categorised lists (``dynamically_reachable``,
        ``statically_reachable``, ``not_reachable``, ``uncertain``) provide the
        structured security-focused view.
        """
        # Back-compat shim: if caller passes the old single ``reachability``
        # map, treat it as static only.
        if reachability is not None and not static_reachability and not dynamic_reachability:
            static_reachability = reachability

        correlation_results: List[Dict[str, Any]] = []
        dynamically_reachable: List[Dict[str, Any]] = []
        statically_reachable: List[Dict[str, Any]] = []
        not_reachable: List[Dict[str, Any]] = []
        uncertain: List[Dict[str, Any]] = []

        rules = policy_rules or []
        pipeline_status = "PASS"

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "MEDIUM")
            package = vuln.get("package", "")
            normalized_package = _normalize_package(package)
            cves = vuln.get("cve_id") or []
            if not isinstance(cves, list):
                cves = [cves]
            if not cves:
                cves = [None]

            for cve in cves:
                cve_str = str(cve or "").strip()
                key = (normalized_package, cve_str) if normalized_package and cve_str else None
                dyn = dynamic_reachability.get(key) if key else None
                sta = static_reachability.get(key) if key else None
                # Legacy fallback for older CVE-only maps.
                if not dyn and cve_str:
                    dyn = dynamic_reachability.get(cve_str)  # type: ignore[arg-type]
                if not sta and cve_str:
                    sta = static_reachability.get(cve_str)  # type: ignore[arg-type]

                # ── Assemble evidence signals ─────────────────────────────────
                # Dynamic map: always has has_coverage_hit=True when present
                coverage_hit: bool = bool(dyn and dyn.get("has_coverage_hit", False))
                has_taint_flow: bool = bool(dyn and dyn.get("has_taint_flow", False))

                # Prefer dynamic-sourced function/file (runtime-confirmed);
                # fall back to static evidence.
                function: str | None = (dyn or {}).get("function") or (sta or {}).get("function")
                file: str | None = (dyn or {}).get("file") or (sta or {}).get("file")
                call_chain_exists: bool = bool(
                    (dyn and dyn.get("call_chain_exists"))
                    or (sta and sta.get("call_chain_exists"))
                )
                import_detected: bool = bool(
                    (dyn and dyn.get("import_detected"))
                    or (sta and sta.get("import_detected"))
                )
                # Taint-grounded sink: the static agents cross-reference tainter's
                # source→sink path and set sink_reachable on the finding. Carry it
                # through so a static import + call chain + confirmed taint sink can
                # reach CONFIRMED, per the canonical reachability_verdict rule —
                # rather than being capped at LIKELY.
                sink_reachable: bool = bool(
                    (dyn and dyn.get("sink_reachable"))
                    or (sta and sta.get("sink_reachable"))
                )
                evidence_type: str = (
                    (dyn or {}).get("evidence_type")
                    or (sta or {}).get("evidence_type")
                    or "static"
                )
                files: list = list(
                    set((dyn or {}).get("files", []) + (sta or {}).get("files", []))
                )[:10]

                # ── Classify ─────────────────────────────────────────────────
                reachability_class, static_subtype = classify_reachability(
                    coverage_hit=coverage_hit,
                    call_chain_exists=call_chain_exists,
                    import_detected=import_detected,
                    function=function,
                    file=file,
                    evidence_type=evidence_type,
                    package=package,
                )

                # ── Map to verdict + confidence ───────────────────────────────
                if reachability_class == "DYNAMICALLY_REACHABLE":
                    # Use the canonical engine function so verdict logic is not duplicated.
                    verdict = dynamic_reachability_verdict(has_taint_flow, coverage_hit)
                    base_conf = dyn.get("confidence") or confidence_from_verdict(verdict)
                    # Compound: independent static evidence alongside dynamic coverage
                    # raises confidence — each source reduces residual uncertainty.
                    # Cap at 0.99 (never claim certainty).
                    confidence = min(0.99, base_conf * 1.10) if sta else base_conf
                    finding_type = "dynamic"
                elif reachability_class == "STATICALLY_REACHABLE":
                    # Canonical rule (shared with the reachability agents and eBPF
                    # verdict integration): import + call chain + taint-grounded sink
                    # ⇒ CONFIRMED; import + call chain ⇒ LIKELY; import only ⇒ POSSIBLE.
                    verdict = reachability_verdict(
                        import_detected=import_detected,
                        call_chain_exists=call_chain_exists,
                        sink_reachable=sink_reachable,
                    )
                    # classify_reachability already proved static reachability from
                    # file/function/call-chain evidence — which does not require the
                    # import flag. The canonical rule floors import-less findings at
                    # NOT_OBSERVED, so raise that floor: a STATICALLY_REACHABLE
                    # finding is at minimum POSSIBLE.
                    if verdict == "NOT_OBSERVED":
                        verdict = "POSSIBLE"
                    confidence = (sta or {}).get("confidence") or confidence_from_verdict(verdict)
                    finding_type = "static"
                elif reachability_class == "UNCERTAIN":
                    verdict = "POSSIBLE"
                    confidence = 0.3
                    finding_type = "uncertain"
                else:  # NOT_REACHABLE
                    verdict = "NOT_OBSERVED"
                    confidence = 0.1
                    finding_type = "not_reachable"

                score = risk_score(severity, verdict, exposure)
                priority = priority_from_score(score)

                evidence_blob: Dict[str, Any] = {
                    "coverage_hit": coverage_hit,
                    "has_taint_flow": has_taint_flow,
                    "call_chain_exists": call_chain_exists,
                    "import_detected": import_detected,
                    "function": function,
                    "file": file,
                    "files": files,
                    "evidence_type": evidence_type,
                    # Dashboard compat fields
                    "has_coverage_hit": coverage_hit,
                    "has_static_evidence": bool(sta),
                    # Classification — stored inside evidence so they survive DB round-trip
                    "reachability_class": reachability_class,
                }
                if static_subtype:
                    evidence_blob["static_subtype"] = static_subtype
                if reachability_class == "UNCERTAIN":
                    uncertainty_reason, uncertainty_detail = _uncertain_reason(dyn)
                    evidence_blob["uncertainty_reason"] = uncertainty_reason
                    evidence_blob["uncertainty_detail"] = uncertainty_detail

                finding: Dict[str, Any] = {
                    "cve_id": cve,
                    "package": package,
                    "severity": severity,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "confidence": confidence,
                    "reachability_class": reachability_class,
                    "finding_type": finding_type,
                    "evidence": evidence_blob,
                }

                if static_subtype:
                    finding["static_subtype"] = static_subtype

                finding["evidence_basis"] = evidence_basis_from_signals(
                    finding_type=finding_type,
                    has_coverage_hit=coverage_hit,
                    has_taint_flow=has_taint_flow,
                    call_chain_exists=call_chain_exists,
                    import_detected=import_detected,
                )

                correlation_results.append(finding)

                # ── Populate categorised lists ────────────────────────────────
                summary = {
                    "cve_id": cve,
                    "package": package,
                    "severity": severity,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "confidence": confidence,
                }

                if reachability_class == "DYNAMICALLY_REACHABLE":
                    dynamically_reachable.append({
                        **summary,
                        "functions_executed": [f for f in [function] if f],
                        "files": files,
                        "reasoning": _dynamic_reasoning(has_taint_flow, call_chain_exists, function),
                    })
                elif reachability_class == "STATICALLY_REACHABLE":
                    statically_reachable.append({
                        **summary,
                        "classification": static_subtype,
                        "reasoning": _static_reasoning(static_subtype, import_detected, call_chain_exists, function, file),
                    })
                elif reachability_class == "UNCERTAIN":
                    uncertainty_reason, uncertainty_detail = _uncertain_reason(dyn)
                    uncertain.append({
                        **summary,
                        "uncertainty_reason": uncertainty_reason,
                        "reason": uncertainty_detail,
                    })
                else:
                    not_reachable.append({"cve_id": cve, "package": package, "severity": severity})

                if apply_policy(severity, verdict, rules) == "BLOCK":
                    pipeline_status = "BLOCK"

        # ── Semgrep static findings ───────────────────────────────────────────
        for finding in semgrep_findings or []:
            severity = finding.get("severity", "MEDIUM")
            check_id = finding.get("check_id")
            verdict = "POSSIBLE"
            score = risk_score(severity, verdict, exposure)
            priority = priority_from_score(score)
            correlation_results.append(
                {
                    "check_id": check_id,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "reachability_class": "STATICALLY_REACHABLE",
                    "finding_type": "semgrep",
                    "source": "semgrep",
                }
            )
            if apply_policy(severity, verdict, rules) == "BLOCK":
                pipeline_status = "BLOCK"

        # ── DAST findings — Claude-steered payload confirmation ───────────────
        for finding in dast_findings or []:
            cve_id = finding.get("cve_id")
            sev = finding.get("dast_severity", "HIGH").upper()
            verdict = finding.get("verdict", "CONFIRMED")
            score = risk_score(sev, verdict, exposure)
            priority = priority_from_score(score)
            correlation_results.append(
                {
                    "cve_id": cve_id,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "confidence": finding.get("confidence", 1.0),
                    "reachability_class": "DYNAMICALLY_REACHABLE",
                    "finding_type": "dast",
                    "evidence": {
                        "vuln_class": finding.get("dast_vuln_class", "sql_injection"),
                        "severity": sev,
                        "endpoint": finding.get("function", ""),
                        "parameter": finding.get("sink", ""),
                        "payload": finding.get("dast_payload"),
                        "confirmation_method": finding.get("dast_method"),
                        "reasoning": finding.get("dast_reasoning"),
                        "files": finding.get("files", []),
                    },
                }
            )
            if apply_policy(sev, verdict, rules) == "BLOCK":
                pipeline_status = "BLOCK"

        return {
            "correlation": correlation_results,
            "dynamically_reachable": dynamically_reachable,
            "statically_reachable": statically_reachable,
            "not_reachable": not_reachable,
            "uncertain": uncertain,
            "pipeline_status": pipeline_status,
            "summary": {
                "total": len(correlation_results),
                "dynamically_reachable": len(dynamically_reachable),
                "statically_reachable": len(statically_reachable),
                "not_reachable": len(not_reachable),
                "uncertain": len(uncertain),
            },
        }


def _dynamic_reasoning(has_taint_flow: bool, call_chain_exists: bool, function: str | None) -> str:
    parts = ["Runtime coverage confirmed execution"]
    if has_taint_flow:
        parts.append("taint flow traces user-controlled input to this package")
    if call_chain_exists:
        parts.append("call chain exists from application code")
    if function:
        parts.append(f"function '{function}' was executed")
    return "; ".join(parts) + "."


def _static_reasoning(
    subtype: str | None,
    import_detected: bool,
    call_chain_exists: bool,
    function: str | None,
    file: str | None,
) -> str:
    if subtype == "FUNCTION":
        return f"Function '{function}' is present in source but was not executed at runtime."
    if subtype == "FILE":
        return f"File '{file}' references this package but was not observed in runtime coverage."
    if subtype == "TRANSITIVE":
        return "Package is loaded via framework bootstrap (e.g. routing/middleware); not directly called by application code."
    if subtype == "IMPORT":
        return "Package import was detected but no function-level usage or runtime execution was observed."
    return "Static evidence present; no runtime execution confirmed."


def _uncertain_reason(dyn: Optional[Dict[str, Any]]) -> tuple[str, str]:
    """Return a (code, human-readable detail) pair explaining why a finding is UNCERTAIN.

    Codes:
        taint_no_dynamic  — taint flow found but runtime scan was not run.
                            Action: enable scan.runtime.enabled: true and re-scan.
        taint_dynamic_miss — taint flow found, runtime scan ran, but this package
                             was never hit during the test run.
                             Action: exercise the affected endpoint with representative
                             input and re-scan, or review the taint flow manually.
    """
    if not dyn:
        return (
            "taint_no_dynamic",
            "Taint flow detected but no runtime scan was run. "
            "Enable scan.runtime.enabled: true and re-scan to confirm or dismiss.",
        )
    return (
        "taint_dynamic_miss",
        "Taint flow detected and runtime scan ran, but this package was not observed "
        "in coverage. The vulnerable path likely requires specific input to trigger. "
        "Exercise the affected endpoint with representative traffic and re-scan, "
        "or review the taint flow manually.",
    )


def _normalize_package(package: Any) -> str:
    raw = unquote(str(package or "").strip().lower())
    if not raw:
        return ""
    if raw.startswith("pkg:"):
        body = raw.split("pkg:", 1)[1]
        if "/" in body:
            body = body.split("/", 1)[1]
        raw = body
    return raw.split("@", 1)[0].strip()

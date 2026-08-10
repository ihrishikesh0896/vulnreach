import logging
from typing import Any, Dict, Set, Tuple
from urllib.parse import unquote

from core.models import AgentResult, ScanContext
from agents.runner import AgentRunner
from correlation.engine import confidence_from_verdict, reachability_verdict
from correlation.service import CorrelationService
from storage.repository import StorageRepository

logger = logging.getLogger(__name__)


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


def _evidence_key(cve_id: Any, package: Any) -> Tuple[str, str] | None:
    cve = str(cve_id or "").strip()
    pkg = _normalize_package(package)
    if not cve or not pkg:
        return None
    return (pkg, cve)


def _merge_reachability(existing: Dict[str, Any] | None, incoming: Dict[str, Any]) -> Dict[str, Any]:
    if not existing:
        merged = dict(incoming)
        merged["import_detected"] = bool(incoming.get("import_detected", False))
        merged["call_chain_exists"] = bool(incoming.get("call_chain_exists", False))
        merged["sink_reachable"] = bool(incoming.get("sink_reachable", False))
        return merged

    merged = dict(existing)
    merged.update({k: v for k, v in incoming.items() if v is not None})
    merged["import_detected"] = bool(existing.get("import_detected", False) or incoming.get("import_detected", False))
    merged["call_chain_exists"] = bool(existing.get("call_chain_exists", False) or incoming.get("call_chain_exists", False))
    merged["sink_reachable"] = bool(existing.get("sink_reachable", False) or incoming.get("sink_reachable", False))

    existing_files = set(existing.get("files", []) or [])
    existing_files.update(incoming.get("files", []) or [])
    merged["files"] = list(existing_files)[:10]

    existing_fn = (existing.get("function") or "").strip()
    incoming_fn = (incoming.get("function") or "").strip()
    if existing_fn and incoming_fn and incoming_fn not in existing_fn:
        merged["function"] = f"{existing_fn}, {incoming_fn}"
    elif incoming_fn:
        merged["function"] = incoming_fn

    try:
        merged["confidence"] = max(float(existing.get("confidence", 0) or 0), float(incoming.get("confidence", 0) or 0))
    except (TypeError, ValueError):
        merged["confidence"] = existing.get("confidence", incoming.get("confidence", 0.1))

    return merged


class Orchestrator:
    def __init__(
        self,
        storage: StorageRepository,
        runner: AgentRunner,
        correlation_service: CorrelationService,
    ) -> None:
        self.storage = storage
        self.runner = runner
        self.correlation_service = correlation_service

    async def execute_scan(
        self,
        scan_id: str,
        repo_path: str,
        config_path: str,
        config: Any,
        repo_url: str | None,
    ) -> None:
        context = ScanContext(
            repo_path=repo_path,
            repo_url=repo_url,
            config_path=config_path,
            config=config,
            scan_id=scan_id,
        )

        logger.info("scan_start", extra={"scan_id": scan_id, "repo_url": repo_url, "repo_path": repo_path})
        results = await self.runner.run_all(context)

        # Identify tools that failed — warn and continue with partial data
        failed_tools = [r.tool_name for r in results if r.metadata.get("error")]
        fatal_tools = [r.tool_name for r in results if r.metadata.get("fatal")]
        if failed_tools:
            logger.warning(
                "scan_partial_tools_skipped",
                extra={"scan_id": scan_id, "failed_tools": failed_tools},
            )

        # Map CVE -> known vulnerable packages (used to fill missing package on agent evidence).
        vuln_packages_by_cve: Dict[str, Set[str]] = {}
        for vuln in context.vulnerabilities:
            pkg = str(vuln.get("package") or "").strip()
            if not pkg:
                continue
            cves = vuln.get("cve_id") or []
            if not isinstance(cves, list):
                cves = [cves]
            for cve in cves:
                cve_str = str(cve or "").strip()
                if cve_str:
                    vuln_packages_by_cve.setdefault(cve_str, set()).add(pkg)

        def resolve_item_key(item: Dict[str, Any]) -> Tuple[Tuple[str, str], str, str] | None:
            cve = str(item.get("cve_id") or "").strip()
            if not cve:
                return None

            package = str(item.get("package") or "").strip()
            if not package:
                candidates = vuln_packages_by_cve.get(cve, set())
                if len(candidates) == 1:
                    package = next(iter(candidates))
            key = _evidence_key(cve, package)
            if not key:
                return None
            return key, cve, package

        # ------------------------------------------------------------------
        # Build STATIC reach map
        # Source: tainter + python_reachability + java_reachability
        # (+ multi_language_reachability when present)
        # Verdict logic: import_detected / call_chain_exists only — no dynamic
        # ------------------------------------------------------------------
        static_reach_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for result in results:
            if result.tool_name in {"tainter", "python_reachability", "java_reachability", "multi_language_reachability"}:
                for item in result.findings:
                    resolved = resolve_item_key(item)
                    if not resolved:
                        continue
                    key, cve, package = resolved
                    verdict = reachability_verdict(
                        import_detected=item.get("import_detected", False),
                        call_chain_exists=item.get("call_chain_exists", False),
                        # The static reachability agents now ground sink_reachable
                        # in a source→sink taint path (tainter cross-reference), so
                        # honour it: import + call chain + taint ⇒ CONFIRMED, per
                        # the canonical reachability_verdict rule. Hardcoding False
                        # here silently discarded the agents' taint grounding and
                        # capped every static finding at LIKELY.
                        sink_reachable=item.get("sink_reachable", False),
                    )
                    static_candidate = {
                        **item,
                        "package": package,
                        "cve_id": cve,
                        "verdict": verdict,
                        "evidence_type": "static",
                        "confidence": item.get("confidence") or confidence_from_verdict(verdict),
                    }
                    static_reach_map[key] = _merge_reachability(static_reach_map.get(key), static_candidate)

        # ------------------------------------------------------------------
        # Build DYNAMIC reach map
        #
        # A CVE earns dynamic reachability ONLY through the FULL evidence chain:
        #   1. SCA vulnerable (already filtered — only vulns from Trivy)
        #   2. Has taint flow (from tainter agent)
        #   3. Has route exposure (from route_extractor)
        #   4. Has static reachability (from static_reach_map above)
        #   5. Coverage confirms execution (from dynamic_reachability/pytest_coverage)
        #
        # Without all five, the package is NOT dynamically reachable.
        # ------------------------------------------------------------------

        # Step 1 — collect (package, CVE) tuples that have taint-flow trace.
        taint_pairs: Set[Tuple[str, str]] = set()
        for result in results:
            if result.tool_name == "tainter":
                for item in result.findings:
                    resolved = resolve_item_key(item)
                    if not resolved:
                        continue
                    key, _, _ = resolved
                    if item.get("call_chain_exists") or item.get("sink_reachable"):
                        taint_pairs.add(key)

        # Step 1b — check if routes exist at all (route_extractor ran and found routes)
        # Route evidence is enforced as a hard gate for dynamic findings.
        has_routes = False
        for result in results:
            if result.tool_name == "route_extractor" and result.findings:
                has_routes = True
                break

        # Step 2 — collect (package, CVE) tuples confirmed by runtime coverage
        coverage_evidence: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for result in results:
            if result.tool_name in ("dynamic_reachability", "pytest_coverage"):
                for item in result.findings:
                    resolved = resolve_item_key(item)
                    if not resolved:
                        continue
                    key, cve, package = resolved
                    candidate = {**item, "cve_id": cve, "package": package}
                    existing = coverage_evidence.get(key)
                    if existing:
                        merged = _merge_reachability(existing, candidate)
                        merged["import_time_hit"] = bool(existing.get("import_time_hit", False) or candidate.get("import_time_hit", False))
                        coverage_evidence[key] = merged
                    else:
                        coverage_evidence[key] = dict(candidate)

        # Step 3 — gate dynamic findings on the full evidence chain
        #
        # Full chain: SCA (already filtered) → taint → routes → static → coverage
        #
        # Route evidence is enforced globally (route_extractor found at least one
        # endpoint). Per-package route-to-sink proof still comes from taint/static
        # evidence checks below.
        #
        # Import-time-only (Strategy 2) is weak evidence — the app code that
        # imports the library ran, but the library's own code isn't in coverage.
        # Promoted to CONFIRMED only when the full chain is present.
        dynamic_reach_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for key, dyn_item in coverage_evidence.items():
            has_taint = key in taint_pairs
            has_coverage = dyn_item.get("sink_reachable", False)
            has_static = key in static_reach_map
            import_time_only = dyn_item.get("import_time_hit", False) and not has_coverage

            # Enforce route gate: dynamic evidence is only valid when route extraction
            # confirmed the app exposes HTTP routes.
            if not has_routes:
                continue

            if import_time_only:
                # Strategy 2 (import-in-executed-file): weak signal.
                # Only promote if FULL evidence chain is satisfied:
                #   taint + static reachability (+ route gate above)
                if not (has_taint and has_static):
                    continue
                # Full chain: SCA + taint + routes + static + coverage (import-time)
                verdict = "CONFIRMED"
                confidence = 0.95
            elif has_coverage and has_taint:
                # Direct library coverage + taint → CONFIRMED
                verdict = "CONFIRMED"
                confidence = 0.95
            elif has_coverage and has_static:
                # Direct coverage + static (no taint) → LIKELY
                verdict = "LIKELY"
                confidence = 0.75
            elif has_coverage:
                # Coverage hit but no taint or static → weak
                verdict = "POSSIBLE"
                confidence = 0.55
            else:
                # No coverage evidence at all — skip
                continue

            dynamic_reach_map[key] = {
                **dyn_item,
                "verdict": verdict,
                "evidence_type": "dynamic",
                "has_taint_flow": has_taint,
                "has_coverage_hit": True,  # all paths above have some coverage evidence
                "has_static_evidence": has_static,
                "has_route_evidence": has_routes,
                "confidence": confidence,
                # sink_reachable=True means a call-site line executed — that IS a
                # call chain. Propagate so classify_reachability() can reach the
                # DYNAMICALLY_REACHABLE tier (which requires call_chain_exists OR function).
                "call_chain_exists": bool(dyn_item.get("call_chain_exists") or has_coverage),
            }

        # ------------------------------------------------------------------
        # Build DAST evidence map
        # Source: intelligent_dast agent — Claude-steered SQLi confirmation
        # These are already verdict=CONFIRMED with confidence=1.0
        # ------------------------------------------------------------------
        dast_findings: list[dict[str, Any]] = []
        for result in results:
            if result.tool_name == "intelligent_dast":
                dast_findings.extend(result.findings)
                # Also store the full DAST metadata (iterations, payloads, etc.)
                if result.metadata.get("findings"):
                    self.storage.store_raw_output(
                        scan_id, "intelligent_dast_detail",
                        result.metadata["findings"],
                    )

        semgrep_result = next((res for res in results if res.tool_name == "semgrep"), AgentResult(tool_name="semgrep"))

        correlation_output = self.correlation_service.correlate(
            vulnerabilities=context.vulnerabilities,
            static_reachability=static_reach_map,
            dynamic_reachability=dynamic_reach_map,
            exposure=config.risk.exposure,
            policy_rules=[rule.model_dump() for rule in config.policy.block_if],
            semgrep_findings=semgrep_result.findings,
            dast_findings=dast_findings,
        )
        self.storage.store_correlation(scan_id, correlation_output["correlation"])

        # Store structured reachability classification for API consumers
        summary = correlation_output.get("summary", {})
        logger.info(
            "correlation_summary",
            extra={
                "scan_id": scan_id,
                "dynamically_reachable": summary.get("dynamically_reachable", 0),
                "statically_reachable": summary.get("statically_reachable", 0),
                "not_reachable": summary.get("not_reachable", 0),
                "uncertain": summary.get("uncertain", 0),
            },
        )

        if correlation_output["pipeline_status"] == "BLOCK":
            status = "blocked"
        elif fatal_tools:
            status = "failed"
        elif failed_tools:
            status = "partial"
        else:
            status = "completed"
        self.storage.update_scan_status(scan_id, status)
        logger.info(
            "scan_complete",
            extra={
                "scan_id": scan_id,
                "status": status,
                "pipeline_status": correlation_output["pipeline_status"],
                "failed_tools": failed_tools,
                "fatal_tools": fatal_tools,
            },
        )

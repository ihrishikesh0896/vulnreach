"""Sink-to-handler reachability engine.

Takes Semgrep SAST findings and static route extraction output to compute
lightweight reachability scores for web handlers. Produces JSON linking sinks
(rule/file/line) to handlers/routes with a 0-1 score, dropping low-signal
results (<0.4).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ReachabilityFinding:
    rule_id: str
    file: str
    line: Optional[int]
    sink_function: Optional[str]
    handler: Optional[str]
    route: Optional[Dict[str, str]]
    reachability_score: float
    reason: str
    severity: Optional[str] = None


def _load_json(path: str) -> Dict:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_semgrep_findings(path: str) -> List[Dict]:
    data = _load_json(path)
    normalized = data.get("normalized_findings")
    if normalized:
        return normalized
    return data.get("results", [])


def _load_routes(path: str) -> List[Dict]:
    data = _load_json(path)
    # routes.json is a list; route extractor writes a list of dicts
    if isinstance(data, list):
        return data
    return []


def _read_file_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def _python_handlers(lines: List[str]) -> List[Tuple[str, int, int]]:
    handlers: List[Tuple[str, int, int]] = []
    stack: List[Tuple[str, int, int]] = []  # name, indent, start_line
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        match = re.match(r"def\s+(\w+)\s*\(", line)
        if not match:
            continue
        name = match.group(1)
        indent = len(raw) - len(raw.lstrip(" "))
        # pop handlers with >= indent
        while stack and stack[-1][1] >= indent:
            popped = stack.pop()
            handlers.append((popped[0], popped[2], idx - 1))
        stack.append((name, indent, idx))
    # close remaining
    for name, _, start in stack:
        handlers.append((name, start, len(lines)))
    return handlers


def _javascript_handlers(lines: List[str]) -> List[Tuple[str, int, int]]:
    handlers: List[Tuple[str, int, int]] = []
    pattern = re.compile(r"function\s+(\w+)\s*\(|const\s+(\w+)\s*=\s*\([^)]*\)\s*=>")
    for idx, line in enumerate(lines, start=1):
        match = pattern.search(line)
        if match:
            name = match.group(1) or match.group(2)
            handlers.append((name, idx, idx))
    return handlers


def _java_handlers(lines: List[str]) -> List[Tuple[str, int, int]]:
    handlers: List[Tuple[str, int, int]] = []
    pattern = re.compile(r"public\s+[\w<>,\s]+\s+(\w+)\s*\(")
    for idx, line in enumerate(lines, start=1):
        match = pattern.search(line)
        if match:
            handlers.append((match.group(1), idx, idx))
    return handlers


def _enclosing_handler(path: Path, line_no: Optional[int]) -> Optional[str]:
    if line_no is None:
        return None
    lines = _read_file_lines(path)
    if path.suffix == ".py":
        candidates = _python_handlers(lines)
    elif path.suffix == ".js":
        candidates = _javascript_handlers(lines)
    elif path.suffix == ".java":
        candidates = _java_handlers(lines)
    else:
        return None
    for name, start, end in candidates:
        if start <= line_no <= end:
            return name
    return None


def _match_route(routes: List[Dict], file_path: str, handler: Optional[str]) -> Optional[Dict[str, str]]:
    for route in routes:
        if route.get("file") == file_path:
            if handler is None or route.get("handler") == handler:
                return route
    return None


def _compute_reachability_score(has_handler: bool, has_route: bool, has_taint_hint: bool, severity: Optional[str]) -> float:
    score = 0.0
    score += 0.4 if has_handler else 0.2
    if has_route:
        score += 0.3
    if has_taint_hint:
        score += 0.2
    if severity:
        sev = severity.lower()
        if sev in {"critical", "high"}:
            score += 0.1
        elif sev == "medium":
            score += 0.05
    return min(score, 1.0)


def run_reachability_engine(project_root: str, findings_dir: str) -> List[ReachabilityFinding]:
    semgrep_path = os.path.join(findings_dir, "semgrep.json")
    routes_path = os.path.join(findings_dir, "routes.json")
    reachable_path = os.path.join(findings_dir, "sink_handler_reachability.json")

    if not os.path.exists(semgrep_path):
        raise FileNotFoundError(f"Missing semgrep findings file: {semgrep_path}")

    semgrep_findings = _load_semgrep_findings(semgrep_path)
    routes = _load_routes(routes_path) if os.path.exists(routes_path) else []

    results: List[ReachabilityFinding] = []
    for finding in semgrep_findings:
        file_path = finding.get("file") or finding.get("path") or ""
        line_no = finding.get("line") or (finding.get("start") or {}).get("line")
        sink_func = finding.get("sink_function") or finding.get("function")
        severity = finding.get("severity")
        taint_hint = finding.get("taint_hint") or (finding.get("metadata") or {}).get("taint_hint")

        abs_path = Path(project_root, file_path)
        handler = _enclosing_handler(abs_path, line_no)
        route = _match_route(routes, file_path, handler)
        # If no handler match, try handler name from sink_function when it matches a route handler
        if route is None and sink_func:
            route = _match_route(routes, file_path, sink_func)
            if route and not handler:
                handler = route.get("handler")

        score = _compute_reachability_score(bool(handler), bool(route), bool(taint_hint), severity)
        reason_parts = []
        if handler:
            reason_parts.append(f"enclosed by handler {handler}")
        if route:
            reason_parts.append("handler has route")
        if taint_hint:
            reason_parts.append("taint/user-input hint")
        if severity:
            reason_parts.append(f"severity={severity}")
        reason = "; ".join(reason_parts) or "low signal"

        if score < 0.4:
            continue

        results.append(
            ReachabilityFinding(
                rule_id=finding.get("rule_id") or finding.get("check_id") or "",
                file=file_path,
                line=line_no,
                sink_function=sink_func,
                handler=handler,
                route=route,
                reachability_score=round(score, 2),
                reason=reason,
                severity=severity,
            )
        )

    payload = {
        "project_root": project_root,
        "findings_dir": findings_dir,
        "routes_linked": len([r for r in results if r.route]),
        "total": len(results),
        "findings": [asdict(r) for r in results],
    }

    os.makedirs(findings_dir, exist_ok=True)
    with open(reachable_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    return results


__all__ = ["run_reachability_engine", "ReachabilityFinding"]

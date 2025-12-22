import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
from flask import Flask, abort, jsonify, send_from_directory
from flask_cors import CORS
# Config
# ---------------------------
BASE_DIR = Path(__file__).parent.resolve()
SECURITY_FINDINGS_DIR = Path(
    os.environ.get("SECURITY_FINDINGS_DIR", BASE_DIR / "security_findings")
).resolve()
REACHABILITY_GLOB = "*_vulnerability_reachability_report.json"
app = Flask(__name__, static_folder="frontend", static_url_path="")
CORS(app)
from flask_cors import CORS

# ---------------------------
# Config
# ---------------------------
BASE_DIR = Path(__file__).parent.resolve()
SECURITY_FINDINGS_DIR = Path(
    os.environ.get("SECURITY_FINDINGS_DIR", BASE_DIR / "security_findings")
).resolve()

REACHABILITY_GLOB = "*_vulnerability_reachability_report.json"

app = Flask(__name__, static_folder="frontend", static_url_path="")
CORS(app)


# ---------------------------
# Helpers
# ---------------------------
def _json_load(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load JSON {path}: {e}")
        return None


def _find_first(project_dir: Path, names: List[str]) -> Optional[Path]:
    for n in names:
        p = project_dir / n
        if p.exists() and p.is_file():
            return p
    return None


def project_files(project_dir: Path) -> Dict[str, Optional[str]]:
    """
    Discover relevant files inside a project directory.
    Returns relative paths (to SECURITY_FINDINGS_DIR) where present, else None.
    """
    reach = sorted(project_dir.glob(REACHABILITY_GLOB))
    consolidated = _find_first(project_dir, ["consolidated.json", "consolidtated.json"])  # accept typo too
    exploitability = _find_first(project_dir, ["exploitability_report.json", "exploitability.json"])
    security = _find_first(project_dir, ["security_report.json"])

    return {
        "reachability_report": str(reach[0].relative_to(SECURITY_FINDINGS_DIR)) if reach else None,
        "consolidated": str(consolidated.relative_to(SECURITY_FINDINGS_DIR)) if consolidated else None,
        "exploitability": str(exploitability.relative_to(SECURITY_FINDINGS_DIR)) if exploitability else None,
        "security_report": str(security.relative_to(SECURITY_FINDINGS_DIR)) if security else None,
    }

def enrich_reachability(data: dict) -> dict:
    """Backfills/normalizes summary using the vulnerabilities array."""
    vulns = data.get("vulnerabilities") or []
    sev_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    all_counts = {k: 0 for k in sev_levels}
    reach_counts = {k: 0 for k in sev_levels}
    status_counts = {"REACHABLE": 0, "NOT_REACHABLE": 0, "UNKNOWN": 0}

    for v in vulns:
        sev = (v.get("criticality") or v.get("severity") or "UNKNOWN").upper()
        if sev not in all_counts:
            all_counts[sev] = 0
            reach_counts[sev] = 0
        all_counts[sev] += 1

        reach = (v.get("reachability_status") or "UNKNOWN").upper()
        if reach not in status_counts:
            status_counts[reach] = 0
        status_counts[reach] += 1

        if "REACHABLE" in reach:
            reach_counts[sev] += 1

    summary = data.get("summary") or {}
    # Always set total from items if missing/0
    if not summary.get("total_vulnerabilities"):
        summary["total_vulnerabilities"] = len(vulns)

    # If all reachable-by-severity are zero but we have vulns, backfill them
    keys = ["critical_reachable", "high_reachable", "medium_reachable", "low_reachable"]
    if sum(int(summary.get(k, 0) or 0) for k in keys) == 0 and len(vulns) > 0:
        summary["critical_reachable"] = reach_counts.get("CRITICAL", 0)
        summary["high_reachable"]     = reach_counts.get("HIGH", 0)
        summary["medium_reachable"]   = reach_counts.get("MEDIUM", 0)
        summary["low_reachable"]      = reach_counts.get("LOW", 0)

    # Calculate not_reachable: preserve existing value if reasonable, otherwise calculate
    total_reachable = (summary.get("critical_reachable", 0) +
                      summary.get("high_reachable", 0) +
                      summary.get("medium_reachable", 0) +
                      summary.get("low_reachable", 0))

    calculated_not_reachable = summary.get("total_vulnerabilities", 0) - total_reachable
    existing_not_reachable = summary.get("not_reachable", 0)

    # Use existing value if it's reasonable, otherwise use calculated value
    if existing_not_reachable > 0 and existing_not_reachable == calculated_not_reachable:
        # Existing value is correct, keep it
        pass
    elif calculated_not_reachable >= 0:
        # Use calculated value
        summary["not_reachable"] = calculated_not_reachable
    else:
        # Fallback to status counts
        summary["not_reachable"] = status_counts.get("NOT_REACHABLE", 0)

    data["summary"] = summary
    data["_normalized"] = {
        "reachable_by_severity": reach_counts,  # counts for reachable only
        "all_by_severity": all_counts,          # counts regardless of reachability
        "by_status": status_counts,             # REACHABLE / NOT_REACHABLE
    }
    return data


def list_projects() -> List[Dict[str, Any]]:
    projects = []
    if not SECURITY_FINDINGS_DIR.exists():
        return projects

    for child in sorted(SECURITY_FINDINGS_DIR.iterdir()):
        if not child.is_dir():
            continue
        files = project_files(child)
        if any(files.values()):
            # language hint from reachability file name (best-effort)
            lang = None
            if files["reachability_report"]:
                name = Path(files["reachability_report"]).name
                lang = name.replace("_vulnerability_reachability_report.json", "")

            projects.append({
                "name": child.name,
                "language": lang,
                "files": files
            })
    return projects


def load_reachability(project: str) -> Optional[Dict[str, Any]]:
    pdir = SECURITY_FINDINGS_DIR / project
    if not pdir.is_dir():
        return None
    matches = sorted(pdir.glob(REACHABILITY_GLOB))
    if not matches:
        return None
    return _json_load(matches[0])


def load_specific(project: str, kind: str) -> Optional[Any]:
    """
    kind in {"consolidated", "exploitability", "security_report"}
    """
    pdir = SECURITY_FINDINGS_DIR / project
    if not pdir.is_dir():
        return None

    if kind == "consolidated":
        path = _find_first(pdir, ["consolidated.json", "consolidtated.json"])
    elif kind == "exploitability":
        path = _find_first(pdir, ["exploitability_report.json", "exploitability.json"])
    elif kind == "security_report":
        path = _find_first(pdir, ["security_report.json"])
    else:
        path = None

    if not path:
        return None
    return _json_load(path)


def safe_int(x, default=0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def aggregate_summary(all_reports: List[Dict[str, Any]]) -> Dict[str, int]:
    agg = {
        "projects": len(all_reports),
        "total_vulnerabilities": 0,
        "critical_reachable": 0,
        "high_reachable": 0,
        "medium_reachable": 0,
        "low_reachable": 0,
        "not_reachable": 0,
    }
    for rep in all_reports:
        s = rep.get("summary", {})
        agg["total_vulnerabilities"] += safe_int(s.get("total_vulnerabilities", 0))
        agg["critical_reachable"] += safe_int(s.get("critical_reachable", 0))
        agg["high_reachable"] += safe_int(s.get("high_reachable", 0))
        agg["medium_reachable"] += safe_int(s.get("medium_reachable", 0))
        agg["low_reachable"] += safe_int(s.get("low_reachable", 0))
        agg["not_reachable"] += safe_int(s.get("not_reachable", 0))
    return agg


# ---------------------------
# API
# ---------------------------
@app.get("/api/projects")
def api_projects():
    projs = list_projects()
    return jsonify({"root": str(SECURITY_FINDINGS_DIR), "projects": projs})

@app.get("/api/report/<project>")
def api_report(project: str):
    data = load_reachability(project)
    if data is None:
        abort(404, description=f"No reachability report found for '{project}'")
    return jsonify(enrich_reachability(data))


@app.get("/api/files/<project>")
def api_files(project: str):
    pdir = SECURITY_FINDINGS_DIR / project
    if not pdir.exists():
        abort(404, description=f"Project '{project}' not found")
    return jsonify(project_files(pdir))


@app.get("/api/consolidated/<project>")
def api_consolidated(project: str):
    data = load_specific(project, "consolidated")
    if data is None:
        abort(404, description=f"No consolidated.json found for '{project}'")
    # consolidated.json can be a list; return as-is
    return jsonify(data)


@app.get("/api/exploitability/<project>")
def api_exploitability(project: str):
    data = load_specific(project, "exploitability")
    if data is None:
        abort(404, description=f"No exploitability report found for '{project}'")
    return jsonify(data)


@app.get("/api/security/<project>")
def api_security(project: str):
    data = load_specific(project, "security_report")
    if data is None:
        abort(404, description=f"No security_report.json found for '{project}'")
    return jsonify(data)


@app.get("/api/summary")
def api_summary():
    projs = list_projects()
    reports = []
    for p in projs:
        data = load_reachability(p["name"])
        if data:
            reports.append(enrich_reachability(data))
    return jsonify(aggregate_summary(reports))


@app.get("/api/dashboard")
def api_dashboard():
    """Dashboard analytics endpoint with accurate data from findings"""
    projs = list_projects()
    reports = []
    recent_scans = []

    for p in projs:
        data = load_reachability(p["name"])
        if data:
            enriched = enrich_reachability(data)
            reports.append(enriched)

            # Get file metadata for last modified time
            pdir = SECURITY_FINDINGS_DIR / p["name"]
            matches = sorted(pdir.glob(REACHABILITY_GLOB))
            last_modified = None
            if matches:
                try:
                    last_modified = datetime.fromtimestamp(matches[0].stat().st_mtime).isoformat()
                except Exception:
                    last_modified = datetime.now().isoformat()
            else:
                last_modified = datetime.now().isoformat()

            # Build recent scan entry
            summary = enriched.get("summary", {})
            recent_scans.append({
                "id": p["name"],
                "projectName": p["name"].replace("-", " ").title(),
                "projectType": (p.get("language") or "Unknown").title(),
                "status": "completed",
                "findings": {
                    "critical": safe_int(summary.get("critical_reachable", 0)),
                    "high": safe_int(summary.get("high_reachable", 0)),
                    "medium": safe_int(summary.get("medium_reachable", 0)),
                    "low": safe_int(summary.get("low_reachable", 0))
                },
                "lastScan": last_modified
            })

    # Sort by last scan date (most recent first)
    recent_scans.sort(key=lambda x: x["lastScan"], reverse=True)

    # Calculate aggregate summary
    agg = aggregate_summary(reports)
    total_reachable = (agg["critical_reachable"] + agg["high_reachable"] +
                      agg["medium_reachable"] + agg["low_reachable"])

    # Calculate security score (percentage of non-critical vulnerabilities)
    total_vulns = agg["total_vulnerabilities"]
    if total_vulns > 0:
        critical_and_high = agg["critical_reachable"] + agg["high_reachable"]
        security_score = max(0, min(100, int((1 - (critical_and_high / total_vulns)) * 100)))
    else:
        security_score = 100

    return jsonify({
        "summary": {
            "totalScans": len(reports),
            "criticalFindings": agg["critical_reachable"] + agg["high_reachable"],
            "totalProjects": agg["projects"],
            "averageScore": security_score
        },
        "recentScans": recent_scans[:10]  # Return only the 10 most recent
    })


@app.get("/api/debug/<project>")
def api_debug(project: str):
    """Debug endpoint to check project data loading"""
    try:
        # Load all data sources
        reachability = load_reachability(project)
        exploitability = load_specific(project, "exploitability")
        consolidated = load_specific(project, "consolidated")
        security = load_specific(project, "security_report")

        debug_info = {
            "project_name": project,
            "reachability_available": reachability is not None,
            "reachability_vuln_count": len(reachability.get("vulnerabilities", [])) if reachability else 0,
            "exploitability_available": exploitability is not None,
            "consolidated_available": consolidated is not None,
            "security_available": security is not None,
            "sample_vulnerability": reachability.get("vulnerabilities", [{}])[0] if reachability and reachability.get("vulnerabilities") else None
        }

        return jsonify(debug_info)
    except Exception as e:
        return jsonify({"error": str(e)})


# ---------------------------
# Static Webapp Routes
# ---------------------------
@app.get("/webapp/")
@app.get("/webapp/home")
def webapp_index():
    """Serve the new webapp"""
    return send_from_directory("webapp", "index.html")

@app.get("/webapp/findings")
def webapp_findings():
    """Serve findings page"""
    return send_from_directory("webapp", "findings.html")

@app.get("/webapp/create-scan")
def webapp_create_scan():
    """Serve create scan page"""
    return send_from_directory("webapp", "create-scan.html")

@app.get("/webapp/<path:filename>")
def webapp_static(filename):
    """Serve webapp static files (CSS, JS, etc.)"""
    # Don't serve .html files through this route
    if filename.endswith('.html'):
        abort(404)
    return send_from_directory("webapp", filename)

# ---------------------------
# Original Static Routes
# ---------------------------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    if not SECURITY_FINDINGS_DIR.exists():
        print(f"[WARN] SECURITY_FINDINGS_DIR not found: {SECURITY_FINDINGS_DIR}")
    app.run(host="0.0.0.0", port=3000, debug=True)
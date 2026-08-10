"""RBOM — Reachability Bill of Materials assembly and CycloneDX export."""
from __future__ import annotations

from correlation.rbom import build_rbom, rbom_from_scan, to_cyclonedx


def _f(package, verdict, etype="static", **kw):
    return {"package": package, "verdict": verdict, "evidence_type": etype, **kw}


# ── grouping + verdict precedence ─────────────────────────────────────────────

def test_groups_findings_by_component_and_merges_cves():
    rbom = build_rbom([
        _f("flask", "LIKELY", cve_id="CVE-1", confidence=0.65),
        _f("flask", "CONFIRMED", cve_id="CVE-2", confidence=0.95),  # stronger wins
    ])
    comps = {c["name"]: c for c in rbom["components"]}
    assert len(comps) == 1
    assert comps["flask"]["verdict"] == "CONFIRMED"     # strongest across findings
    assert comps["flask"]["confidence"] == 0.95          # max
    assert comps["flask"]["cve_ids"] == ["CVE-1", "CVE-2"]


def test_components_sorted_strongest_first():
    rbom = build_rbom([
        _f("a", "NOT_OBSERVED"), _f("b", "CONFIRMED", cve_id="C"),
        _f("c", "POSSIBLE", cve_id="C2"), _f("d", "LIKELY", cve_id="C3"),
    ])
    assert [c["name"] for c in rbom["components"]] == ["b", "d", "c", "a"]


# ── evidence layers ───────────────────────────────────────────────────────────

def test_static_dynamic_transitive_evidence_layers():
    rbom = build_rbom([
        _f("flask", "CONFIRMED", etype="static", cve_id="C1",
           import_detected=True, call_chain_exists=True, sink_reachable=True),
        _f("flask", "LIKELY", etype="dynamic", cve_id="C1",
           import_detected=True, call_chain_exists=False),
        _f("werkzeug", "POSSIBLE", etype="static", cve_id="C2",
           reachable_via=["flask", "werkzeug"]),
    ])
    comps = {c["name"]: c for c in rbom["components"]}
    ev = comps["flask"]["evidence"]
    assert ev["static"] == {"import_detected": True, "call_chain_exists": True, "sink_reachable": True}
    assert ev["dynamic"] == {"loaded": True, "executed": False, "sink_reachable": False}
    assert comps["werkzeug"]["evidence"]["transitive"]["reachable_via"] == ["flask", "werkzeug"]
    assert comps["werkzeug"]["direct"] is False


def test_reads_signals_from_nested_evidence_dict():
    # correlation rows carry the booleans inside an `evidence` sub-dict.
    rbom = build_rbom([{
        "package": "requests", "cve_id": "CVE-X",
        "evidence": {"verdict": "LIKELY", "evidence_type": "dynamic",
                     "import_detected": True, "call_chain_exists": False},
    }])
    c = rbom["components"][0]
    assert c["verdict"] == "LIKELY"
    assert c["evidence"]["dynamic"]["loaded"] is True


# ── inventory enrichment + summary ────────────────────────────────────────────

def test_inventory_adds_non_vulnerable_components():
    rbom = build_rbom(
        [_f("flask", "CONFIRMED", cve_id="C1")],
        components=[{"name": "left-pad", "ecosystem": "node", "version": "1.0.0", "direct": False}],
    )
    comps = {c["name"]: c for c in rbom["components"]}
    assert comps["left-pad"]["verdict"] == "NOT_OBSERVED"
    assert comps["left-pad"]["cve_ids"] == []
    assert comps["left-pad"]["reachable"] is False


def test_summary_counts_reachable_and_vulnerable():
    rbom = build_rbom([
        _f("flask", "CONFIRMED", cve_id="C1"),     # reachable + vulnerable
        _f("requests", "LIKELY", cve_id="C2"),      # reachable + vulnerable
        _f("lodash", "NOT_OBSERVED", cve_id="C3"),  # vulnerable, not reachable
        _f("used-lib", "LIKELY"),                   # reachable, not vulnerable
    ])
    s = rbom["summary"]
    assert s["total_components"] == 4
    assert s["reachable"] == 3
    assert s["vulnerable"] == 3
    assert s["reachable_and_vulnerable"] == 2   # the actionable set
    assert s["by_verdict"] == {"CONFIRMED": 1, "LIKELY": 2, "POSSIBLE": 0, "NOT_OBSERVED": 1}


# ── CycloneDX / VEX ───────────────────────────────────────────────────────────

def test_cyclonedx_maps_reachability_to_vex_state():
    rbom = build_rbom([
        _f("flask", "CONFIRMED", ecosystem="python", cve_id="CVE-1", version="2.0.1"),
        _f("lodash", "NOT_OBSERVED", ecosystem="node", cve_id="CVE-2"),
        _f("werkzeug", "POSSIBLE", ecosystem="python", cve_id="CVE-3"),
    ])
    cdx = to_cyclonedx(rbom)
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    vex = {v["id"]: v["analysis"] for v in cdx["vulnerabilities"]}
    assert vex["CVE-1"]["state"] == "exploitable"
    assert vex["CVE-2"]["state"] == "not_affected"
    assert vex["CVE-2"]["justification"] == "code_not_reachable"
    assert vex["CVE-3"]["state"] == "in_triage"


def test_cyclonedx_purls_and_properties():
    rbom = build_rbom([_f("flask", "CONFIRMED", ecosystem="python", cve_id="C", version="2.0.1")])
    cdx = to_cyclonedx(rbom)
    comp = cdx["components"][0]
    assert comp["purl"] == "pkg:pypi/flask@2.0.1"
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["vulnreach:reachability"] == "CONFIRMED"


def test_rbom_from_scan_uses_correlation_and_project_metadata():
    """The shared helper both API and package mode call: RBOM from a stored scan."""
    scan = {
        "scan_id": "s-123", "repo_name": "demo-app", "repo_url": "https://x/demo",
        "correlation": [
            _f("flask", "CONFIRMED", ecosystem="python", cve_id="CVE-1", version="2.0.1"),
            _f("lodash", "NOT_OBSERVED", ecosystem="node", cve_id="CVE-2"),
        ],
    }
    rbom = rbom_from_scan(scan)
    assert rbom["project"] == {"name": "demo-app", "repo": "https://x/demo", "scan_id": "s-123"}
    assert rbom["summary"]["reachable_and_vulnerable"] == 1
    assert {c["name"] for c in rbom["components"]} == {"flask", "lodash"}


def test_empty_scan_produces_valid_empty_rbom():
    rbom = build_rbom([])
    assert rbom["summary"]["total_components"] == 0
    assert rbom["components"] == []
    cdx = to_cyclonedx(rbom)
    assert cdx["components"] == [] and cdx["vulnerabilities"] == []

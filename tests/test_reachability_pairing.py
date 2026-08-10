from correlation.service import CorrelationService


def test_correlation_uses_package_and_cve_pair() -> None:
    service = CorrelationService()

    vulnerabilities = [
        {"package": "pkg-one", "cve_id": ["CVE-2026-0001"], "severity": "HIGH"},
        {"package": "pkg-two", "cve_id": ["CVE-2026-0001"], "severity": "HIGH"},
    ]

    static_reachability = {
        ("pkg-one", "CVE-2026-0001"): {
            "import_detected": True,
            "call_chain_exists": True,
            "sink_reachable": False,
            "evidence_type": "static",
            "confidence": 0.7,
            "function": "doWork",
            "files": ["app.py"],
        }
    }

    result = service.correlate(
        vulnerabilities=vulnerabilities,
        static_reachability=static_reachability,
        dynamic_reachability={},
        exposure="public",
        policy_rules=[],
        semgrep_findings=[],
        dast_findings=[],
    )

    findings = {
        (f.get("package"), f.get("cve_id")): f
        for f in result["correlation"]
        if f.get("package")
    }

    one = findings[("pkg-one", "CVE-2026-0001")]
    two = findings[("pkg-two", "CVE-2026-0001")]

    assert one["reachability_class"] == "STATICALLY_REACHABLE"
    assert one["verdict"] in {"LIKELY", "POSSIBLE"}
    assert two["reachability_class"] == "NOT_REACHABLE"
    assert two["verdict"] == "NOT_OBSERVED"


def test_static_taint_grounded_sink_yields_confirmed() -> None:
    """import + call chain + a taint-grounded sink ⇒ CONFIRMED, matching the
    canonical reachability_verdict rule. Previously the correlation layer capped
    every static finding at LIKELY, discarding the agents' taint grounding."""
    service = CorrelationService()

    result = service.correlate(
        vulnerabilities=[{"package": "flask", "cve_id": ["CVE-2026-9999"], "severity": "HIGH"}],
        static_reachability={
            ("flask", "CVE-2026-9999"): {
                "import_detected": True,
                "call_chain_exists": True,
                "sink_reachable": True,  # tainter cross-referenced a source→sink path
                "evidence_type": "static",
                "function": "render_template_string",
                "files": ["app.py"],
            }
        },
        dynamic_reachability={},
        exposure="public",
        policy_rules=[],
        semgrep_findings=[],
        dast_findings=[],
    )

    finding = next(f for f in result["correlation"] if f.get("package") == "flask")
    assert finding["reachability_class"] == "STATICALLY_REACHABLE"
    assert finding["verdict"] == "CONFIRMED"

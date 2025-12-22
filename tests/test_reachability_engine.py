import json
import os
from pathlib import Path

from vulnreach.utils.reachability_engine import run_reachability_engine

FIXTURES = Path(__file__).parent / "fixtures"


def test_reachability_engine_links_sinks_and_routes(tmp_path):
    project_root = FIXTURES
    findings_dir = tmp_path

    semgrep_src = FIXTURES / "semgrep_sample.json"
    routes_src = FIXTURES / "routes_sample.json"

    semgrep_dst = findings_dir / "semgrep.json"
    routes_dst = findings_dir / "routes.json"

    semgrep_dst.write_bytes(semgrep_src.read_bytes())
    routes_dst.write_bytes(routes_src.read_bytes())

    results = run_reachability_engine(str(project_root), str(findings_dir))

    output_path = findings_dir / "sink_handler_reachability.json"
    assert output_path.exists(), "engine should emit sink_handler_reachability.json"

    payload = json.loads(output_path.read_text())

    # Ensure only scored findings above threshold are kept
    assert payload["total"] == len(results) == 2

    # First finding: logger inside login handler, has route, has taint hint
    first = next(f for f in payload["findings"] if f["rule_id"].endswith("dangerous-logger"))
    assert first["handler"] == "login"
    assert first["route"]["path"] == "/login"
    assert first["reachability_score"] >= 0.5
    assert "taint" in first["reason"]

    # Second finding: set_cookie inside login handler, has route, no taint hint
    second = next(f for f in payload["findings"] if f["rule_id"].endswith("cookie-no-httponly"))
    assert second["handler"] in {"login", None}
    assert second["route"]["path"] in {"/login", "/health"}
    assert second["reachability_score"] >= 0.4


def test_reachability_engine_skips_low_signal(tmp_path):
    project_root = FIXTURES
    findings_dir = tmp_path

    low_signal = {
        "tool": "semgrep",
        "normalized_findings": [
            {
                "rule_id": "python.lang.best-practice.some-low-signal",
                "file": "app.py",
                "line": 99,
                "sink_function": "noop",
                "taint_hint": None,
                "message": "low signal",
                "severity": "LOW",
                "metadata": {}
            }
        ]
    }

    (findings_dir / "semgrep.json").write_text(json.dumps(low_signal), encoding="utf-8")

    results = run_reachability_engine(str(project_root), str(findings_dir))

    output_path = findings_dir / "sink_handler_reachability.json"
    payload = json.loads(output_path.read_text())

    assert payload["total"] == len(results) == 0
    assert payload["findings"] == []


def test_reachability_engine_missing_semgrep(tmp_path):
    project_root = FIXTURES
    findings_dir = tmp_path

    # routes exist but semgrep missing -> should raise FileNotFoundError
    (findings_dir / "routes.json").write_bytes((FIXTURES / "routes_sample.json").read_bytes())

    try:
        run_reachability_engine(str(project_root), str(findings_dir))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError when semgrep.json is absent")

"""Transitive reachability — a vulnerable dep reached through a used package.

Plain unit tests (no Docker). Validated end-to-end by the Tier 3 oracle
(observer/e2e/static_vs_runtime.py), which measured recall on labs/python_vuln_app
rising 0.33 → 0.89 once these upgrades were applied, precision holding at 1.00.
"""
from __future__ import annotations

import json
import textwrap

from agents.reachability.transitive import (
    apply_transitive, requires_graph_from_lockfile,
    requires_graph_from_site_packages, transitive_paths,
)


_FLASK_STACK = {
    "flask": {"werkzeug", "jinja2", "click", "itsdangerous"},
    "jinja2": {"markupsafe"},
    "werkzeug": {"markupsafe"},
    "requests": {"urllib3", "certifi", "idna"},
}


def test_transitive_paths_shortest_chain():
    paths = transitive_paths(["flask", "requests"], _FLASK_STACK)
    assert paths["werkzeug"] == ["flask", "werkzeug"]
    assert paths["urllib3"] == ["requests", "urllib3"]
    # markupsafe is reachable via both flask→jinja2 and flask→werkzeug; either
    # 3-hop chain is acceptable, but it must be shortest (no longer path).
    assert len(paths["markupsafe"]) == 3
    # a root is never listed as reachable-from-itself
    assert "flask" not in paths


def test_apply_transitive_upgrades_only_not_observed():
    findings = [
        {"package": "Flask", "verdict": "CONFIRMED"},
        {"package": "Werkzeug", "verdict": "NOT_OBSERVED"},
        {"package": "Jinja2", "verdict": "NOT_OBSERVED"},
        {"package": "lxml", "verdict": "NOT_OBSERVED"},   # not a dep of anything used
    ]
    apply_transitive(findings, _FLASK_STACK)
    by = {f["package"]: f for f in findings}
    # CONFIRMED is left alone
    assert by["Flask"]["verdict"] == "CONFIRMED"
    assert by["Flask"].get("reachable_via") is None
    # transitive vuln deps become POSSIBLE with a parent chain
    assert by["Werkzeug"]["verdict"] == "POSSIBLE"
    assert by["Werkzeug"]["reachable_via"] == ["flask", "werkzeug"]
    assert by["Jinja2"]["verdict"] == "POSSIBLE"
    # a package no used package depends on stays NOT_OBSERVED
    assert by["lxml"]["verdict"] == "NOT_OBSERVED"
    assert by["lxml"].get("reachable_via") is None


def test_apply_transitive_noop_without_used_roots():
    # Nothing directly used ⇒ nothing to reach through ⇒ no upgrades.
    findings = [{"package": "Werkzeug", "verdict": "NOT_OBSERVED"}]
    apply_transitive(findings, _FLASK_STACK)
    assert findings[0]["verdict"] == "NOT_OBSERVED"


def test_apply_transitive_noop_with_empty_graph():
    findings = [{"package": "Flask", "verdict": "CONFIRMED"},
                {"package": "Werkzeug", "verdict": "NOT_OBSERVED"}]
    apply_transitive(findings, {})
    assert findings[1]["verdict"] == "NOT_OBSERVED"


def test_requires_graph_from_poetry_lock(tmp_path):
    """poetry.lock is the static-time graph source: [package.dependencies] edges.

    This is what makes transitive reachability work in a real scan — the agent
    has the repo source but not the app's installed env, and a lockfile carries
    the resolved dependency graph.
    """
    (tmp_path / "poetry.lock").write_text(textwrap.dedent("""\
        [[package]]
        name = "Flask"
        version = "2.0.1"
        [package.dependencies]
        Werkzeug = ">=2.0"
        Jinja2 = ">=3.0"

        [[package]]
        name = "Jinja2"
        version = "3.0.0"
        [package.dependencies]
        MarkupSafe = ">=2.0"
    """))
    graph = requires_graph_from_lockfile(str(tmp_path))
    assert graph["flask"] == {"werkzeug", "jinja2"}
    # closure reaches the grandchild
    assert "markupsafe" in transitive_paths(["flask"], graph)


def test_requires_graph_from_uv_lock(tmp_path):
    (tmp_path / "uv.lock").write_text(textwrap.dedent("""\
        [[package]]
        name = "flask"
        dependencies = [
          { name = "werkzeug" },
          { name = "jinja2" },
        ]
    """))
    graph = requires_graph_from_lockfile(str(tmp_path))
    assert graph["flask"] == {"werkzeug", "jinja2"}


def test_requires_graph_no_lockfile_is_empty(tmp_path):
    # A pinned requirements.txt has no edges → no graph → honest no-op.
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\nwerkzeug==2.0.1\n")
    assert requires_graph_from_lockfile(str(tmp_path)) == {}


# ── Node (npm package-lock.json) ──────────────────────────────────────────────

def test_node_package_lock_v3(tmp_path):
    """npm lockfileVersion 2/3 keys packages by install path; edges under
    `dependencies`. Scoped and nested packages must resolve correctly."""
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "^4.18.0"}},
            "node_modules/express": {"dependencies": {"accepts": "~1.3.8"}},
            "node_modules/accepts": {"dependencies": {"mime-types": "~2.1.34"}},
            "node_modules/@scope/util": {"dependencies": {"lodash.merge": "^4.0.0"}},
            "node_modules/express/node_modules/debug": {},  # nested, no deps
        },
    }))
    graph = requires_graph_from_lockfile(str(tmp_path), ecosystem="node")
    assert graph["express"] == {"accepts"}
    assert graph["@scope/util"] == {"lodash-merge"}   # lodash.merge normalized
    # closure reaches the grandchild through accepts
    assert "mime-types" in transitive_paths(["express"], graph)


def test_node_package_lock_v1(tmp_path):
    """npm lockfileVersion 1 nests a dependency tree; edges under `requires`."""
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "requires": {"accepts": "~1.3.8"},
                "dependencies": {"debug": {"requires": {"ms": "2.0.0"}}},
            },
        },
    }))
    graph = requires_graph_from_lockfile(str(tmp_path), ecosystem="node")
    assert graph["express"] == {"accepts"}
    assert graph["debug"] == {"ms"}


def test_node_transitive_upgrades_unused_dep_via_bridge():
    """End-to-end shape: an unused npm package that a used one depends on becomes
    POSSIBLE with a parent chain — the Node analogue of the Flask→Werkzeug case."""
    from agents.reachability.agent_bridge import MultiLanguageReachabilityBridge

    graph = {"express": {"accepts"}}
    report = {"analyses": [
        {"package_name": "express", "is_used": True, "call_chain_graph": "graph TD;",
         "usage_contexts": []},
        {"package_name": "accepts", "is_used": False, "call_chain_graph": None,
         "usage_contexts": []},
    ]}
    vulns = [{"package": "express", "cve_id": ["CVE-E"]},
             {"package": "accepts", "cve_id": ["CVE-A"]}]

    bridge = MultiLanguageReachabilityBridge()
    findings = bridge._map_findings(report, vulns, "javascript", set())
    apply_transitive(findings, graph)
    by = {f["package"]: f for f in findings}

    assert by["express"]["verdict"] in ("POSSIBLE", "LIKELY")   # directly used
    assert by["accepts"]["verdict"] == "POSSIBLE"               # transitively reached
    assert by["accepts"]["reachable_via"] == ["express", "accepts"]


def test_agent_requires_graph_uses_lockfile_not_scanner_env(tmp_path):
    """The production wiring: the agent must source the graph from the repo's
    lockfile, not the scanner's own environment (which holds vulnreach's deps,
    never the target app's — the bug this fixes made transitive a silent no-op).
    """
    from agents.agent_python_reachability import PythonReachabilityAgent

    (tmp_path / "poetry.lock").write_text(textwrap.dedent("""\
        [[package]]
        name = "flask"
        [package.dependencies]
        werkzeug = ">=2.0"
    """))

    class _Ctx:
        repo_path = str(tmp_path)

    graph = PythonReachabilityAgent()._requires_graph(_Ctx())
    assert graph.get("flask") == {"werkzeug"}, \
        "agent did not read the repo lockfile for the transitive graph"


# ── Container-metadata source (runtime back-stop) ─────────────────────────────

def test_requires_graph_from_container_node_modules(tmp_path):
    """Node graph from an installed node_modules tree (the runtime source).

    Works even when the repo ships no lockfile, and handles scoped packages.
    """
    from agents.reachability.transitive import requires_graph_from_container

    for name, deps in [("express", {"accepts": "1"}),
                       ("accepts", {"mime-types": "1"}),
                       ("@scope/util", {"lodash": "1"})]:
        d = tmp_path / "app" / "node_modules"
        for seg in name.split("/"):
            d = d / seg
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": name, "dependencies": deps}))
    graph = requires_graph_from_container(str(tmp_path), "node")
    assert graph["express"] == {"accepts"}
    assert graph["@scope/util"] == {"lodash"}


def test_container_transitive_backstop_in_verdict_integration():
    """A vulnerable dep that never loaded but is reachable via a LOADED package
    becomes POSSIBLE (structural), not NOT_OBSERVED. The observer's reached set
    is the closure root."""
    from agents.ebpf.reachability import PackageReach, POTENTIALLY_REACHABLE
    from agents.ebpf.verdict_integration import to_reachability_findings

    reach = {"node:express": PackageReach(
        name="express", ecosystem="node", version="4",
        verdict=POTENTIALLY_REACHABLE, rule="R1")}
    graph = {"express": {"accepts"}}
    vulns = [
        {"package": "express", "cve_id": ["CVE-E"]},   # loaded
        {"package": "accepts", "cve_id": ["CVE-A"]},   # not loaded, dep of express
        {"package": "left-pad", "cve_id": ["CVE-L"]},  # not loaded, unreachable
    ]
    by_pkg = {f.package: f for f in
              to_reachability_findings(reach, vulns, requires_graph=graph)}
    assert by_pkg["express"].verdict == "LIKELY"           # observed loading
    assert by_pkg["accepts"].verdict == "POSSIBLE"         # structural back-stop
    assert by_pkg["accepts"].reachable_via == ["express", "accepts"]
    assert by_pkg["left-pad"].verdict == "NOT_OBSERVED"    # neither observed nor reachable


def test_container_backstop_noop_without_graph():
    """Without a container graph, an unloaded vuln stays NOT_OBSERVED (unchanged)."""
    from agents.ebpf.reachability import PackageReach, POTENTIALLY_REACHABLE
    from agents.ebpf.verdict_integration import to_reachability_findings

    reach = {"node:express": PackageReach(name="express", ecosystem="node",
                                          version="4", verdict=POTENTIALLY_REACHABLE, rule="R1")}
    f = to_reachability_findings(reach, [{"package": "accepts", "cve_id": ["C"]}])[0]
    assert f.verdict == "NOT_OBSERVED"
    assert f.reachable_via is None


def test_requires_graph_from_site_packages_parses_metadata(tmp_path):
    """The graph reader must handle the real METADATA header shape.

    Regression guard: the Name value carries leading whitespace ("Name: Flask")
    and Requires-Dist entries carry version specifiers and extras — the first
    cut keyed the graph on " flask\\n" and the flask→werkzeug edge was lost.
    """
    sp = tmp_path / "site-packages"
    dist = sp / "Flask-2.0.1.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text(textwrap.dedent("""\
        Metadata-Version: 2.1
        Name: Flask
        Version: 2.0.1
        Requires-Dist: Werkzeug (>=2.0)
        Requires-Dist: Jinja2 (>=3.0)
        Requires-Dist: asgiref (>=3.2) ; extra == 'async'

        Flask is a lightweight WSGI web application framework.
    """))
    graph = requires_graph_from_site_packages(str(sp))
    assert "flask" in graph, f"Name not parsed cleanly: {list(graph)}"
    assert "werkzeug" in graph["flask"]
    assert "jinja2" in graph["flask"]
    # extras are optional deps, not part of the default closure
    assert "asgiref" not in graph["flask"]

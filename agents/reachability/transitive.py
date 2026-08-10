"""Transitive reachability — a vulnerable dependency reached through a used one.

The app uses Flask; Flask depends on Werkzeug; a Werkzeug CVE is therefore
reachable *through* Flask even though the app never imports werkzeug itself.
Source-scanning static reachability cannot see this — it only finds direct
imports — so such packages score NOT_OBSERVED, a false negative that hides a
genuinely reachable CVE (measured on labs/python_vuln_app: 5 of 6 runtime-loaded
misses were exactly this shape).

This lifts those to **POSSIBLE**: the vulnerable package is present and pulled in
by code the app actually uses, but there is no proof its vulnerable sink is
exercised on the app's own path — which is precisely what POSSIBLE means. The
chain from a used root to the package is recorded as evidence (Reachability
Finding.reachable_via).

The dependency graph must come from the *target app's* environment (its installed
package metadata), not the scanner's — Flask→Werkzeug is only knowable from where
Flask is installed. `requires_graph_from_site_packages` reads it from a site-
packages tree (e.g. the container root the dynamic path already inspects);
`requires_graph_from_env` is the fallback when the scanner shares the app's venv.
"""
from __future__ import annotations

import os
import re
from collections import deque
from typing import Dict, Iterable, List, Optional, Set

from agents.ebpf.package_index import _norm

# "Requires-Dist: werkzeug>=2.0" / "Werkzeug (>=2.0)" → werkzeug
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_dist_name(requirement: str) -> Optional[str]:
    m = _REQ_NAME.match(requirement or "")
    return _norm(m.group(1)) if m else None


def _is_optional(requirement: str) -> bool:
    # Deps that only apply under an extra are optional and not installed by
    # default, so they are not part of the always-present transitive closure.
    return "extra ==" in requirement or "extra==" in requirement


def requires_graph_from_site_packages(root: str, max_depth: int = 9) -> Dict[str, Set[str]]:
    """dist → set(dist it requires), parsed from ``*.dist-info/METADATA`` under *root*.

    *root* is a filesystem path containing site-packages (a container's
    ``/proc/<pid>/root`` or any prefix). Returns {} if nothing is found — the
    caller then simply makes no transitive upgrades.
    """
    graph: Dict[str, Set[str]] = {}
    root = root.rstrip("/")
    base_depth = root.count("/")
    for dirpath, dirs, files in os.walk(root):
        if dirpath.count("/") - base_depth > max_depth:
            dirs[:] = []
            continue
        if not dirpath.endswith(".dist-info"):
            continue
        dirs[:] = []  # don't descend into a dist-info
        meta = os.path.join(dirpath, "METADATA")
        if not os.path.isfile(meta):
            continue
        name: Optional[str] = None
        deps: Set[str] = set()
        try:
            with open(meta, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("Name:"):
                        name = _norm(line.split(":", 1)[1].strip())
                    elif line.startswith("Requires-Dist:"):
                        req = line.split(":", 1)[1].strip()
                        if not _is_optional(req):
                            dep = _req_dist_name(req)
                            if dep:
                                deps.add(dep)
                    elif line == "\n":
                        break  # headers end at the first blank line
        except OSError:
            continue
        if name:
            graph.setdefault(name, set()).update(deps)
    return graph


def requires_graph_from_lockfile(repo_path: str, ecosystem: str = "python") -> Dict[str, Set[str]]:
    """Resolved dependency graph (name → set(names it requires)) from a repo lockfile.

    This is the source that works at *static* time without the app's installed
    environment: a lockfile encodes the resolved graph and ships in the repo.

    - python: poetry.lock, uv.lock (both carry explicit inter-package edges).
    - node/javascript: package-lock.json (npm lockfileVersion 1/2/3).

    Pipfile.lock and yarn.lock are not (yet) supported — the former records
    versions but not edges; the latter needs a custom parser. Java/Maven has no
    source-time transitive graph (Maven resolves it at build), so it is not
    handled here; that requires the built jars, which the container path exposes.

    Names are normalized the same way ``apply_transitive`` normalizes finding
    packages, so the graph and the findings align regardless of ecosystem
    quirks. Returns {} when no supported lockfile is present.
    """
    eco = (ecosystem or "python").strip().lower()
    if eco in ("node", "javascript", "js", "typescript"):
        return _node_lockfile_graph(repo_path)
    if eco == "python":
        return _python_lockfile_graph(repo_path)
    return {}


def _python_lockfile_graph(repo_path: str) -> Dict[str, Set[str]]:
    import tomllib

    graph: Dict[str, Set[str]] = {}
    for name in ("poetry.lock", "uv.lock"):
        lock = os.path.join(repo_path, name)
        if not os.path.isfile(lock):
            continue
        try:
            with open(lock, "rb") as fh:
                data = tomllib.load(fh)
        except (OSError, ValueError):
            continue
        for pkg in data.get("package", []):
            pkg_name = _norm(str(pkg.get("name", "")))
            if not pkg_name:
                continue
            deps: Set[str] = set()
            # poetry.lock: [package.dependencies] is a table {dep = constraint}.
            raw = pkg.get("dependencies")
            if isinstance(raw, dict):
                deps.update(_norm(k) for k in raw)
            # uv.lock: dependencies = [{ name = "dep" }, ...]
            elif isinstance(raw, list):
                for d in raw:
                    if isinstance(d, dict) and d.get("name"):
                        deps.add(_norm(str(d["name"])))
            graph.setdefault(pkg_name, set()).update(deps)
        if graph:
            return graph
    return graph


def _node_lockfile_graph(repo_path: str) -> Dict[str, Set[str]]:
    """npm package-lock.json → dependency graph, across lockfileVersion 1/2/3.

    v2/v3 key packages by install path (``node_modules/<name>``, nested for
    version conflicts); the package name is the segment after the last
    ``node_modules/``. v1 nests a ``dependencies`` tree where each entry lists
    its edges under ``requires``. Both scoped (``@scope/pkg``) and nested
    packages are handled.
    """
    import json

    lock = os.path.join(repo_path, "package-lock.json")
    if not os.path.isfile(lock):
        return {}
    try:
        with open(lock, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}

    graph: Dict[str, Set[str]] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue  # "" is the root project
            name = path.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            deps: Set[str] = set()
            for key in ("dependencies", "optionalDependencies"):
                d = info.get(key)
                if isinstance(d, dict):
                    deps.update(_norm(k) for k in d)
            graph.setdefault(_norm(name), set()).update(deps)
    else:  # lockfileVersion 1: nested tree with "requires"
        def _walk(deps):
            if not isinstance(deps, dict):
                return
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                reqs = info.get("requires")
                if isinstance(reqs, dict):
                    graph.setdefault(_norm(name), set()).update(_norm(k) for k in reqs)
                _walk(info.get("dependencies"))
        _walk(data.get("dependencies"))
    return graph


def requires_graph_from_container(container_root: str, ecosystem: str = "node") -> Dict[str, Set[str]]:
    """Dependency graph from the target app's *installed* packages in a container.

    Complements the lockfile source: the runtime path has the container root
    (``/proc/<pid>/root``) with every dependency installed, so the graph exists
    even for a repo that ships no lockfile. Used to back-stop the eBPF observer —
    a vulnerable dependency that is installed and reachable via a *loaded*
    package, but that did not itself load during the traffic window, becomes
    POSSIBLE rather than NOT_OBSERVED.

    Node only for now: npm's package name is consistent across the install dir,
    package.json, and the vuln feed, so the graph and the observer's reached set
    share a namespace. Python (dist-vs-import) and Java (pom parsing) need name
    reconciliation and are not handled here yet.
    """
    eco = (ecosystem or "").strip().lower()
    if eco in ("node", "javascript", "js", "typescript"):
        return _node_modules_graph(container_root)
    return {}


def _node_modules_graph(container_root: str, max_depth: int = 12) -> Dict[str, Set[str]]:
    import json

    graph: Dict[str, Set[str]] = {}
    root = container_root.rstrip("/")
    base_depth = root.count("/")
    for dirpath, dirs, files in os.walk(root):
        if dirpath.count("/") - base_depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
        # A package's own manifest lives directly inside a node_modules/<pkg>/.
        if "package.json" not in files or os.sep + "node_modules" not in dirpath:
            continue
        try:
            with open(os.path.join(dirpath, "package.json"), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        name = data.get("name")
        if not isinstance(name, str) or not name:
            continue
        deps: Set[str] = set()
        for key in ("dependencies", "optionalDependencies"):
            d = data.get(key)
            if isinstance(d, dict):
                deps.update(_norm(k) for k in d)
        graph.setdefault(_norm(name), set()).update(deps)
    return graph


def requires_graph_from_env() -> Dict[str, Set[str]]:
    """Fallback graph from the *current* interpreter's installed packages.

    Correct only when the scanner runs in (or shares) the target app's venv.
    """
    import importlib.metadata as importlib_metadata

    graph: Dict[str, Set[str]] = {}
    try:
        dists = list(importlib_metadata.distributions())
    except Exception:
        return graph
    for dist in dists:
        try:
            name = _norm(dist.metadata["Name"])
        except Exception:
            continue
        deps: Set[str] = set()
        for req in (dist.requires or []):
            if _is_optional(req):
                continue
            dep = _req_dist_name(req)
            if dep:
                deps.add(dep)
        graph.setdefault(name, set()).update(deps)
    return graph


def apply_transitive(finding_map: List[dict], requires_graph: Dict[str, Set[str]]) -> List[dict]:
    """Upgrade NOT_OBSERVED findings that are transitively reachable to POSSIBLE.

    A finding's package that the app never imports directly (NOT_OBSERVED) but
    that a directly-used package depends on becomes POSSIBLE, with the parent
    chain recorded in ``reachable_via``. Mutates and returns *finding_map*.
    """
    from correlation.engine import confidence_from_verdict

    if not requires_graph:
        return finding_map
    used_roots = {_norm(f.get("package") or "")
                  for f in finding_map
                  if f.get("verdict") not in (None, "NOT_OBSERVED")}
    if not used_roots:
        return finding_map
    paths = transitive_paths(used_roots, requires_graph)
    for f in finding_map:
        if f.get("verdict") != "NOT_OBSERVED":
            continue
        chain = paths.get(_norm(f.get("package") or ""))
        if chain:
            f["verdict"] = "POSSIBLE"
            f["confidence"] = confidence_from_verdict("POSSIBLE")
            f["reachable_via"] = chain
    return finding_map


def transitive_paths(used_roots: Iterable[str], graph: Dict[str, Set[str]],
                     max_depth: int = 6) -> Dict[str, List[str]]:
    """Shortest dependency chain from a used root to each reachable dist.

    Returns {dist → [root, …, dist]} for every dist reachable from a used root,
    excluding the roots themselves. BFS, so the first path found is shortest.
    """
    roots = {_norm(r) for r in used_roots if r}
    paths: Dict[str, List[str]] = {}
    queue: deque = deque((r, [r]) for r in roots)
    while queue:
        node, path = queue.popleft()
        if len(path) > max_depth:
            continue
        for dep in graph.get(node, ()):
            if dep in roots or dep in paths:
                continue
            paths[dep] = path + [dep]
            queue.append((dep, path + [dep]))
    return paths

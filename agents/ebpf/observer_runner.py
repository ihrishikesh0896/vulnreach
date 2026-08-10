"""Observer orchestration — attach to a running container and produce findings.

This is the single entrypoint the DynamicReachabilityAgent calls for the eBPF
"observer" engine. It ties the pieces together:

    resolve container → cgroup id        (target_resolver)
    build Package-Index from /proc root  (package_index)
    run the observer over a traffic window (observer_client)
    correlate opens → package reach      (reachability, Rule R1)
    map to canonical ReachabilityFinding (verdict_integration, D5/D6)

Kept separate from the agent so the whole path is unit-testable against a real
container without standing up a full scan (OpenAPI/schemathesis/etc.).
"""
from __future__ import annotations

import asyncio
import glob
import os
import platform
import time
from typing import Any, Awaitable, Callable, Optional

from core.models import ReachabilityFinding
from agents.ebpf.target_resolver import DockerTargetResolver
from agents.ebpf.observer_client import ObserverClient, _DEFAULT_BIN
from agents.ebpf.package_index import build_index
from agents.ebpf.reachability import correlate_opens
from agents.reachability.transitive import requires_graph_from_container
from agents.ebpf.verdict_integration import (
    to_reachability_findings,
    taint_modules as _taint_modules,
)


def observer_available(binary_path: str = _DEFAULT_BIN) -> tuple[bool, str]:
    """Return (available, reason). Bypasses the legacy bpftrace/LinuxKit gate.

    The observer only needs a Linux host, the built binary, and kernel BTF —
    it works on modern LinuxKit (Docker Desktop 6.x) where the old bpftrace
    check in _ebpf_available() false-negatives.
    """
    if platform.system() != "Linux":
        return False, "not_linux"
    if not os.path.exists(binary_path):
        return False, f"observer_binary_missing:{binary_path}"
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return False, "btf_unavailable"
    return True, "ok"


# How long the CPython uprobe stays live once traffic starts. Measured cost of
# staying attached (agents/ebpf/observer/e2e/bench_uprobe.py, Docker Desktop
# 6.12 arm64): median Flask request latency 2.9x on CPython 3.11+, 10.1x on
# <=3.10 — on 3.11+ the eval loop inlines Python->Python calls so only C->Python
# transitions trap, while every call traps below that. Rule R5 only needs each
# source file to execute once while we listen, and a served request path repeats
# constantly, so a few seconds of traffic yields the same evidence at a small
# fraction of the cost. 0 disables the bound (attached until the run ends).
_DEFAULT_TIER_B_WINDOW = int(os.environ.get("VULNREACH_EBPF_TIER_B_WINDOW", "5"))


class TrafficWindow:
    """Marks the boot→traffic boundary for Rule R5.

    The caller calls :meth:`mark` once the target is healthy and real traffic is
    about to start. Everything the interpreter ran before that is startup/import
    work; everything after is request handling. Uses CLOCK_MONOTONIC to line up
    with the observer's ``ts_ns`` (``bpf_ktime_get_ns``).

    If nobody marks it, ``start_ns`` stays None and R5 falls back to counting any
    executed frame — the pre-boundary behaviour.
    """

    __slots__ = ("start_ns", "_hooks")

    def __init__(self) -> None:
        self.start_ns: Optional[int] = None
        self._hooks: list[Callable[[], None]] = []

    def attach(self, hook: Callable[[], None]) -> None:
        """Register a side effect to run on mark (the runner attaches the
        observer's epoch bump here)."""
        self._hooks.append(hook)

    def mark(self) -> None:
        if self.start_ns is not None:
            return
        self.start_ns = time.monotonic_ns()
        for hook in self._hooks:
            hook()


def find_libpython(container_root: str) -> Optional[str]:
    """Locate the target's libpython for the Tier B uprobe (Rule R5).

    Returns a host-visible path (under ``/proc/<pid>/root``) or None. CPython is
    normally built ``--enable-shared`` in the official images, so the eval loop
    lives in libpython3.X.so; where it doesn't, the symbol is in the interpreter
    binary itself, so we fall back to that.

    None is not an error — Tier B is optional by design and the caller keeps the
    Tier A baseline either way.
    """
    patterns = (
        "usr/local/lib/libpython3.*.so*",
        "usr/lib/*/libpython3.*.so*",
        "usr/lib/libpython3.*.so*",
    )
    for pat in patterns:
        for hit in sorted(glob.glob(os.path.join(container_root, pat))):
            if os.path.isfile(hit):
                return hit
    # Statically-linked interpreter: the uprobe target is the binary.
    for pat in ("usr/local/bin/python3.*", "usr/bin/python3.*"):
        for hit in sorted(glob.glob(os.path.join(container_root, pat))):
            if os.path.isfile(hit) and not os.path.islink(hit):
                return hit
    return None


def find_libjvm(container_root: str) -> Optional[str]:
    """Locate the target's libjvm.so for the Java Tier B probe (Rule R6).

    Returns a host-visible path (under ``/proc/<pid>/root``) or None. None is not
    an error — Tier B is optional and the Tier A baseline stands without it.
    """
    for pat in ("opt/java/*/lib/server/libjvm.so",
                "usr/lib/jvm/*/lib/server/libjvm.so",
                "usr/lib/jvm/*/jre/lib/*/server/libjvm.so",
                "opt/*/lib/server/libjvm.so"):
        for hit in sorted(glob.glob(os.path.join(container_root, pat))):
            if os.path.isfile(hit):
                return hit
    return None


async def run_observer_reachability(
    container_ref: str,
    vulnerabilities: list[dict],
    *,
    import_map: Optional[dict[str, str]] = None,
    taint_flows: Optional[list[dict]] = None,
    ecosystems: tuple[str, ...] = ("python", "node", "java"),
    duration: int = 10,
    binary_path: Optional[str] = None,
    traffic: Optional[Callable[[], Awaitable[None]]] = None,
    window: Optional["TrafficWindow"] = None,
    tier_b_window: int = _DEFAULT_TIER_B_WINDOW,
) -> tuple[list[ReachabilityFinding], dict[str, Any]]:
    """Observe *container_ref* over a window and return (findings, metadata).

    Args:
        container_ref:   Docker container id/name (already running).
        vulnerabilities: SCA vuln dicts (need ``package`` + ``cve_id``).
        import_map:      optional dist→module map (from MetadataAgent).
        ecosystems:      Package-Index ecosystems to enumerate.
        duration:        hard cap (seconds) on the observation window; the run
                         normally ends when ``traffic`` returns and we stop the
                         observer, whichever comes first.
        binary_path:     observer binary (defaults to VULNREACH_OBSERVER_BIN / bundled).
        traffic:         optional async callback to drive load during the window
                         (e.g. schemathesis). If None, we observe for ``duration`` seconds.
        window:          optional TrafficWindow; ``traffic`` should call
                         ``window.mark()`` once the app is healthy so Rule R5 can
                         tell request-handling code from boot-time imports.
        tier_b_window:   seconds to keep the CPython uprobe live after the mark
                         (0 = whole run). See ``_DEFAULT_TIER_B_WINDOW``.
    """
    resolver = DockerTargetResolver()
    target = resolver.resolve(container_ref)

    container_root = f"/proc/{target.init_pid}/root"
    # A cheap glob, done before attach so it can't delay it further.
    libpython = find_libpython(container_root) if "python" in ecosystems else None
    libjvm = find_libjvm(container_root) if "java" in ecosystems else None

    # Attach the observer FIRST, then build the Package-Index while already
    # recording — every millisecond before attach is a startup import we miss.
    client = ObserverClient(binary_path or _DEFAULT_BIN)
    ready = await client.start([target.cgroup_id], duration=duration,
                               python_lib=libpython, jvm_lib=libjvm,
                               tier_b_window=tier_b_window)
    progs = ready.get("progs") or []
    tier_b = "uprobe:py_eval_frame" in progs or "uprobe:jvm_class_loaded" in progs
    if window is not None and tier_b:
        window.attach(client.mark)

    # Read the event stream CONCURRENTLY with driving traffic — otherwise a busy
    # container fills the observer's stdout pipe and stalls it while we wait.
    collector = asyncio.create_task(client.collect())
    try:
        index = build_index(container_root, ecosystems=ecosystems)
        if traffic is not None:
            await traffic()
        else:
            await asyncio.sleep(duration)
    finally:
        await client.stop()  # SIGTERM → observer flushes summary → collector returns
    events = await collector

    reach = correlate_opens(events, index,
                            traffic_start_ns=window.start_ns if window else None)
    # Transitive back-stop from the container's installed dependency graph: a
    # vulnerable package reachable via a *loaded* one but not itself observed
    # loading is structurally reachable (POSSIBLE), not absent. Node only for now
    # (its package name is namespace-consistent); Python/Java need name
    # reconciliation. Guarded on a Node package actually having loaded — with no
    # Node roots there is nothing to reach through, so we skip the container walk
    # entirely on pure-Python/Java targets.
    reached_node = "node" in ecosystems and any(
        pr.ecosystem == "node" for pr in reach.values())
    requires_graph = requires_graph_from_container(container_root, "node") if reached_node else {}
    findings = to_reachability_findings(reach, vulnerabilities, import_map,
                                        taint_flows, requires_graph=requires_graph)

    metadata = {
        "engine": "observer",
        "target_container": target.container_id[:12],
        "target_cgroup_id": target.cgroup_id,
        "index_entries": len(index),
        "open_events": sum(1 for e in events if e.get("type") == "open"),
        "py_call_events": sum(1 for e in events if e.get("type") == "py_call"),
        "java_class_events": sum(1 for e in events if e.get("type") == "java_class"),
        "packages_reached": len(reach),
        "reached": sorted({pr.name for pr in reach.values()}),
        "native_exec": sorted({pr.name for pr in reach.values() if "R2" in pr.rule}),
        "code_executed": sorted({pr.name for pr in reach.values()
                                 if "R5" in pr.rule or "R6" in pr.rule}),
        "tier_b": {"enabled": tier_b, "libpython": libpython, "libjvm": libjvm,
                   "traffic_start_ns": window.start_ns if window else None,
                   "uprobe_window_s": tier_b_window},
        "taint_modules": sorted(_taint_modules(taint_flows)),
    }
    return findings, metadata

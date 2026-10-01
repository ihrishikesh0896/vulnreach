"""Unit tests for agents.ebpf.observer_client.ObserverClient.

ObserverClient (168 lines — the async subprocess/NDJSON protocol client that
every eBPF integration goes through) had zero coverage anywhere, gated or
not, before this file. It doesn't need the real Go binary, Docker, a kernel,
or root to test: it only needs *something* on the other end of a pipe that
speaks the same NDJSON control-line protocol the real observer does (``v``,
``type`` in {ready, warn, error, marked, summary} + event lines). These tests
stand up a tiny Python "fake observer" script per scenario to play that role,
so the real asyncio subprocess/pipe/readline code path is exercised for
real — only the Go binary is substituted. Runs anywhere Python does.
"""
from __future__ import annotations

import asyncio

import pytest

from agents.ebpf.observer_client import ObserverClient, ObserverError


def _fake_observer(tmp_path, body: str) -> str:
    """Write an executable script that speaks the observer's NDJSON protocol.

    Every line must be flushed explicitly — stdout is a pipe here, not a
    tty, so Python fully buffers by default and an unflushed line would
    never reach the parent, hanging the test.
    """
    script = tmp_path / "fake_observer"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys, time\n"
        f"{body}\n"
    )
    script.chmod(0o755)
    return str(script)


# ── start() — ready / warn handling ─────────────────────────────────────────────

def test_start_returns_ready_line_and_collects_preceding_warnings(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print(json.dumps({"v": 1, "type": "warn", "msg": "openat2 unsupported"}), flush=True)
print(json.dumps({"v": 1, "type": "ready", "kernel": "5.15"}), flush=True)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        line = await client.start([123])
        await client.stop()
        return line

    line = asyncio.run(run())
    assert line["type"] == "ready"
    assert line["kernel"] == "5.15"
    assert line["warnings"] == ["openat2 unsupported"]


def test_start_ignores_unknown_schema_version(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print(json.dumps({"v": 2, "type": "ready", "unexpected": "schema"}), flush=True)
print(json.dumps({"v": 1, "type": "ready", "kernel": "5.15"}), flush=True)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        line = await client.start([123])
        await client.stop()
        return line

    line = asyncio.run(run())
    assert line["kernel"] == "5.15"
    assert "unexpected" not in line


def test_start_skips_blank_and_malformed_lines(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print("", flush=True)
print("not-json-at-all", flush=True)
print(json.dumps({"v": 1, "type": "ready"}), flush=True)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        line = await client.start([123])
        await client.stop()
        return line

    line = asyncio.run(run())
    assert line["type"] == "ready"


# ── start() — failure paths ──────────────────────────────────────────────────────

def test_start_raises_when_binary_missing(tmp_path):
    client = ObserverClient(binary_path=str(tmp_path / "does-not-exist"))

    with pytest.raises(ObserverError, match="not found"):
        asyncio.run(client.start([123]))


def test_start_raises_on_error_line(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print(json.dumps({"v": 1, "type": "error", "msg": "boom"}), flush=True)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        try:
            await client.start([123])
        finally:
            await client.stop()

    with pytest.raises(ObserverError, match="boom"):
        asyncio.run(run())


def test_start_raises_when_process_exits_before_ready(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print("cannot attach: kernel too old", file=sys.stderr, flush=True)
sys.exit(1)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        try:
            await client.start([123])
        finally:
            await client.stop()

    with pytest.raises(ObserverError, match="exited before ready"):
        asyncio.run(run())


def test_start_times_out_and_terminates_process(tmp_path):
    bin_path = _fake_observer(tmp_path, """
time.sleep(30)
""")
    client = ObserverClient(binary_path=bin_path)

    with pytest.raises(ObserverError, match="timeout"):
        asyncio.run(client.start([123], ready_timeout=0.3))

    # start()'s timeout branch calls stop() before raising — the sleeping
    # child must actually be dead, not leaked.
    assert client._proc.returncode is not None


# ── events() / collect() ────────────────────────────────────────────────────────

def test_collect_yields_events_and_filters_control_lines(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print(json.dumps({"v": 1, "type": "ready"}), flush=True)
print(json.dumps({"v": 1, "type": "exec", "path": "/bin/ls"}), flush=True)
print(json.dumps({"v": 1, "type": "warn", "msg": "ignored mid-stream"}), flush=True)
print(json.dumps({"v": 1, "type": "marked"}), flush=True)
print(json.dumps({"v": 1, "type": "exec", "path": "/bin/cat"}), flush=True)
print(json.dumps({"v": 1, "type": "summary", "count": 2}), flush=True)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        await client.start([123])
        events = await client.collect()
        await client._proc.wait()  # reap: the process exits on its own after summary
        return events

    events = asyncio.run(run())
    assert [e["path"] for e in events] == ["/bin/ls", "/bin/cat"]
    assert all(e["type"] == "exec" for e in events)


def test_collect_raises_on_mid_stream_error(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print(json.dumps({"v": 1, "type": "ready"}), flush=True)
print(json.dumps({"v": 1, "type": "exec", "path": "/bin/ls"}), flush=True)
print(json.dumps({"v": 1, "type": "error", "msg": "kaboom"}), flush=True)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        await client.start([123])
        try:
            await client.collect()
        finally:
            await client.stop()

    with pytest.raises(ObserverError, match="kaboom"):
        asyncio.run(run())


# ── mark() ────────────────────────────────────────────────────────────────────

def test_mark_is_noop_without_started_process():
    client = ObserverClient(binary_path="/nonexistent")
    client.mark()  # must not raise — best-effort by design


def test_mark_writes_control_line_to_running_process(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print(json.dumps({"v": 1, "type": "ready"}), flush=True)
line = sys.stdin.readline().strip()
print(json.dumps({"v": 1, "type": "exec", "path": "/received/" + line}), flush=True)
print(json.dumps({"v": 1, "type": "summary"}), flush=True)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        await client.start([123])
        client.mark()
        events = await client.collect()
        await client._proc.wait()  # reap: the process exits on its own after summary
        return events

    events = asyncio.run(run())
    assert events == [{"v": 1, "type": "exec", "path": "/received/mark"}]


# ── stop() ────────────────────────────────────────────────────────────────────

def test_stop_terminates_running_process(tmp_path):
    bin_path = _fake_observer(tmp_path, """
print(json.dumps({"v": 1, "type": "ready"}), flush=True)
time.sleep(30)
""")
    client = ObserverClient(binary_path=bin_path)

    async def run():
        await client.start([123])
        await client.stop()

    asyncio.run(run())
    assert client._proc.returncode is not None

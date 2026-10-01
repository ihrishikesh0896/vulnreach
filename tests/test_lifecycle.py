"""Unit tests for vulnreach.lifecycle — server start/stop/reload/status.

Mocks subprocess.run/Popen and os.kill throughout: these tests must never
spawn a real uvicorn process, touch a real Docker daemon, or write outside
tmp_path (RUN_DIR/PIDFILE/LOGFILE are monkeypatched per test, never the real
~/.vulnreach).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnreach import lifecycle


def _redirect_run_dir(monkeypatch, tmp_path):
    run_dir = tmp_path / "run"
    monkeypatch.setattr(lifecycle, "RUN_DIR", run_dir)
    monkeypatch.setattr(lifecycle, "PIDFILE", run_dir / "vulnreach.pid")
    monkeypatch.setattr(lifecycle, "LOGFILE", run_dir / "vulnreach.log")
    return run_dir


# ── detect_mode ──────────────────────────────────────────────────────────────

def test_detect_mode_process_when_no_compose_file(tmp_path):
    missing = tmp_path / "docker-compose.yml"
    assert lifecycle.detect_mode(str(missing)) == "process"


def test_detect_mode_process_when_docker_not_on_path(tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}")
    monkeypatch.setattr(lifecycle.shutil, "which", lambda _: None)
    assert lifecycle.detect_mode(str(compose)) == "process"


def test_detect_mode_process_when_daemon_unreachable(tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}")
    monkeypatch.setattr(lifecycle.shutil, "which", lambda _: "/usr/bin/docker")

    def _fail(*a, **k):
        raise lifecycle.subprocess.CalledProcessError(1, "docker info")
    monkeypatch.setattr(lifecycle.subprocess, "run", _fail)

    assert lifecycle.detect_mode(str(compose)) == "process"


def test_detect_mode_docker_when_compose_file_and_daemon_present(tmp_path, monkeypatch):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}")
    monkeypatch.setattr(lifecycle.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(
        lifecycle.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0),
    )
    assert lifecycle.detect_mode(str(compose)) == "docker"


# ── docker mode ──────────────────────────────────────────────────────────────

def test_docker_start_invokes_compose_up_d(monkeypatch):
    calls = []
    monkeypatch.setattr(
        lifecycle.subprocess, "run",
        lambda cmd, **k: calls.append(cmd) or SimpleNamespace(returncode=0),
    )
    lifecycle.docker_start(compose_file="my-compose.yml")
    assert calls == [["docker", "compose", "-f", "my-compose.yml", "up", "-d"]]


def test_docker_stop_invokes_compose_down(monkeypatch):
    calls = []
    monkeypatch.setattr(
        lifecycle.subprocess, "run",
        lambda cmd, **k: calls.append(cmd) or SimpleNamespace(returncode=0),
    )
    lifecycle.docker_stop()
    assert calls == [["docker", "compose", "-f", "docker-compose.yml", "down"]]


def test_docker_reload_uses_up_d_not_restart(monkeypatch):
    # `restart` would not re-read an edited .env.local; `up -d` recreates
    # only what changed. This test exists specifically to pin that choice.
    calls = []
    monkeypatch.setattr(
        lifecycle.subprocess, "run",
        lambda cmd, **k: calls.append(cmd) or SimpleNamespace(returncode=0),
    )
    lifecycle.docker_reload()
    assert calls == [["docker", "compose", "-f", "docker-compose.yml", "up", "-d"]]
    assert "restart" not in calls[0]


def test_docker_command_failure_raises_lifecycle_error(monkeypatch):
    monkeypatch.setattr(
        lifecycle.subprocess, "run",
        lambda cmd, **k: SimpleNamespace(returncode=1),
    )
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.docker_start()


def test_docker_status_returns_compose_ps_output(monkeypatch):
    monkeypatch.setattr(
        lifecycle.subprocess, "run",
        lambda cmd, **k: SimpleNamespace(returncode=0, stdout="vulnreach  running\n"),
    )
    assert lifecycle.docker_status() == "vulnreach  running"


def test_docker_status_empty_output_is_labelled(monkeypatch):
    monkeypatch.setattr(
        lifecycle.subprocess, "run",
        lambda cmd, **k: SimpleNamespace(returncode=0, stdout=""),
    )
    assert lifecycle.docker_status() == "(no containers)"


# ── process mode ─────────────────────────────────────────────────────────────

def test_process_start_writes_pidfile_and_returns_pid(tmp_path, monkeypatch):
    _redirect_run_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(lifecycle, "_check_server_extras", lambda: None)
    monkeypatch.setattr(
        lifecycle.subprocess, "Popen",
        lambda *a, **k: SimpleNamespace(pid=4242),
    )

    pid = lifecycle.process_start()

    assert pid == 4242
    assert lifecycle.PIDFILE.read_text().strip() == "4242"


def test_process_start_passes_main_app_and_host_port(tmp_path, monkeypatch):
    _redirect_run_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(lifecycle, "_check_server_extras", lambda: None)
    captured = {}

    def _popen(cmd, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(pid=1)
    monkeypatch.setattr(lifecycle.subprocess, "Popen", _popen)

    lifecycle.process_start(host="127.0.0.1", port=9000)

    assert captured["cmd"][-4:] == ["--host", "127.0.0.1", "--port", "9000"]
    assert "main:app" in captured["cmd"]


def test_process_start_raises_when_server_extras_missing(tmp_path, monkeypatch):
    _redirect_run_dir(monkeypatch, tmp_path)

    def _missing():
        raise lifecycle.LifecycleError("The server isn't installed. Run `pip install vulnreach[server]`")
    monkeypatch.setattr(lifecycle, "_check_server_extras", _missing)

    with pytest.raises(lifecycle.LifecycleError, match="vulnreach\\[server\\]"):
        lifecycle.process_start()


def test_process_start_raises_when_already_running(tmp_path, monkeypatch):
    run_dir = _redirect_run_dir(monkeypatch, tmp_path)
    run_dir.mkdir(parents=True)
    lifecycle.PIDFILE.write_text("777")
    monkeypatch.setattr(lifecycle, "_check_server_extras", lambda: None)
    monkeypatch.setattr(lifecycle, "_pid_alive", lambda pid: pid == 777)

    with pytest.raises(lifecycle.LifecycleError, match="already running"):
        lifecycle.process_start()


def test_process_stop_raises_when_not_running(tmp_path, monkeypatch):
    _redirect_run_dir(monkeypatch, tmp_path)
    with pytest.raises(lifecycle.LifecycleError, match="not running"):
        lifecycle.process_stop()


def test_process_stop_sends_sigterm_and_clears_pidfile(tmp_path, monkeypatch):
    run_dir = _redirect_run_dir(monkeypatch, tmp_path)
    run_dir.mkdir(parents=True)
    lifecycle.PIDFILE.write_text("555")

    signals = []
    alive = {"state": True}
    monkeypatch.setattr(lifecycle.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(lifecycle, "_pid_alive", lambda pid: alive["state"])
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _: alive.__setitem__("state", False))

    lifecycle.process_stop(timeout=1.0)

    assert signals[0] == (555, lifecycle.signal.SIGTERM)
    assert not lifecycle.PIDFILE.exists()


def test_process_stop_escalates_to_sigkill_after_timeout(tmp_path, monkeypatch):
    run_dir = _redirect_run_dir(monkeypatch, tmp_path)
    run_dir.mkdir(parents=True)
    lifecycle.PIDFILE.write_text("555")

    signals = []
    monkeypatch.setattr(lifecycle.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(lifecycle, "_pid_alive", lambda pid: True)  # never dies gracefully
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _: None)

    lifecycle.process_stop(timeout=0.0)

    assert signals == [(555, lifecycle.signal.SIGTERM), (555, lifecycle.signal.SIGKILL)]


def test_process_reload_tolerates_not_running(tmp_path, monkeypatch):
    _redirect_run_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(lifecycle, "_check_server_extras", lambda: None)
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *a, **k: SimpleNamespace(pid=99))

    pid = lifecycle.process_reload()

    assert pid == 99


def test_process_reload_stops_then_starts(tmp_path, monkeypatch):
    run_dir = _redirect_run_dir(monkeypatch, tmp_path)
    run_dir.mkdir(parents=True)
    lifecycle.PIDFILE.write_text("111")

    order = []
    # _pid_alive reports dead as soon as the stop signal has been sent, so the
    # stop loop exits immediately instead of waiting out the real timeout.
    monkeypatch.setattr(lifecycle, "_pid_alive", lambda pid: not order)
    monkeypatch.setattr(lifecycle.os, "kill", lambda pid, sig: order.append("stop"))
    monkeypatch.setattr(lifecycle, "_check_server_extras", lambda: None)
    monkeypatch.setattr(
        lifecycle.subprocess, "Popen",
        lambda *a, **k: order.append("start") or SimpleNamespace(pid=222),
    )

    pid = lifecycle.process_reload()

    assert order == ["stop", "start"]
    assert pid == 222


def test_process_status_running(tmp_path, monkeypatch):
    run_dir = _redirect_run_dir(monkeypatch, tmp_path)
    run_dir.mkdir(parents=True)
    lifecycle.PIDFILE.write_text("321")
    monkeypatch.setattr(lifecycle, "_pid_alive", lambda pid: True)

    assert lifecycle.process_status() == "running (pid 321)"


def test_process_status_stale_pidfile(tmp_path, monkeypatch):
    run_dir = _redirect_run_dir(monkeypatch, tmp_path)
    run_dir.mkdir(parents=True)
    lifecycle.PIDFILE.write_text("321")
    monkeypatch.setattr(lifecycle, "_pid_alive", lambda pid: False)

    assert lifecycle.process_status() == "not running (stale pidfile)"


def test_process_status_no_pidfile(tmp_path, monkeypatch):
    _redirect_run_dir(monkeypatch, tmp_path)
    assert lifecycle.process_status() == "not running"

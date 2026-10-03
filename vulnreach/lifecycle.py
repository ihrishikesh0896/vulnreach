"""VulnReach server lifecycle — start, stop, reload, status.

Deliberately does not talk to `/scan` or any other scan-triggering endpoint.
Scanning happens via the web UI or direct API calls (curl); this module's only
job is getting the server process itself running, stopped, or restarted, in
either Docker mode (wraps `docker compose`) or bare-process mode (pidfile-based
`uvicorn` supervision for a plain `pip install vulnreach[server]`).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Literal, Optional

Mode = Literal["docker", "process"]

RUN_DIR = Path(os.environ.get("VULNREACH_RUN_DIR", str(Path.home() / ".vulnreach")))
PIDFILE = RUN_DIR / "vulnreach.pid"
LOGFILE = RUN_DIR / "vulnreach.log"

DEFAULT_COMPOSE_FILE = "docker-compose.yml"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000


class LifecycleError(RuntimeError):
    pass


def detect_mode(compose_file: str = DEFAULT_COMPOSE_FILE) -> Mode:
    """"docker" if a compose file is present here and the daemon answers, else "process"."""
    if Path(compose_file).exists() and shutil.which("docker"):
        try:
            subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
            return "docker"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            pass
    return "process"


# ── Docker mode ──────────────────────────────────────────────────────────────

def _compose(*args: str, compose_file: str = DEFAULT_COMPOSE_FILE) -> list[str]:
    return ["docker", "compose", "-f", compose_file, *args]


def _run(cmd: list[str]) -> None:
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise LifecycleError(f"command failed ({result.returncode}): {' '.join(cmd)}")


def docker_start(compose_file: str = DEFAULT_COMPOSE_FILE) -> None:
    _run(_compose("up", "-d", compose_file=compose_file))


def docker_stop(compose_file: str = DEFAULT_COMPOSE_FILE) -> None:
    _run(_compose("down", compose_file=compose_file))


def docker_reload(compose_file: str = DEFAULT_COMPOSE_FILE) -> None:
    # `up -d` recreates containers whose config changed (e.g. an edited
    # .env.local) and no-ops otherwise. `docker compose restart` would NOT pick
    # that up — Compose only re-reads `env_file` on recreate, not on restart.
    _run(_compose("up", "-d", compose_file=compose_file))


def docker_status(compose_file: str = DEFAULT_COMPOSE_FILE) -> str:
    result = subprocess.run(
        _compose("ps", compose_file=compose_file), capture_output=True, text=True,
    )
    return result.stdout.strip() or "(no containers)"


# ── Process mode ─────────────────────────────────────────────────────────────

def _check_server_extras() -> None:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError as exc:
        raise LifecycleError(
            "The server isn't installed. Run `pip install vulnreach[server]`, "
            "or use Docker mode instead."
        ) from exc


def _read_pid() -> Optional[int]:
    if not PIDFILE.exists():
        return None
    try:
        return int(PIDFILE.read_text().strip())
    except (ValueError, OSError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def process_start(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> int:
    _check_server_extras()
    existing = _read_pid()
    if existing and _pid_alive(existing):
        raise LifecycleError(f"already running (pid {existing})")

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    log = open(LOGFILE, "ab")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", host, "--port", str(port)],
        stdout=log,
        stderr=log,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    PIDFILE.write_text(str(proc.pid))
    return proc.pid


def process_stop(timeout: float = 10.0) -> None:
    pid = _read_pid()
    if not pid or not _pid_alive(pid):
        PIDFILE.unlink(missing_ok=True)
        raise LifecycleError("not running")

    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            break
        time.sleep(0.2)
    else:
        os.kill(pid, signal.SIGKILL)
    PIDFILE.unlink(missing_ok=True)


def process_reload(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> int:
    try:
        process_stop()
    except LifecycleError:
        pass  # wasn't running — reload still starts it fresh
    return process_start(host=host, port=port)


def process_status() -> str:
    pid = _read_pid()
    if pid and _pid_alive(pid):
        return f"running (pid {pid})"
    if pid:
        return "not running (stale pidfile)"
    return "not running"

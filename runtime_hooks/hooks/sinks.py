"""Dangerous sink hooks for security-relevant function calls."""
from __future__ import annotations

import builtins
import subprocess
import traceback
from typing import Any, Callable

from hooks.events import emit

# Store original functions
_original_eval = builtins.eval
_original_exec = builtins.exec
_original_popen = subprocess.Popen
_original_open = builtins.open

# Try to import and store SQL-related originals
try:
    import sqlite3
    _original_sqlite_execute = sqlite3.Cursor.execute
    _has_sqlite = True
except ImportError:
    _has_sqlite = False

# Try to import network-related originals
try:
    import urllib.request
    _original_urlopen = urllib.request.urlopen
    _has_urllib = True
except ImportError:
    _has_urllib = False

# Try to import socket
try:
    import socket
    _original_socket_connect = socket.socket.connect
    _has_socket = True
except ImportError:
    _has_socket = False


def _eval_hook(source: str | bytes | Any, globals: dict[str, Any] | None = None, locals: dict[str, Any] | None = None) -> Any:
    """Wrapper around eval() that emits sink events."""
    emit(
        "sink",
        {
            "function": "eval",
            "category": "CODE_INJECTION",
            "source_preview": str(source)[:500] if source else None,
            "stack": traceback.format_stack(limit=10),
        },
    )
    return _original_eval(source, globals, locals)


def _exec_hook(
    object: str | bytes | Any,
    globals: dict[str, Any] | None = None,
    locals: dict[str, Any] | None = None,
    /,
) -> None:
    """Wrapper around exec() that emits sink events."""
    emit(
        "sink",
        {
            "function": "exec",
            "category": "CODE_INJECTION",
            "source_preview": str(object)[:500] if object else None,
            "stack": traceback.format_stack(limit=10),
        },
    )
    return _original_exec(object, globals, locals)


class _PopenHook(subprocess.Popen):
    """Wrapper around subprocess.Popen that emits sink events."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        emit(
            "sink",
            {
                "function": "subprocess.Popen",
                "category": "COMMAND_INJECTION",
                "args": str(args)[:500] if args else None,
                "kwargs": str(kwargs)[:500] if kwargs else None,
                "stack": traceback.format_stack(limit=10),
            },
        )
        super().__init__(*args, **kwargs)


def _open_hook(file, mode='r', *args: Any, **kwargs: Any):
    """Wrapper around open() that emits sink events."""
    emit(
        "sink",
        {
            "function": "open",
            "category": "FILE_ACCESS",
            "file": str(file)[:500],
            "mode": mode,
            "stack": traceback.format_stack(limit=10),
        },
    )
    return _original_open(file, mode, *args, **kwargs)


def _sqlite_execute_hook(self, sql, parameters=None):
    """Wrapper around sqlite3.Cursor.execute that emits sink events."""
    emit(
        "sink",
        {
            "function": "sqlite3.Cursor.execute",
            "category": "SQL_INJECTION",
            "query_preview": str(sql)[:500],
            "has_parameters": parameters is not None,
            "stack": traceback.format_stack(limit=10),
        },
    )
    if parameters is not None:
        return _original_sqlite_execute(self, sql, parameters)
    else:
        return _original_sqlite_execute(self, sql)


def _urlopen_hook(url, data=None, timeout=None, *args: Any, **kwargs: Any):
    """Wrapper around urllib.request.urlopen that emits sink events."""
    emit(
        "sink",
        {
            "function": "urllib.request.urlopen",
            "category": "SSRF",
            "url": str(url)[:500],
            "has_data": data is not None,
            "stack": traceback.format_stack(limit=10),
        },
    )
    if timeout is not None:
        return _original_urlopen(url, data, timeout, *args, **kwargs)
    elif data is not None:
        return _original_urlopen(url, data, *args, **kwargs)
    else:
        return _original_urlopen(url, *args, **kwargs)


def _socket_connect_hook(self, address):
    """Wrapper around socket.connect that emits sink events."""
    emit(
        "sink",
        {
            "function": "socket.connect",
            "category": "NETWORK_ACCESS",
            "address": str(address)[:500],
            "stack": traceback.format_stack(limit=10),
        },
    )
    return _original_socket_connect(self, address)


def install_eval() -> None:
    """Install eval() hook once."""
    if getattr(install_eval, "_installed", False):
        return
    builtins.eval = _eval_hook
    install_eval._installed = True  # type: ignore[attr-defined]


def install_exec() -> None:
    """Install exec() hook once."""
    if getattr(install_exec, "_installed", False):
        return
    builtins.exec = _exec_hook
    install_exec._installed = True  # type: ignore[attr-defined]


def install_popen() -> None:
    """Install subprocess.Popen hook once."""
    if getattr(install_popen, "_installed", False):
        return
    subprocess.Popen = _PopenHook
    install_popen._installed = True  # type: ignore[attr-defined]


def install_open() -> None:
    """Install open() hook once."""
    if getattr(install_open, "_installed", False):
        return
    builtins.open = _open_hook
    install_open._installed = True  # type: ignore[attr-defined]


def install_sqlite() -> None:
    """Install sqlite3.Cursor.execute hook once."""
    if not _has_sqlite:
        return
    if getattr(install_sqlite, "_installed", False):
        return
    import sqlite3
    sqlite3.Cursor.execute = _sqlite_execute_hook
    install_sqlite._installed = True  # type: ignore[attr-defined]


def install_urlopen() -> None:
    """Install urllib.request.urlopen hook once."""
    if not _has_urllib:
        return
    if getattr(install_urlopen, "_installed", False):
        return
    import urllib.request
    urllib.request.urlopen = _urlopen_hook
    install_urlopen._installed = True  # type: ignore[attr-defined]


def install_socket() -> None:
    """Install socket.connect hook once."""
    if not _has_socket:
        return
    if getattr(install_socket, "_installed", False):
        return
    import socket
    socket.socket.connect = _socket_connect_hook
    install_socket._installed = True  # type: ignore[attr-defined]


def install() -> None:
    """Install all sink hooks."""
    # Core sinks (always installed)
    install_eval()
    install_exec()
    install_popen()
    install_open()

    # Optional sinks (installed if modules available)
    install_sqlite()
    install_urlopen()
    install_socket()

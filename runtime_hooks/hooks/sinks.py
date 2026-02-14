"""Dangerous sink hooks for security-relevant function calls.

Enhanced for STEP 10: Now detects when tainted data reaches dangerous sinks.
"""
from __future__ import annotations

import builtins
import os
import subprocess
import traceback
from typing import Any, Callable

from hooks.events import emit
from hooks.taint import is_tainted, get_taint_info

# Helper function to unwrap TaintedValue objects
def _unwrap_if_tainted(value):
    """Extract the actual value from TaintedValue wrapper if needed."""
    if hasattr(value, 'unwrap'):
        return value.unwrap()
    return value

# Store original functions
_original_eval = builtins.eval
_original_exec = builtins.exec
_original_popen = subprocess.Popen
_original_open = builtins.open
_original_os_system = os.system

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
    """Wrapper around eval() that emits sink events and detects tainted data."""
    # Check if source is tainted
    tainted = is_tainted(source)
    taint_info = get_taint_info(source) if tainted else None
    
    # Unwrap TaintedValue if needed
    unwrapped_source = _unwrap_if_tainted(source)
    
    # Emit basic sink event
    emit(
        "sink",
        {
            "function": "eval",
            "category": "CODE_INJECTION",
            "source_preview": str(unwrapped_source)[:500] if unwrapped_source else None,
            "tainted": tainted,
            "stack": traceback.format_stack(limit=10),
        },
    )
    
    # If tainted, emit vulnerability alert
    if tainted:
        emit(
            "taint_sink_reached",
            {
                "vulnerability_type": "CODE_INJECTION",
                "sink_function": "eval",
                "severity": "CRITICAL",
                "taint_source": taint_info['source'],
                "taint_source_type": taint_info['source_type'],
                "sink_argument": str(unwrapped_source)[:200],
                "stack": traceback.format_stack(limit=10),
                "message": f"🚨 CRITICAL: Tainted data from '{taint_info['source']}' reached eval()",
            },
        )
    
    return _original_eval(unwrapped_source, globals, locals)


def _exec_hook(
    object: str | bytes | Any,
    globals: dict[str, Any] | None = None,
    locals: dict[str, Any] | None = None,
    /,
) -> None:
    """Wrapper around exec() that emits sink events and detects tainted data."""
    # Check if code is tainted
    tainted = is_tainted(object)
    taint_info = get_taint_info(object) if tainted else None
    
    # Unwrap TaintedValue if needed
    unwrapped_object = _unwrap_if_tainted(object)
    
    # Emit basic sink event
    emit(
        "sink",
        {
            "function": "exec",
            "category": "CODE_INJECTION",
            "source_preview": str(unwrapped_object)[:500] if unwrapped_object else None,
            "tainted": tainted,
            "stack": traceback.format_stack(limit=10),
        },
    )
    
    # If tainted, emit vulnerability alert
    if tainted:
        emit(
            "taint_sink_reached",
            {
                "vulnerability_type": "CODE_INJECTION",
                "sink_function": "exec",
                "severity": "CRITICAL",
                "taint_source": taint_info['source'],
                "taint_source_type": taint_info['source_type'],
                "sink_argument": str(unwrapped_object)[:200],
                "stack": traceback.format_stack(limit=10),
                "message": f"🚨 CRITICAL: Tainted data from '{taint_info['source']}' reached exec()",
            },
        )
    
    return _original_exec(unwrapped_object, globals, locals)


class _PopenHook(subprocess.Popen):
    """Wrapper around subprocess.Popen that emits sink events and detects tainted data."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Check if command is tainted
        tainted = False
        taint_info = None
        command_preview = None
        unwrapped_args = list(args)
        
        if args and len(args) > 0:
            cmd = args[0]
            command_preview = str(cmd)[:500]
            
            # Check if command is tainted (could be string or list)
            if is_tainted(cmd):
                tainted = True
                taint_info = get_taint_info(cmd)
                # Unwrap the command
                unwrapped_args[0] = _unwrap_if_tainted(cmd)
            elif isinstance(cmd, (list, tuple)):
                # Check each element of command list
                unwrapped_cmd = []
                for elem in cmd:
                    if is_tainted(elem):
                        tainted = True
                        if not taint_info:
                            taint_info = get_taint_info(elem)
                        unwrapped_cmd.append(_unwrap_if_tainted(elem))
                    else:
                        unwrapped_cmd.append(elem)
                unwrapped_args[0] = unwrapped_cmd
        
        # Emit basic sink event
        emit(
            "sink",
            {
                "function": "subprocess.Popen",
                "category": "COMMAND_INJECTION",
                "args": str(args)[:500] if args else None,
                "kwargs": str(kwargs)[:500] if kwargs else None,
                "tainted": tainted,
                "stack": traceback.format_stack(limit=10),
            },
        )
        
        # If tainted, emit vulnerability alert
        if tainted:
            emit(
                "taint_sink_reached",
                {
                    "vulnerability_type": "COMMAND_INJECTION",
                    "sink_function": "subprocess.Popen",
                    "severity": "CRITICAL",
                    "taint_source": taint_info['source'],
                    "taint_source_type": taint_info['source_type'],
                    "sink_argument": command_preview,
                    "stack": traceback.format_stack(limit=10),
                    "message": f"🚨 CRITICAL: Tainted data from '{taint_info['source']}' reached subprocess.Popen",
                },
            )
        
        super().__init__(*unwrapped_args, **kwargs)


def _open_hook(file, mode='r', *args: Any, **kwargs: Any):
    """Wrapper around open() that emits sink events and detects tainted data."""
    # Check if file path is tainted
    tainted = is_tainted(file)
    taint_info = get_taint_info(file) if tainted else None
    
    # Unwrap TaintedValue if needed
    unwrapped_file = _unwrap_if_tainted(file)
    
    # Emit basic sink event
    emit(
        "sink",
        {
            "function": "open",
            "category": "FILE_ACCESS",
            "file": str(unwrapped_file)[:500],
            "mode": mode,
            "tainted": tainted,
            "stack": traceback.format_stack(limit=10),
        },
    )
    
    # If tainted, emit vulnerability alert (potential path traversal)
    if tainted:
        severity = "HIGH" if 'w' in mode or 'a' in mode else "MEDIUM"
        vuln_type = "PATH_TRAVERSAL" if 'w' in mode or 'a' in mode else "ARBITRARY_FILE_READ"
        
        emit(
            "taint_sink_reached",
            {
                "vulnerability_type": vuln_type,
                "sink_function": "open",
                "severity": severity,
                "taint_source": taint_info['source'],
                "taint_source_type": taint_info['source_type'],
                "sink_argument": str(unwrapped_file)[:200],
                "file_mode": mode,
                "stack": traceback.format_stack(limit=10),
                "message": f"🚨 {severity}: Tainted data from '{taint_info['source']}' used in file path",
            },
        )
    
    return _original_open(unwrapped_file, mode, *args, **kwargs)


def _os_system_hook(command):
    """Wrapper around os.system() that emits sink events and detects tainted data."""
    # Check if command is tainted
    tainted = is_tainted(command)
    taint_info = get_taint_info(command) if tainted else None
    
    # Unwrap TaintedValue if needed
    unwrapped_command = _unwrap_if_tainted(command)
    
    # Emit basic sink event
    emit(
        "sink",
        {
            "function": "os.system",
            "category": "COMMAND_INJECTION",
            "command": str(unwrapped_command)[:500],
            "tainted": tainted,
            "stack": traceback.format_stack(limit=10),
        },
    )
    
    # If tainted, emit vulnerability alert
    if tainted:
        emit(
            "taint_sink_reached",
            {
                "vulnerability_type": "COMMAND_INJECTION",
                "sink_function": "os.system",
                "severity": "CRITICAL",
                "taint_source": taint_info['source'],
                "taint_source_type": taint_info['source_type'],
                "sink_argument": str(unwrapped_command)[:200],
                "stack": traceback.format_stack(limit=10),
                "message": f"🚨 CRITICAL: Tainted data from '{taint_info['source']}' reached os.system()",
            },
        )
    
    return _original_os_system(unwrapped_command)


def _sqlite_execute_hook(self, sql, parameters=None):
    """Wrapper around sqlite3.Cursor.execute that emits sink events and detects tainted data."""
    # Check if SQL query is tainted
    tainted = is_tainted(sql)
    taint_info = get_taint_info(sql) if tainted else None
    
    # Emit basic sink event
    emit(
        "sink",
        {
            "function": "sqlite3.Cursor.execute",
            "category": "SQL_INJECTION",
            "query_preview": str(sql)[:500],
            "has_parameters": parameters is not None,
            "tainted": tainted,
            "stack": traceback.format_stack(limit=10),
        },
    )
    
    # If tainted, emit vulnerability alert
    if tainted:
        # If using parameters, it's safer (parameterized query)
        if parameters is not None:
            severity = "MEDIUM"
            message = f"⚠️  MEDIUM: Tainted query with parameters from '{taint_info['source']}'"
        else:
            severity = "CRITICAL"
            message = f"🚨 CRITICAL: Tainted SQL query from '{taint_info['source']}' without parameterization"
        
        emit(
            "taint_sink_reached",
            {
                "vulnerability_type": "SQL_INJECTION",
                "sink_function": "sqlite3.Cursor.execute",
                "severity": severity,
                "taint_source": taint_info['source'],
                "taint_source_type": taint_info['source_type'],
                "sink_argument": str(sql)[:200],
                "uses_parameters": parameters is not None,
                "stack": traceback.format_stack(limit=10),
                "message": message,
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


def install_os_system() -> None:
    """Install os.system() hook once."""
    if getattr(install_os_system, "_installed", False):
        return
    os.system = _os_system_hook
    install_os_system._installed = True  # type: ignore[attr-defined]


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
    """Install all sink hooks with taint detection."""
    # Core sinks (always installed)
    install_eval()
    install_exec()
    install_popen()
    install_open()
    install_os_system()

    # Optional sinks (installed if modules available)
    # Note: sqlite3.Cursor, urllib.request, and socket types are immutable in Python 3.11+
    # These hooks are commented out to avoid TypeError
    # install_sqlite()
    # install_urlopen()
    # install_socket()

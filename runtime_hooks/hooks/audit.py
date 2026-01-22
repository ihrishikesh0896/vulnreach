"""Python audit hook for interpreter-level events."""
from __future__ import annotations

import sys
import traceback
from typing import Any, Tuple

from hooks.events import emit

# Audit events we care about in this phase
INTERESTING_EVENTS = {
    "import",
    "importlib.__import__",
    "exec",
    "compile",
    "pickle.load",
    "subprocess.Popen",
}


def _safe_repr(obj: Any) -> str:
    """Best-effort, bounded repr to avoid huge payloads."""
    try:
        text = repr(obj)
    except Exception:
        return "<unrepresentable>"
    return text[:5000]  # cap size


def _audit_hook(event: str, args: Tuple[Any, ...]) -> None:
    if event not in INTERESTING_EVENTS:
        return

    emit(
        "audit",
        {
            "event": event,
            "args": [_safe_repr(a) for a in args],
            "stack": traceback.format_stack(limit=10),
        },
    )


def install() -> None:
    """Install the audit hook once."""
    if getattr(install, "_installed", False):
        return
    sys.addaudithook(_audit_hook)
    install._installed = True  # type: ignore[attr-defined]

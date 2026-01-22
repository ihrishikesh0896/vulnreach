"""Import tracking hook for runtime import observation."""
from __future__ import annotations

import builtins
import traceback
from typing import Any

from hooks.events import emit

# Store the original __import__ function
_original_import = builtins.__import__


def _import_hook(
    name: str,
    globals: dict[str, Any] | None = None,
    locals: dict[str, Any] | None = None,
    fromlist: tuple[str, ...] = (),
    level: int = 0,
) -> Any:
    """Wrapper around builtins.__import__ that emits import events."""
    # Emit the import event BEFORE calling the original
    emit(
        "import",
        {
            "module": name,
            "fromlist": list(fromlist) if fromlist else [],
            "level": level,
            "stack": traceback.format_stack(limit=10),
        },
    )

    # Call the original import and return its result
    return _original_import(name, globals, locals, fromlist, level)


def install() -> None:
    """Install the import hook once."""
    if getattr(install, "_installed", False):
        return
    builtins.__import__ = _import_hook
    install._installed = True  # type: ignore[attr-defined]

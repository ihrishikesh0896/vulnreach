"""Runner wrapper that executes a target Python file after hooks are installed."""
from __future__ import annotations

import os
import sys

from hooks import audit, imports, sinks
from hooks.events import flush


def _run_target(target_path: str) -> None:
    # Ensure the target directory is importable
    target_abs = os.path.abspath(target_path)
    target_dir = os.path.dirname(target_abs)
    if target_dir not in sys.path:
        sys.path.insert(0, target_dir)

    # Read + compile for accurate filenames in traces
    with open(target_abs, "r", encoding="utf-8") as f:
        source = f.read()
    code = compile(source, target_abs, "exec")

    # Execute with a clean globals dict
    globals_dict = {"__name__": "__main__", "__file__": target_abs}
    exec(code, globals_dict, globals_dict)


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        print("Usage: python runner.py <target_file.py>")
        sys.exit(1)

    # Install all hooks BEFORE running target
    audit.install()
    imports.install()
    sinks.install()

    target = argv[1]
    _run_target(target)
    flush()


if __name__ == "__main__":
    main(sys.argv)

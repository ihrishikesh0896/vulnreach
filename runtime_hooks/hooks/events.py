"""Minimal in-memory event collector for runtime observations."""
from __future__ import annotations

import json
from typing import Any, Dict, List

# Simple in-memory buffer; no disk I/O in this phase
_events: List[Dict[str, Any]] = []


def emit(event_type: str, data: Dict[str, Any]) -> None:
    """Record a structured event.

    Args:
        event_type: Short identifier for the event (e.g., "import", "sink").
        data: Arbitrary structured payload describing the event.
    """
    _events.append({"event_type": event_type, "data": data})


def get_events() -> List[Dict[str, Any]]:
    """Return all collected events without clearing them.
    
    Returns:
        List of event dictionaries
    """
    return _events.copy()


def clear_events() -> None:
    """Clear all collected events."""
    _events.clear()


def flush() -> None:
    """Print all collected events as JSON and clear the buffer."""
    if not _events:
        print("[]")
        return

    print(json.dumps(_events))
    _events.clear()

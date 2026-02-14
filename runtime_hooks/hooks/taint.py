"""
Core taint tracking system for Phase 2.

Provides the foundation for marking data as tainted, tracking taint metadata,
and querying taint status.
"""
from __future__ import annotations

import uuid
import weakref
from typing import Any, Optional, Dict


# Global taint registry: maps object id → taint metadata
# Using WeakValueDictionary to avoid preventing garbage collection
_taint_registry: Dict[str, Dict[str, Any]] = {}

# Track which Python object IDs are tainted
# Using a set for fast lookups
_tainted_objects: set = set()


class TaintedValue:
    """
    Wrapper class that marks a value as tainted.
    
    This is used when we need to explicitly wrap a value to track taint.
    For primitive types (str, int, etc.) we use the registry instead.
    
    Supports propagation operations to maintain taint through transformations.
    """
    
    def __init__(self, value: Any, taint_id: str, source: str, source_type: str, metadata: Optional[Dict] = None):
        self.value = value
        self.taint_id = taint_id
        self.source = source
        self.source_type = source_type
        self.metadata = metadata or {}
    
    def __repr__(self):
        return f"TaintedValue({self.value!r}, source={self.source})"
    
    def __str__(self):
        # Return the string representation of the underlying value
        return str(self.value)
    
    def unwrap(self):
        """Get the underlying value"""
        return self.value
    
    # Propagation operations - maintain taint through transformations
    
    def __add__(self, other):
        """Propagate taint through concatenation"""
        from hooks.events import emit
        import traceback
        
        # Perform the operation on the underlying value
        if isinstance(other, TaintedValue):
            result_value = self.value + other.value
        else:
            result_value = self.value + other
        
        # Create tainted result
        result = TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
        
        # Emit propagation event
        emit("taint_propagation", {
            "operation": "__add__",
            "source": self.source,
            "result_preview": str(result_value)[:100],
            "stack": traceback.format_stack(limit=5)
        })
        
        return result
    
    def __radd__(self, other):
        """Reverse add for "string" + TaintedValue"""
        from hooks.events import emit
        import traceback
        
        result_value = other + self.value
        result = TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
        
        emit("taint_propagation", {
            "operation": "__radd__",
            "source": self.source,
            "result_preview": str(result_value)[:100],
            "stack": traceback.format_stack(limit=5)
        })
        
        return result
    
    def __mod__(self, other):
        """Propagate taint through % formatting (left side tainted)"""
        from hooks.events import emit
        import traceback
        
        result_value = self.value % other
        result = TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
        
        emit("taint_propagation", {
            "operation": "__mod__",
            "source": self.source,
            "result_preview": str(result_value)[:100],
            "stack": traceback.format_stack(limit=5)
        })
        
        return result
    
    def __rmod__(self, other):
        """Propagate taint when right side is tainted (other % self)"""
        from hooks.events import emit
        import traceback
        
        # other is the format string (e.g., "Template: %s")
        # self is the tainted value
        result_value = other % self.value
        result = TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
        
        emit("taint_propagation", {
            "operation": "__rmod__",
            "source": self.source,
            "result_preview": str(result_value)[:100],
            "stack": traceback.format_stack(limit=5)
        })
        
        return result
    
    def format(self, *args, **kwargs):
        """Propagate taint through format()"""
        from hooks.events import emit
        import traceback
        
        result_value = self.value.format(*args, **kwargs)
        result = TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
        
        emit("taint_propagation", {
            "operation": "format",
            "source": self.source,
            "result_preview": str(result_value)[:100],
            "stack": traceback.format_stack(limit=5)
        })
        
        return result
    
    def upper(self):
        """Propagate taint through upper()"""
        result_value = self.value.upper() if hasattr(self.value, 'upper') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def lower(self):
        """Propagate taint through lower()"""
        result_value = self.value.lower() if hasattr(self.value, 'lower') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def strip(self):
        """Propagate taint through strip()"""
        result_value = self.value.strip() if hasattr(self.value, 'strip') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def lstrip(self):
        """Propagate taint through lstrip()"""
        result_value = self.value.lstrip() if hasattr(self.value, 'lstrip') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def rstrip(self):
        """Propagate taint through rstrip()"""
        result_value = self.value.rstrip() if hasattr(self.value, 'rstrip') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def replace(self, old, new):
        """Propagate taint through replace()"""
        result_value = self.value.replace(old, new) if hasattr(self.value, 'replace') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def title(self):
        """Propagate taint through title()"""
        result_value = self.value.title() if hasattr(self.value, 'title') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def __getitem__(self, key):
        """Propagate taint through indexing/slicing"""
        result_value = self.value[key]
        # Handle both single index and slicing
        if isinstance(result_value, (str, list, tuple)):
            return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
        return result_value
    
    def __len__(self):
        """Support len() on TaintedValue"""
        return len(self.value)
    
    def capitalize(self):
        """Propagate taint through capitalize()"""
        result_value = self.value.capitalize() if hasattr(self.value, 'capitalize') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)
    
    def swapcase(self):
        """Propagate taint through swapcase()"""
        result_value = self.value.swapcase() if hasattr(self.value, 'swapcase') else self.value
        return TaintedValue(result_value, self.taint_id, self.source, self.source_type, self.metadata)


def mark_tainted(value: Any, source: str, source_type: str, metadata: Optional[Dict] = None) -> Any:
    """
    Mark a value as tainted.
    
    Args:
        value: The value to mark as tainted
        source: Description of where the taint came from (e.g., "request.args.username")
        source_type: Category of the taint source (e.g., "HTTP_INPUT", "FILE_READ")
        metadata: Optional additional context
    
    Returns:
        The tainted value (may be wrapped or original with registry entry)
    
    Example:
        >>> user_input = mark_tainted("admin", source="request.args.user", source_type="HTTP_INPUT")
        >>> is_tainted(user_input)
        True
    """
    # Generate unique taint ID
    taint_id = f"taint-{uuid.uuid4().hex[:8]}"
    
    # Store taint metadata in registry
    obj_id = id(value)
    _taint_registry[taint_id] = {
        "taint_id": taint_id,
        "source": source,
        "source_type": source_type,
        "metadata": metadata or {},
        "obj_id": obj_id,
    }
    
    # Mark this object ID as tainted
    _tainted_objects.add(obj_id)
    
    # For immutable types (str, int, bytes), wrap them
    # For mutable types, we track by ID
    if isinstance(value, (str, int, float, bytes, bool)):
        wrapped = TaintedValue(value, taint_id, source, source_type, metadata)
        # Update registry with wrapped object's ID too
        _tainted_objects.add(id(wrapped))
        _taint_registry[taint_id]["wrapped_obj_id"] = id(wrapped)
        return wrapped
    else:
        # For mutable objects, just track in registry
        return value


def is_tainted(value: Any) -> bool:
    """
    Check if a value is tainted.
    
    Args:
        value: The value to check
    
    Returns:
        True if the value is tainted, False otherwise
    
    Example:
        >>> x = mark_tainted("test", source="input", source_type="USER")
        >>> is_tainted(x)
        True
        >>> is_tainted("clean")
        False
    """
    # Check if it's a TaintedValue wrapper
    if isinstance(value, TaintedValue):
        return True
    
    # Check if object ID is in tainted set
    obj_id = id(value)
    return obj_id in _tainted_objects


def get_taint_info(value: Any) -> Optional[Dict[str, Any]]:
    """
    Get taint metadata for a tainted value.
    
    Args:
        value: The tainted value
    
    Returns:
        Dictionary with taint metadata, or None if not tainted
    
    Example:
        >>> x = mark_tainted("test", source="request.args.user", source_type="HTTP_INPUT")
        >>> info = get_taint_info(x)
        >>> info["source"]
        'request.args.user'
    """
    if not is_tainted(value):
        return None
    
    # If it's a TaintedValue, get info directly
    if isinstance(value, TaintedValue):
        return {
            "taint_id": value.taint_id,
            "source": value.source,
            "source_type": value.source_type,
            "metadata": value.metadata,
        }
    
    # Otherwise, search registry by object ID
    obj_id = id(value)
    for taint_id, info in _taint_registry.items():
        if info.get("obj_id") == obj_id or info.get("wrapped_obj_id") == obj_id:
            return {
                "taint_id": info["taint_id"],
                "source": info["source"],
                "source_type": info["source_type"],
                "metadata": info.get("metadata", {}),
            }
    
    return None


def clear_taint_registry():
    """
    Clear all taint tracking data.
    Useful for testing or resetting state.
    """
    global _taint_registry, _tainted_objects
    _taint_registry.clear()
    _tainted_objects.clear()


def get_taint_stats() -> Dict[str, Any]:
    """
    Get statistics about current taint tracking.
    
    Returns:
        Dictionary with stats about tainted objects
    """
    return {
        "total_tainted_objects": len(_tainted_objects),
        "taint_registry_size": len(_taint_registry),
        "source_types": list({info["source_type"] for info in _taint_registry.values()}),
    }


# Emit taint source event when marking data as tainted
def _emit_taint_source_event(taint_id: str, source: str, source_type: str):
    """Emit an event when a new taint source is detected"""
    from hooks.events import emit
    import traceback
    
    emit("taint_source", {
        "taint_id": taint_id,
        "source": source,
        "source_type": source_type,
        "stack": traceback.format_stack(limit=5),
    })


# Update mark_tainted to emit event
_original_mark_tainted = mark_tainted

def mark_tainted(value: Any, source: str, source_type: str, metadata: Optional[Dict] = None) -> Any:
    """Mark a value as tainted and emit event"""
    result = _original_mark_tainted(value, source, source_type, metadata)
    
    # Get taint ID from result
    if isinstance(result, TaintedValue):
        taint_id = result.taint_id
    else:
        # Find the taint ID we just created
        obj_id = id(value)
        taint_id = None
        for tid, info in _taint_registry.items():
            if info.get("obj_id") == obj_id:
                taint_id = tid
                break
    
    if taint_id:
        _emit_taint_source_event(taint_id, source, source_type)
    
    return result

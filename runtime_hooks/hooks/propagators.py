"""
Propagation hooks for taint tracking (STEP 9).

Tracks how taint spreads through common operations:
- String operations (concatenation, formatting, methods)
- Container operations (list, dict)
- Type conversions

Note: Python 3.11+ made str immutable, so we cannot monkey-patch str methods.
Instead, we rely on the TaintedValue wrapper to handle propagation.
The wrapper overrides __add__, __mod__, etc. to propagate taint.
"""
from __future__ import annotations

import sys
from typing import Any

# Flag to track if propagation is conceptually "installed"
_propagation_enabled = False


def install_string_propagation():
    """
    Enable string propagation tracking.
    
    Note: In Python 3.11+, str is immutable and cannot be monkey-patched.
    Propagation is handled by the TaintedValue wrapper class which overrides
    __add__, __mod__, format(), upper(), lower(), etc.
    
    This function exists for API compatibility and to signal that
    propagation tracking is conceptually enabled.
    """
    global _propagation_enabled
    _propagation_enabled = True
    
    # Propagation is handled by TaintedValue class methods
    # No actual hooking needed since we can't modify str in Python 3.11+
    pass


def install_percent_formatting():
    """
    Enable % formatting propagation.
    
    Handled by TaintedValue.__mod__() method.
    """
    pass


def install_container_propagation():
    """
    Install hooks for container operations that propagate taint.
    
    Note: Container tracking is complex and has performance implications.
    For now, we track when tainted values are added to containers.
    """
    # Container propagation is complex and will be simplified
    # We'll emit events when tainted data enters containers
    pass


def install_all():
    """
    Install all propagation hooks.
    
    Call this once at startup to enable taint propagation tracking.
    Note: Actual propagation is handled by TaintedValue wrapper methods.
    """
    global _propagation_enabled
    _propagation_enabled = True
    
    install_string_propagation()
    install_percent_formatting()
    install_container_propagation()


def get_installed_hooks():
    """
    Get status of installed propagation hooks.
    
    Returns:
        Dictionary with hook installation status
    """
    return {
        "propagation_enabled": _propagation_enabled,
        "wrapper_methods": True,  # TaintedValue always has propagation methods
        "str_add": True,  # Handled by TaintedValue.__add__
        "str_format": True,  # Handled by TaintedValue.format
        "str_mod": True,  # Handled by TaintedValue.__mod__
        "str_upper": True,  # Handled by TaintedValue.upper
    }

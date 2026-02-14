"""
Source hooks for automatic taint marking (STEP 8).

Hooks common data entry points to automatically mark incoming data as tainted:
- HTTP request parameters (Flask)
- File operations
- Environment variables
- Command line arguments
"""
from __future__ import annotations

import sys
import os
import builtins
from typing import Any, Optional


def install_flask_hooks():
    """
    Install hooks for Flask request objects.
    
    Marks data from HTTP requests as tainted:
    - request.args.get() / request.args[]
    - request.form.get() / request.form[]
    - request.json.get() / request.json[]
    - request.cookies.get()
    - request.headers.get()
    """
    # Only install if Flask is imported
    if 'flask' not in sys.modules:
        return
    
    try:
        from flask import request
        from werkzeug.datastructures import ImmutableMultiDict
        from hooks.taint import mark_tainted
        
        # Hook ImmutableMultiDict.get() used by request.args, request.form
        if not hasattr(ImmutableMultiDict.get, '_taint_hooked'):
            original_get = ImmutableMultiDict.get
            
            def tainted_get(self, key, default=None, type=None):
                """Wrapper that marks Flask request data as tainted"""
                value = original_get(self, key, default, type)
                
                if value is not None and value != default:
                    # Determine which part of request this is from
                    source_type = "HTTP_INPUT"
                    try:
                        if self is request.args:
                            source = f"request.args.{key}"
                        elif self is request.form:
                            source = f"request.form.{key}"
                        elif self is request.cookies:
                            source = f"request.cookies.{key}"
                        else:
                            source = f"request.{key}"
                    except:
                        source = f"request.{key}"
                    
                    return mark_tainted(value, source=source, source_type=source_type)
                
                return value
            
            tainted_get._taint_hooked = True
            ImmutableMultiDict.get = tainted_get
        
        # Hook request.json access
        # Note: request.json returns dict, we'll hook dict access separately
        
    except ImportError:
        pass  # Flask not available


def install_file_hooks():
    """
    Install hooks for file operations.
    
    Marks file content as tainted when read:
    - open().read()
    - open().readline()
    - open().readlines()
    """
    # File operations are already hooked in sinks.py for tracking
    # Here we add taint marking
    
    # Hook the read methods on file objects
    # This is tricky because file objects are created by open()
    # We'll hook it at the open() level instead
    pass  # Will implement with open() wrapper


def install_env_hooks():
    """
    Install hooks for environment variable access.
    
    Marks environment variables as tainted:
    - os.getenv()
    - os.environ.get()
    - os.environ[]
    """
    from hooks.taint import mark_tainted
    
    # Hook os.getenv()
    if not hasattr(os.getenv, '_taint_hooked'):
        original_getenv = os.getenv
        
        def tainted_getenv(key, default=None):
            """Wrapper that marks environment variables as tainted"""
            value = original_getenv(key, default)
            
            if value is not None and value != default:
                return mark_tainted(value, 
                    source=f"os.getenv('{key}')",
                    source_type="ENV_VAR")
            
            return value
        
        tainted_getenv._taint_hooked = True
        os.getenv = tainted_getenv
    
    # Hook os.environ.get()
    if not hasattr(os.environ.get, '_taint_hooked'):
        original_environ_get = os.environ.get
        
        def tainted_environ_get(key, default=None):
            """Wrapper that marks os.environ access as tainted"""
            value = original_environ_get(key, default)
            
            if value is not None and value != default:
                return mark_tainted(value,
                    source=f"os.getenv('{key}')",  # Use consistent naming
                    source_type="ENV_VAR")
            
            return value
        
        tainted_environ_get._taint_hooked = True
        os.environ.get = tainted_environ_get


def install_argv_hooks():
    """
    Install hooks for command line argument access.
    
    Marks sys.argv values as tainted when accessed.
    Note: This is challenging because sys.argv is a list.
    """
    from hooks.taint import mark_tainted
    
    # Wrap sys.argv with a proxy that taints on access
    # This is advanced - for now, we'll provide a helper function
    
    # Store original argv
    if not hasattr(sys, '_original_argv'):
        sys._original_argv = sys.argv[:]
    
    # Replace with tainted versions
    tainted_argv = []
    for i, arg in enumerate(sys._original_argv):
        tainted_arg = mark_tainted(arg,
            source=f"sys.argv[{i}]",
            source_type="CLI_ARG")
        tainted_argv.append(tainted_arg)
    
    sys.argv = tainted_argv


def install_input_hook():
    """
    Install hook for input() function.
    
    Marks user input from stdin as tainted.
    """
    from hooks.taint import mark_tainted
    
    if not hasattr(builtins.input, '_taint_hooked'):
        original_input = builtins.input
        
        def tainted_input(prompt=''):
            """Wrapper that marks input() data as tainted"""
            value = original_input(prompt)
            return mark_tainted(value,
                source="input()",
                source_type="USER_INPUT")
        
        tainted_input._taint_hooked = True
        builtins.input = tainted_input


def install_all():
    """
    Install all source hooks.
    
    Call this once at startup to enable automatic taint marking
    for all supported data sources.
    """
    install_flask_hooks()
    install_file_hooks()
    install_env_hooks()
    install_argv_hooks()
    install_input_hook()


# Convenience function to check which hooks are installed
def get_installed_hooks():
    """
    Get list of installed source hooks.
    
    Returns:
        Dictionary with hook status
    """
    status = {
        "flask": 'flask' in sys.modules and hasattr(
            sys.modules.get('werkzeug.datastructures', {}).get('ImmutableMultiDict', {}).get('get', {}), 
            '_taint_hooked'
        ),
        "env": hasattr(os.getenv, '_taint_hooked'),
        "input": hasattr(builtins.input, '_taint_hooked'),
        "argv": hasattr(sys, '_original_argv'),
    }
    return status


# Auto-install hooks for commonly available sources
# (Flask hooks will only install if Flask is imported)
def auto_install():
    """
    Automatically install hooks for available sources.
    
    This is called when the module is imported if desired.
    """
    # Install non-Flask hooks immediately
    install_env_hooks()
    install_argv_hooks()
    install_input_hook()
    
    # Flask hooks will be installed if Flask is detected
    install_flask_hooks()

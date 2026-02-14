"""
Helper to handle format() when called on untainted strings with tainted arguments.

Since we can't hook str.format directly in Python 3.11+, we provide utilities
to manually check and propagate taint through format operations.
"""
from hooks.taint import is_tainted, get_taint_info, mark_tainted


def propagate_format_taint(format_string, *args, **kwargs):
    """
    Helper function to propagate taint through format operations.
    
    Usage:
        Instead of: result = "Hello {}".format(tainted)
        Use: result = propagate_format_taint("Hello {}", tainted)
    
    Returns:
        The formatted string, tainted if any arguments were tainted
    """
    # Perform the formatting
    result = format_string.format(*args, **kwargs)
    
    # Check if any arguments are tainted
    tainted_found = None
    
    if is_tainted(format_string):
        tainted_found = get_taint_info(format_string)
    else:
        # Check args
        for arg in args:
            if is_tainted(arg):
                tainted_found = get_taint_info(arg)
                break
        
        # Check kwargs
        if not tainted_found:
            for v in kwargs.values():
                if is_tainted(v):
                    tainted_found = get_taint_info(v)
                    break
    
    if tainted_found:
        return mark_tainted(result,
            source=tainted_found['source'],
            source_type=tainted_found['source_type'],
            metadata={'operation': 'format', 'propagated_from': tainted_found['source']})
    
    return result

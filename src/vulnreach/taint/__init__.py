"""Static Taint Analysis Module

Analyzes Python code to detect taint flows from sources (user input) to sinks (vulnerable functions).
Maps taint flows to vulnerable packages identified by SCA scanning.
"""

from .static_taint import StaticTaintAnalyzer, TaintFlow, TaintSource, TaintSink

__all__ = ['StaticTaintAnalyzer', 'TaintFlow', 'TaintSource', 'TaintSink']

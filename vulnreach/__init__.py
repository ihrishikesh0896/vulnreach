"""
VulnReach - Smart Vulnerability Reachability Analyzer

Beyond version checking: Discover which vulnerabilities in your dependencies 
actually matter by analyzing real code usage patterns.
"""

__version__ = "1.0.0"
__author__ = "VulnReach Team"
__email__ = "contact@vulnreach.dev"
__license__ = "MIT"

from .core import (
    SyftSBOMGenerator,
    TrivySCAScanner, 
    SecurityReporter,
    Component,
    Vulnerability
)

__all__ = [
    "SyftSBOMGenerator",
    "TrivySCAScanner", 
    "SecurityReporter",
    "Component",
    "Vulnerability",
    "__version__"
]
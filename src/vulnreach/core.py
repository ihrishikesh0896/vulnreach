"""
VulnReach Core Components

Core classes and functionality for vulnerability analysis.
"""

import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import core components from tracer_
from vulnreach.tracer_ import (
    Component,
    Vulnerability,
    SyftSBOMGenerator,
    TrivySCAScanner,
    SecurityReporter,
    check_prerequisites,
    consolidate_fixed_versions,
    get_project_name,
    create_security_findings_dir
)

__all__ = [
    "Component",
    "Vulnerability", 
    "SyftSBOMGenerator",
    "TrivySCAScanner",
    "SecurityReporter",
    "check_prerequisites",
    "consolidate_fixed_versions",
    "get_project_name",
    "create_security_findings_dir"
]
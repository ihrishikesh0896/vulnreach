#!/usr/bin/env python3
"""
Example: Agent-Based Reachability Analysis
Demonstrates the multi-agent vulnerability reachability system
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from vulnreach.agents import AgentCoordinator


def main():
    print("=" * 70)
    print("Agent-Based Vulnerability Reachability Analysis")
    print("=" * 70)
    print()
    
    # Initialize coordinator with project root
    project_root = Path(__file__).parent.parent
    coordinator = AgentCoordinator(str(project_root))
    
    print("[1] Checking Agent Status...")
    status = coordinator.get_agent_status()
    print(f"Active Agents: {len(status['agents'])}")
    for name, info in status['agents'].items():
        print(f"  - {name.upper()}: {len(info['capabilities'])} capabilities")
    print()
    
    print("[2] Getting Project Dependencies...")
    deps = coordinator.get_dependencies()
    if 'error' not in deps:
        print(f"Package Manager: {deps.get('package_manager', 'unknown')}")
        print(f"Total Dependencies: {deps.get('count', 0)}")
        
        # Show first 5 dependencies
        dependencies = deps.get('dependencies', {})
        if dependencies:
            print("Sample dependencies:")
            for i, (name, info) in enumerate(list(dependencies.items())[:5]):
                print(f"  - {name} ({info.get('version', 'unknown')})")
    else:
        print(f"Error: {deps['error']}")
    print()
    
    print("[3] Example: Checking 'requests' Package...")
    pkg_result = coordinator.analyze_package(
        package_name='requests',
        language='python',
        ecosystem='PyPI'
    )
    
    print(f"Package: {pkg_result.get('package', 'N/A')}")
    print(f"Installed: {pkg_result.get('installed', False)}")
    print(f"Version: {pkg_result.get('version', 'N/A')}")
    print(f"Vulnerabilities Found: {pkg_result.get('vulnerability_count', 0)}")
    print(f"Reachable: {pkg_result.get('reachable_vulnerabilities', 0)}")
    print(f"Risk Level: {pkg_result.get('risk_level', 'N/A').upper()}")
    print(f"Recommendation: {pkg_result.get('recommendation', 'N/A')}")
    print()
    
    print("[4] Example: Finding Function Usage...")
    func_result = coordinator.find_function_usage(
        function_name='requests.get',
        language='python'
    )
    
    if func_result.get('found', 0) > 0:
        print(f"Function 'requests.get' found in {func_result['found']} locations")
    else:
        print("Function 'requests.get' not found in codebase")
    print()
    
    print("=" * 70)
    print("Demo Complete!")
    print()
    print("To run full project analysis:")
    print("  coordinator.analyze_project()")
    print()
    print("To analyze specific CVE:")
    print("  coordinator.analyze_cve('CVE-2023-12345', package_name='requests')")
    print("=" * 70)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
VulnReach CLI - Command Line Interface

Entry point for the vulnreach command-line tool.
"""

import sys
from pathlib import Path

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from vulnreach.tracer_ import main as tracer_main

def main():
    """Main CLI entry point."""
    try:
        tracer_main()
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
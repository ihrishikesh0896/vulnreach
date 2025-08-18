#!/usr/bin/env python3
"""
CLI entry point for Security SCA Tool
"""

import sys
import os

# Add the package directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tracer_ import main as core_main

def main():
    """CLI entry point"""
    try:
        core_main()
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
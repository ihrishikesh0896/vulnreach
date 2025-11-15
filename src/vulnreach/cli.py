#!/usr/bin/env python3
"""
VulnReach CLI - Command Line Interface

Entry point for the vulnreach command-line tool.
"""

import sys
from pathlib import Path

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent
# Prioritize explicit src path to avoid stale build/lib modules
src_path = project_root / 'src'
if src_path.exists():
    sys.path.insert(0, str(src_path))
# Remove any build/lib path that might shadow editable source
for _p in list(sys.path):
    if _p.endswith('/build/lib'):
        try:
            sys.path.remove(_p)
        except ValueError:
            pass
sys.path.insert(0, str(project_root))

from vulnreach.tracer_ import main as tracer_main
from vulnreach.config import get_config_loader
import logging

def main():
    """Main CLI entry point."""
    try:
        # Initialize configuration on startup
        _initialize_config()
        tracer_main()
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


def _initialize_config():
    """Initialize configuration loading on CLI startup"""
    try:
        config_loader = get_config_loader()
        config = config_loader.get_config()
        
        # Log configuration status (if logging is enabled)
        logger = logging.getLogger(__name__)
        if config.providers:
            logger.debug(f"Loaded configuration with {len(config.providers)} providers")
        else:
            logger.debug("No providers configured")
            
    except FileNotFoundError:
        # Config file doesn't exist - this is ok, we'll use defaults
        logger = logging.getLogger(__name__)
        logger.debug("Config file not found, using defaults")
        
    except Exception as e:
        # Config file exists but has errors - warn user
        print(f"⚠️  Warning: Failed to load configuration from ~/.vulnreach/config/creds.yaml: {e}")
        print("   Continuing with default settings...")
        
        # Log the full error for debugging
        logger = logging.getLogger(__name__)
        logger.warning(f"Config loading failed: {e}", exc_info=True)

if __name__ == "__main__":
    main()
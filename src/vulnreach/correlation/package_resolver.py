"""Package Resolver - Normalize package names for matching

Handles the complexity of matching Python module imports to PyPI package names.

Examples:
- import flask → Flask==2.0.1
- import PIL → Pillow==8.3.1
- import yaml → PyYAML==5.4.1
"""
from __future__ import annotations

from typing import Optional, Dict, Set
import re


# Canonical mapping of import names to PyPI package names
# This handles common cases where import name != package name
IMPORT_TO_PACKAGE = {
    # Web frameworks
    "flask": "Flask",
    "django": "Django",
    "fastapi": "FastAPI",
    "tornado": "tornado",
    "bottle": "bottle",
    "pyramid": "pyramid",

    # Image processing
    "PIL": "Pillow",
    "cv2": "opencv-python",

    # Data science
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "cv": "opencv-python",

    # YAML
    "yaml": "PyYAML",

    # Databases
    "psycopg2": "psycopg2-binary",
    "MySQLdb": "mysqlclient",
    "pymongo": "pymongo",

    # Utilities
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "PyJWT",
    "bs4": "beautifulsoup4",
    "lxml": "lxml",

    # Crypto
    "Crypto": "pycryptodome",
    "cryptography": "cryptography",

    # Testing
    "pytest": "pytest",
    "nose": "nose",

    # Common packages
    "requests": "requests",
    "urllib3": "urllib3",
    "certifi": "certifi",
    "charset_normalizer": "charset-normalizer",
    "idna": "idna",
}


class PackageResolver:
    """Resolve import names to PyPI package names"""

    def __init__(self):
        self.cache: Dict[str, Optional[str]] = {}

    def normalize_package_name(self, name: str) -> str:
        """Normalize a package name to PyPI canonical form

        PyPI treats package names case-insensitively and treats
        hyphens, underscores, and dots as equivalent.

        Args:
            name: Package name (e.g., "Flask", "django_rest_framework")

        Returns:
            Normalized name (lowercase, hyphens replaced with underscores)
        """
        # Convert to lowercase
        normalized = name.lower()

        # Replace hyphens and dots with underscores
        normalized = normalized.replace('-', '_').replace('.', '_')

        return normalized

    def resolve_import_to_package(self, import_name: str) -> Set[str]:
        """Resolve an import name to possible package names

        Args:
            import_name: Module name from import statement (e.g., "flask")

        Returns:
            Set of possible package names (may include variants)
        """
        if import_name in self.cache:
            cached = self.cache[import_name]
            return {cached} if cached else set()

        candidates = set()

        # Check canonical mapping first
        if import_name in IMPORT_TO_PACKAGE:
            canonical = IMPORT_TO_PACKAGE[import_name]
            candidates.add(canonical)
            candidates.add(self.normalize_package_name(canonical))

        # Add the import name itself (many packages match exactly)
        candidates.add(import_name)
        candidates.add(self.normalize_package_name(import_name))

        # Try capitalized version (Flask, Django, etc.)
        candidates.add(import_name.capitalize())

        # Try lowercase version
        candidates.add(import_name.lower())

        # Cache the result
        if len(candidates) == 1:
            self.cache[import_name] = list(candidates)[0]

        return candidates

    def get_parent_package(self, module_name: str) -> Optional[str]:
        """Extract parent package from a submodule

        Args:
            module_name: Full module name (e.g., "flask.app")

        Returns:
            Parent package name (e.g., "flask") or None if no parent
        """
        if '.' in module_name:
            return module_name.split('.')[0]
        return None

    def match_package(
        self,
        import_name: str,
        sbom_packages: Dict[str, any]
    ) -> tuple[Optional[str], float]:
        """Match an import name to an SBOM package

        Args:
            import_name: Module name from import
            sbom_packages: Dict mapping normalized package names to components

        Returns:
            Tuple of (matched_package_name, confidence_score)
            confidence_score: 0.0 to 1.0
        """
        # Try direct match first
        candidates = self.resolve_import_to_package(import_name)

        for candidate in candidates:
            normalized = self.normalize_package_name(candidate)
            if normalized in sbom_packages:
                # Direct match = high confidence
                return (candidate, 1.0)

        # Try parent package for submodules
        parent = self.get_parent_package(import_name)
        if parent:
            parent_candidates = self.resolve_import_to_package(parent)
            for candidate in parent_candidates:
                normalized = self.normalize_package_name(candidate)
                if normalized in sbom_packages:
                    # Submodule match = medium confidence
                    return (candidate, 0.8)

        # Try fuzzy matching
        for candidate in candidates:
            normalized_candidate = self.normalize_package_name(candidate)
            for pkg_name in sbom_packages.keys():
                if normalized_candidate in pkg_name or pkg_name in normalized_candidate:
                    # Fuzzy match = lower confidence
                    return (pkg_name, 0.6)

        # No match
        return (None, 0.0)


# Global resolver instance
_resolver = PackageResolver()


def resolve_import(import_name: str) -> Set[str]:
    """Convenience function to resolve an import name

    Args:
        import_name: Module name from import

    Returns:
        Set of possible package names
    """
    return _resolver.resolve_import_to_package(import_name)


def match_import_to_sbom(
    import_name: str,
    sbom_packages: Dict[str, any]
) -> tuple[Optional[str], float]:
    """Convenience function to match import to SBOM package

    Args:
        import_name: Module name from import
        sbom_packages: Dict mapping normalized package names to components

    Returns:
        Tuple of (matched_package_name, confidence_score)
    """
    return _resolver.match_package(import_name, sbom_packages)

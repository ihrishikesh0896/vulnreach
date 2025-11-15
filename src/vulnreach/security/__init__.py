"""
Security configuration and setup module
"""

__version__ = "1.0.0"
__all__ = ["validator", "subprocess_security"]
"""
Secure input validation module for VulnReach

This module provides validation for all user inputs to prevent injection attacks,
path traversal, and other input-based vulnerabilities.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from pydantic import BaseModel, Field, validator, ValidationError
import logging

logger = logging.getLogger(__name__)


class SecurityValidationError(ValueError):
    """Raised when input validation fails for security reasons"""
    pass


# ============================================================================
# PYDANTIC MODELS FOR INPUT VALIDATION
# ============================================================================

class FilePathModel(BaseModel):
    """Validate file paths to prevent directory traversal"""
    path: str
    allowed_base: Optional[str] = None
    allow_non_existent: bool = True

    @validator('path')
    def validate_path(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Path must be a non-empty string")

        if len(v) > 4096:
            raise ValueError("Path is too long")

        # Detect path traversal attempts
        if ".." in v:
            raise SecurityValidationError("Path traversal detected")

        if "\x00" in v:
            raise SecurityValidationError("Null byte in path")

        return v

    def get_safe_path(self) -> Path:
        """Get validated path as resolved Path object"""
        try:
            path = Path(self.path).resolve()

            # Verify within allowed base if specified
            if self.allowed_base:
                base = Path(self.allowed_base).resolve()
                path.relative_to(base)  # Raises ValueError if outside

            return path
        except Exception as e:
            raise SecurityValidationError(f"Invalid path: {e}")


class CVEIdModel(BaseModel):
    """Validate CVE identifiers"""
    cve_id: str = Field(..., min_length=5, max_length=20)

    @validator('cve_id')
    def validate_cve_format(cls, v):
        # Standard CVE format: CVE-YYYY-NNNNN (or more digits)
        if not re.match(r'^CVE-\d{4}-\d{4,}$', v, re.IGNORECASE):
            raise ValueError("Invalid CVE format. Expected: CVE-YYYY-NNNNN")
        return v.upper()


class PackageNameModel(BaseModel):
    """Validate package names"""
    name: str = Field(..., min_length=1, max_length=255)
    version: Optional[str] = Field(None, max_length=50)

    @validator('name')
    def validate_package_name(cls, v):
        # Allow alphanumeric, hyphens, underscores, dots
        if not re.match(r'^[a-zA-Z0-9\-_.]+$', v):
            raise ValueError("Invalid characters in package name")
        return v

    @validator('version')
    def validate_version(cls, v):
        if v is None:
            return v
        # Allow semantic versioning patterns
        if not re.match(r'^[a-zA-Z0-9\.\-_+]+$', v):
            raise ValueError("Invalid version format")
        return v


class URLModel(BaseModel):
    """Validate URLs safely"""
    url: str = Field(..., max_length=2048)

    @validator('url')
    def validate_url(cls, v):
        allowed_schemes = ('http', 'https', 'git', 'ssh')

        try:
            from urllib.parse import urlparse
            parsed = urlparse(v)

            if not parsed.scheme or parsed.scheme not in allowed_schemes:
                raise ValueError(f"Invalid URL scheme. Allowed: {', '.join(allowed_schemes)}")

            if not parsed.netloc:
                raise ValueError("Invalid URL: missing hostname")

            return v
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")


class CommandArgumentModel(BaseModel):
    """Validate command line arguments"""
    argument: str = Field(..., max_length=1024)
    allow_wildcards: bool = False

    @validator('argument')
    def validate_argument(cls, v, values):
        # Never allow shell metacharacters that could enable injection
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r']

        for char in dangerous_chars:
            if char in v:
                raise SecurityValidationError(
                    f"Shell injection detected: forbidden character '{char}'"
                )

        # Validate wildcards if disallowed
        if not values.get('allow_wildcards', False):
            if '*' in v or '?' in v or '[' in v:
                raise SecurityValidationError("Wildcards not allowed in arguments")

        return v


class JSONInputModel(BaseModel):
    """Validate JSON input data"""
    data: Dict = Field(...)
    max_depth: int = 20

    @validator('data', pre=True)
    def validate_json_depth(cls, v, values):
        """Prevent JSON bomb attacks by checking depth"""
        def check_depth(obj, current_depth=0, max_depth=20):
            if current_depth > max_depth:
                raise SecurityValidationError("JSON structure too deeply nested")

            if isinstance(obj, dict):
                for value in obj.values():
                    check_depth(value, current_depth + 1, max_depth)
            elif isinstance(obj, list):
                for item in obj:
                    check_depth(item, current_depth + 1, max_depth)

        max_depth = values.get('max_depth', 20)
        check_depth(v, max_depth=max_depth)
        return v


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_filepath(path: str, allowed_base: Optional[str] = None) -> Path:
    """
    Validate and return safe file path

    Args:
        path: Path to validate
        allowed_base: Optional base directory to restrict paths

    Returns:
        Validated Path object

    Raises:
        SecurityValidationError: If path is invalid or unsafe
    """
    try:
        model = FilePathModel(path=path, allowed_base=allowed_base)
        return model.get_safe_path()
    except ValidationError as e:
        logger.error(f"Path validation failed: {e}")
        raise SecurityValidationError(f"Invalid path: {path}") from e


def validate_cve_id(cve_id: str) -> str:
    """
    Validate CVE identifier

    Args:
        cve_id: CVE ID to validate

    Returns:
        Validated CVE ID (normalized to uppercase)

    Raises:
        SecurityValidationError: If CVE ID is invalid
    """
    try:
        model = CVEIdModel(cve_id=cve_id)
        return model.cve_id
    except ValidationError as e:
        logger.error(f"CVE validation failed: {e}")
        raise SecurityValidationError(f"Invalid CVE ID: {cve_id}") from e


def validate_package_name(name: str, version: Optional[str] = None) -> tuple:
    """
    Validate package name and version

    Args:
        name: Package name
        version: Optional version string

    Returns:
        Tuple of (name, version)

    Raises:
        SecurityValidationError: If package name/version is invalid
    """
    try:
        model = PackageNameModel(name=name, version=version)
        return model.name, model.version
    except ValidationError as e:
        logger.error(f"Package validation failed: {e}")
        raise SecurityValidationError(f"Invalid package: {name}") from e


def validate_url(url: str) -> str:
    """
    Validate URL

    Args:
        url: URL to validate

    Returns:
        Validated URL

    Raises:
        SecurityValidationError: If URL is invalid
    """
    try:
        model = URLModel(url=url)
        return model.url
    except ValidationError as e:
        logger.error(f"URL validation failed: {e}")
        raise SecurityValidationError(f"Invalid URL: {url}") from e


def validate_command_argument(arg: str, allow_wildcards: bool = False) -> str:
    """
    Validate command line argument for shell injection

    Args:
        arg: Argument to validate
        allow_wildcards: Whether wildcards are allowed

    Returns:
        Validated argument

    Raises:
        SecurityValidationError: If argument contains injection attempts
    """
    try:
        model = CommandArgumentModel(argument=arg, allow_wildcards=allow_wildcards)
        return model.argument
    except ValidationError as e:
        logger.error(f"Argument validation failed: {e}")
        raise SecurityValidationError(f"Invalid argument: argument contains dangerous characters") from e


def validate_json_input(data: Dict, max_depth: int = 20) -> Dict:
    """
    Validate JSON input data

    Args:
        data: Data to validate
        max_depth: Maximum nesting depth

    Returns:
        Validated data

    Raises:
        SecurityValidationError: If data is invalid or too deeply nested
    """
    try:
        model = JSONInputModel(data=data, max_depth=max_depth)
        return model.data
    except ValidationError as e:
        logger.error(f"JSON validation failed: {e}")
        raise SecurityValidationError(f"Invalid JSON data") from e


# ============================================================================
# VALIDATION UTILITIES
# ============================================================================

def sanitize_string(text: str, max_length: int = 1024) -> str:
    """
    Sanitize string input

    Args:
        text: Text to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized text

    Raises:
        SecurityValidationError: If text is too long
    """
    if len(text) > max_length:
        raise SecurityValidationError(f"Input exceeds maximum length of {max_length}")

    # Remove null bytes
    text = text.replace('\x00', '')

    # Normalize whitespace
    text = ' '.join(text.split())

    return text


def validate_file_size(filepath: Path, max_size: int = 100 * 1024 * 1024) -> int:
    """
    Validate file size to prevent resource exhaustion

    Args:
        filepath: Path to file
        max_size: Maximum file size in bytes (default: 100MB)

    Returns:
        File size in bytes

    Raises:
        SecurityValidationError: If file is too large
    """
    try:
        size = filepath.stat().st_size
        if size > max_size:
            raise SecurityValidationError(
                f"File size ({size} bytes) exceeds maximum ({max_size} bytes)"
            )
        return size
    except FileNotFoundError:
        raise SecurityValidationError(f"File not found: {filepath}")
    except Exception as e:
        raise SecurityValidationError(f"Cannot validate file: {e}")


if __name__ == "__main__":
    # Example usage
    print("Input Validation Module loaded successfully")
    print("Available validators:")
    print("  - validate_filepath()")
    print("  - validate_cve_id()")
    print("  - validate_package_name()")
    print("  - validate_url()")
    print("  - validate_command_argument()")
    print("  - validate_json_input()")


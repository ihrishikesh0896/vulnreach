#!/usr/bin/env python3
"""
Setup script for VulnReach (fallback for older pip versions)
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="vulnreach",
    version="1.0.0",
    description="Smart Vulnerability Reachability Analyzer - Beyond version checking",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="VulnReach Team",
    author_email="contact@vulnreach.dev",
    url="https://github.com/ihrishikesh0896/vulnreach",
    packages=find_packages(include=["vulnreach*", "utils*"]),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "vulnreach=vulnreach.cli:main",
            "vulnreach-scan=vulnreach.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators", 
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
    ],
    keywords="security vulnerability sca sbom reachability",
    license="MIT",
    include_package_data=True,
)
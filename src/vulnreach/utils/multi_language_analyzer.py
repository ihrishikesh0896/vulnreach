#!/usr/bin/env python3
"""
Multi-Language Vulnerability Reachability Analyzer

Automatically detects project language and runs appropriate reachability analysis.
"""

import os
from pathlib import Path
import importlib
from typing import Optional, Callable
from .vuln_reachability_analyzer import run_reachability_analysis
from .java_reachability_analyzer import run_java_reachability_analysis
from .javascript_reachability_analyzer import run_javascript_reachability_analysis
from .php_reachability_analyzer import run_php_reachability_analysis
from .go_reachability_analyzer import run_go_reachability_analysis
from .csharp_reachability_analyzer import run_csharp_reachability_analysis


# Optional debug flag
_DEBUG_IMPORTS = os.getenv("VULNREACH_DEBUG_IMPORTS") == "1"
if _DEBUG_IMPORTS:
    print(f"[DEBUG] multi_language_analyzer loaded from: {__file__}")

# Track import errors for analyzers (debug only)
_js_import_error: Optional[Exception] = None
_go_import_error: Optional[Exception] = None
_csharp_import_error: Optional[Exception] = None
_php_import_error: Optional[Exception] = None

# Dynamically load optional analyzers to avoid static import errors during analysis
run_javascript_reachability_analysis: Optional[Callable[[str, str, str], None]] = None
run_go_reachability_analysis: Optional[Callable[[str, str, str], None]] = None
run_csharp_reachability_analysis: Optional[Callable[[str, str, str], None]] = None
run_php_reachability_analysis: Optional[Callable[[str, str, str], None]] = None

try:
    _mod = importlib.import_module('.javascript_reachability_analyzer', package=__package__)
    run_javascript_reachability_analysis = getattr(_mod, 'run_javascript_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded JavaScript analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_javascript_reachability_analysis}")
except Exception as e:
    _js_import_error = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load JavaScript analyzer: {e.__class__.__name__}: {e}")

try:
    _mod = importlib.import_module('.go_reachability_analyzer', package=__package__)
    run_go_reachability_analysis = getattr(_mod, 'run_go_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded Go analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_go_reachability_analysis}")
except Exception as e:
    _go_import_error = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load Go analyzer: {e.__class__.__name__}: {e}")

try:
    _mod = importlib.import_module('.csharp_reachability_analyzer', package=__package__)
    run_csharp_reachability_analysis = getattr(_mod, 'run_csharp_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded C# analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_csharp_reachability_analysis}")
except Exception as e:
    _csharp_import_error = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load C# analyzer: {e.__class__.__name__}: {e}")

try:
    _mod = importlib.import_module('.php_reachability_analyzer', package=__package__)
    run_php_reachability_analysis = getattr(_mod, 'run_php_reachability_analysis', None)
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Loaded PHP analyzer: {_mod.__file__ if hasattr(_mod,'__file__') else 'no file'} => {run_php_reachability_analysis}")
except Exception as e:
    _php_import_error = e
    if _DEBUG_IMPORTS:
        print(f"[DEBUG] Failed to load PHP analyzer: {e.__class__.__name__}: {e}")


# Provide safe no-op stubs if dynamic import failed so unconditional calls won't crash
if run_javascript_reachability_analysis is None:
    def run_javascript_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ JavaScript analyzer unavailable; skipping reachability analysis.")
if run_go_reachability_analysis is None:
    def run_go_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ Go analyzer unavailable; skipping reachability analysis.")
if run_csharp_reachability_analysis is None:
    def run_csharp_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ C# analyzer unavailable; skipping reachability analysis.")
if run_php_reachability_analysis is None:
    def run_php_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):  # type: ignore
        print("⚠️ PHP analyzer unavailable; skipping reachability analysis.")


class ProjectLanguageDetector:
    """Detect the primary language of a project."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
    
    def detect_language(self) -> str:
        """Detect primary project language based on files and build configs."""
        file_counts = {}
        build_files = set()
        
        # Scan for files and build configurations
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', '__pycache__', '.venv', 'venv', 'node_modules',
                'target', 'build', '.gradle', '.idea', '.vscode', 'bin', 'out'
            }]
            
            for file in files:
                # Count source files
                if file.endswith('.py'):
                    file_counts['python'] = file_counts.get('python', 0) + 1
                elif file.endswith('.java'):
                    file_counts['java'] = file_counts.get('java', 0) + 1
                elif file.endswith('.js') or file.endswith('.ts'):
                    file_counts['javascript'] = file_counts.get('javascript', 0) + 1
                elif file.endswith('.go'):
                    file_counts['go'] = file_counts.get('go', 0) + 1
                elif file.endswith('.cs'):
                    file_counts['csharp'] = file_counts.get('csharp', 0) + 1
                elif file.endswith('.php'):
                    file_counts['php'] = file_counts.get('php', 0) + 1

                # Check for build files
                if file in {'pom.xml', 'build.gradle', 'build.gradle.kts'}:
                    build_files.add('java')
                elif file in {'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'}:
                    build_files.add('python')
                elif file in {'package.json', 'yarn.lock', 'package-lock.json'}:
                    build_files.add('javascript')
                elif file in {'go.mod', 'go.sum'}:
                    build_files.add('go')
                # csproj or solution files may be named per-project, so check suffixes
                elif file.endswith('.csproj') or file.endswith('.sln'):
                    build_files.add('csharp')
                elif file == 'composer.json':
                    build_files.add('php')

        # Determine language based on build files first, then file counts
        if 'java' in build_files and file_counts.get('java', 0) > 0:
            return 'java'
        elif 'python' in build_files and file_counts.get('python', 0) > 0:
            return 'python'
        elif 'javascript' in build_files and file_counts.get('javascript', 0) > 0:
            return 'javascript'
        elif 'go' in build_files and file_counts.get('go', 0) > 0:
            return 'go'
        elif 'csharp' in build_files and file_counts.get('csharp', 0) > 0:
            return 'csharp'
        elif 'php' in build_files and file_counts.get('php', 0) > 0:
            return 'php'

        # Fall back to file counts
        if file_counts:
            return max(file_counts, key=file_counts.get)
        
        return 'unknown'


def run_multi_language_analysis(project_root: str, consolidated_path: str, output_dir: str = None):
    """Run vulnerability reachability analysis for detected project language."""
    
    if not output_dir:
        output_dir = "security_findings"
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Detect project language
    detector = ProjectLanguageDetector(project_root)
    language = detector.detect_language()
    print('hereeeeee--------------')
    print(f"🔍 Detected project language: {language.upper()}")
    print('hereeeeee--------------',language)
    # Run appropriate analyzer
    if language == 'python':
        output_path = os.path.join(output_dir, "python_vulnerability_reachability_report.json")
        run_reachability_analysis(project_root, consolidated_path, output_path)

    elif language == 'java':
        output_path = os.path.join(output_dir, "java_vulnerability_reachability_report.json")
        run_java_reachability_analysis(project_root, consolidated_path, output_path)

    elif language == 'javascript':
        print('hereeeeee--------------')
        output_path = os.path.join(output_dir, "javascript_vulnerability_reachability_report.json")
        run_javascript_reachability_analysis(project_root, consolidated_path, output_path)

    elif language == 'go':
        output_path = os.path.join(output_dir, "go_vulnerability_reachability_report.json")
        run_go_reachability_analysis(project_root, consolidated_path, output_path)

    elif language == 'csharp':
        output_path = os.path.join(output_dir, "csharp_vulnerability_reachability_report.json")
        run_csharp_reachability_analysis(project_root, consolidated_path, output_path)

    elif language == 'php':
        output_path = os.path.join(output_dir, "php_vulnerability_reachability_report.json")
        run_php_reachability_analysis(project_root, consolidated_path, output_path)

    else:
        print(f"⚠️  Language '{language}' not supported for reachability analysis")
        print("   Falling back to basic vulnerability scanning")
    
    return language


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python multi_language_analyzer.py <project_root> <consolidated_json>")
        sys.exit(1)
    
    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else None
    
    run_multi_language_analysis(project_root, consolidated_path, output_dir)
#!/usr/bin/env python3
"""
Multi-Language Vulnerability Reachability Analyzer

Automatically detects project language and runs appropriate reachability analysis.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from .vuln_reachability_analyzer import run_reachability_analysis
from .java_reachability_analyzer import run_java_reachability_analysis


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
                
                # Check for build files
                if file in {'pom.xml', 'build.gradle', 'build.gradle.kts'}:
                    build_files.add('java')
                elif file in {'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'}:
                    build_files.add('python')
                elif file in {'package.json', 'yarn.lock', 'package-lock.json'}:
                    build_files.add('javascript')
                elif file in {'go.mod', 'go.sum'}:
                    build_files.add('go')
        
        # Determine language based on build files first, then file counts
        if 'java' in build_files and file_counts.get('java', 0) > 0:
            return 'java'
        elif 'python' in build_files and file_counts.get('python', 0) > 0:
            return 'python'
        elif 'javascript' in build_files and file_counts.get('javascript', 0) > 0:
            return 'javascript'
        elif 'go' in build_files and file_counts.get('go', 0) > 0:
            return 'go'
        
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
    
    print(f"🔍 Detected project language: {language.upper()}")
    
    # Run appropriate analyzer
    if language == 'python':
        output_path = os.path.join(output_dir, "python_vulnerability_reachability_report.json")
        run_reachability_analysis(project_root, consolidated_path, output_path)
        
    elif language == 'java':
        output_path = os.path.join(output_dir, "java_vulnerability_reachability_report.json")
        run_java_reachability_analysis(project_root, consolidated_path, output_path)
        
    elif language == 'javascript':
        print("⚠️  JavaScript reachability analysis not yet implemented")
        print("   Falling back to basic vulnerability scanning")
        
    elif language == 'go':
        print("⚠️  Go reachability analysis not yet implemented")
        print("   Falling back to basic vulnerability scanning")
        
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
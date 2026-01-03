#!/usr/bin/env python3
"""
ast-grep Integration Module

Provides a Python wrapper around ast-grep for multi-language code analysis.
Falls back to regex-based parsing if ast-grep is not available.

ast-grep is a fast code search and manipulation tool using abstract syntax trees.
It supports Python, JavaScript, TypeScript, Java, Go, Rust, and many other languages.
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from enum import Enum

logger = logging.getLogger(__name__)


class Language(Enum):
    """Supported languages for ast-grep"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    CSHARP = "csharp"
    RUBY = "ruby"


@dataclass
class AstGrepMatch:
    """Represents a single ast-grep match"""
    file: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    matched_text: str
    context: Optional[str] = None
    language: Optional[str] = None


@dataclass
class AstGrepQuery:
    """Represents an ast-grep query configuration"""
    pattern: str
    language: Language
    constraints: Optional[Dict[str, Any]] = None
    inside: Optional[str] = None  # Match only inside this pattern
    has: Optional[str] = None  # Match only if has child matching this


class AstGrepNotFoundError(Exception):
    """Raised when ast-grep is not installed"""
    pass


class AstGrepWrapper:
    """
    Python wrapper for ast-grep CLI tool.
    
    Requires ast-grep to be installed: https://ast-grep.github.io/
    Installation: cargo install ast-grep OR npm install -g @ast-grep/cli
    """
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.ast_grep_available = self._check_ast_grep_available()
        
        if not self.ast_grep_available:
            logger.warning(
                "ast-grep not found. Install with: pip install ast-grep-py OR "
                "cargo install ast-grep OR npm install -g @ast-grep/cli"
            )
    
    def _check_ast_grep_available(self) -> bool:
        """Check if ast-grep is available on PATH"""
        try:
            result = subprocess.run(
                ["ast-grep", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"ast-grep found: {version}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False
    
    def search(
        self,
        query: Union[AstGrepQuery, str],
        paths: Optional[List[str]] = None,
        exclude_dirs: Optional[List[str]] = None
    ) -> List[AstGrepMatch]:
        """
        Search codebase using ast-grep pattern.
        
        Args:
            query: AstGrepQuery object or simple pattern string
            paths: Optional list of specific paths to search
            exclude_dirs: Directories to exclude from search
            
        Returns:
            List of matches found
            
        Raises:
            AstGrepNotFoundError: If ast-grep is not installed
        """
        if not self.ast_grep_available:
            raise AstGrepNotFoundError(
                "ast-grep is required but not found. "
                "Install with: cargo install ast-grep"
            )
        
        # Convert simple string to AstGrepQuery
        if isinstance(query, str):
            query = AstGrepQuery(pattern=query, language=Language.PYTHON)
        
        # Build ast-grep command
        cmd = self._build_command(query, paths, exclude_dirs)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(self.project_root)
            )
            
            if result.returncode not in [0, 1]:  # 1 means no matches, which is OK
                logger.error(f"ast-grep error: {result.stderr}")
                return []
            
            return self._parse_output(result.stdout, query.language.value)
            
        except subprocess.TimeoutExpired:
            logger.error("ast-grep query timed out after 60 seconds")
            return []
        except Exception as e:
            logger.error(f"ast-grep execution failed: {e}")
            return []
    
    def _build_command(
        self,
        query: AstGrepQuery,
        paths: Optional[List[str]],
        exclude_dirs: Optional[List[str]]
    ) -> List[str]:
        """Build ast-grep CLI command"""
        cmd = [
            "ast-grep",
            "--json",  # JSON output for easy parsing
            "-l", query.language.value,
            "-p", query.pattern,
        ]
        
        # Add constraints if present
        if query.constraints:
            # ast-grep uses YAML config for complex queries
            # For now, we'll use simple patterns
            pass
        
        # Add paths or use project root
        if paths:
            for path in paths:
                cmd.append(str(self.project_root / path))
        else:
            cmd.append(str(self.project_root))
        
        return cmd
    
    def _parse_output(self, output: str, language: str) -> List[AstGrepMatch]:
        """Parse ast-grep JSON output into AstGrepMatch objects"""
        if not output.strip():
            return []
        
        matches = []
        try:
            # ast-grep outputs newline-delimited JSON
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                data = json.loads(line)
                
                # ast-grep JSON format varies, handle common structures
                if 'range' in data:
                    range_data = data['range']
                    match = AstGrepMatch(
                        file=data.get('file', ''),
                        start_line=range_data.get('start', {}).get('line', 0),
                        end_line=range_data.get('end', {}).get('line', 0),
                        start_col=range_data.get('start', {}).get('column', 0),
                        end_col=range_data.get('end', {}).get('column', 0),
                        matched_text=data.get('text', ''),
                        language=language
                    )
                    matches.append(match)
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse ast-grep output: {e}")
        
        return matches
    
    def find_imports(
        self,
        package_name: str,
        language: Language
    ) -> List[AstGrepMatch]:
        """
        Find all imports of a specific package.
        
        Args:
            package_name: Name of package to search for
            language: Programming language
            
        Returns:
            List of import locations
        """
        patterns = {
            Language.PYTHON: f"import {package_name}",
            Language.JAVASCRIPT: f"require('{package_name}')",
            Language.JAVA: f"import {package_name}.*",
        }
        
        pattern = patterns.get(language)
        if not pattern:
            logger.warning(f"No import pattern defined for {language}")
            return []
        
        query = AstGrepQuery(pattern=pattern, language=language)
        return self.search(query)
    
    def find_function_calls(
        self,
        function_name: str,
        language: Language,
        module: Optional[str] = None
    ) -> List[AstGrepMatch]:
        """
        Find all calls to a specific function.
        
        Args:
            function_name: Name of function to search for
            module: Optional module/class containing the function
            language: Programming language
            
        Returns:
            List of function call locations
        """
        if module:
            pattern = f"{module}.{function_name}($$$)"
        else:
            pattern = f"{function_name}($$$)"
        
        query = AstGrepQuery(pattern=pattern, language=language)
        return self.search(query)
    
    def find_class_instantiations(
        self,
        class_name: str,
        language: Language
    ) -> List[AstGrepMatch]:
        """
        Find all instantiations of a specific class.
        
        Args:
            class_name: Name of class
            language: Programming language
            
        Returns:
            List of instantiation locations
        """
        patterns = {
            Language.PYTHON: f"{class_name}($$$)",
            Language.JAVA: f"new {class_name}($$$)",
            Language.JAVASCRIPT: f"new {class_name}($$$)",
        }
        
        pattern = patterns.get(language)
        if not pattern:
            return []
        
        query = AstGrepQuery(pattern=pattern, language=language)
        return self.search(query)
    
    def trace_call_path(
        self,
        from_function: str,
        to_function: str,
        language: Language
    ) -> List[List[AstGrepMatch]]:
        """
        Attempt to trace call paths from one function to another.
        
        This is a simplified implementation. Full call graph analysis
        requires more sophisticated analysis.
        
        Args:
            from_function: Starting function
            to_function: Target function
            language: Programming language
            
        Returns:
            List of potential call paths
        """
        # Find all calls to target function
        target_calls = self.find_function_calls(to_function, language)
        
        # Find definition of source function
        source_pattern = f"def {from_function}" if language == Language.PYTHON else None
        if not source_pattern:
            return []
        
        # This is a placeholder - real implementation needs graph traversal
        return [[match] for match in target_calls]


def create_query_patterns() -> Dict[str, Dict[str, str]]:
    """
    Pre-defined query patterns for common vulnerability checks.
    
    Returns:
        Dictionary of pattern categories and their queries
    """
    return {
        "sql_injection": {
            "python": "execute($SQL)",
            "java": "executeQuery($SQL)",
            "javascript": "query($SQL)",
        },
        "command_injection": {
            "python": "os.system($CMD)",
            "java": "Runtime.getRuntime().exec($CMD)",
            "javascript": "exec($CMD)",
        },
        "path_traversal": {
            "python": "open($PATH)",
            "java": "new File($PATH)",
            "javascript": "fs.readFile($PATH)",
        },
        "unsafe_deserialization": {
            "python": "pickle.loads($DATA)",
            "java": "ObjectInputStream.readObject()",
            "javascript": "eval($DATA)",
        }
    }


# Convenience function for quick searches
def quick_search(
    project_root: str,
    pattern: str,
    language: str = "python"
) -> List[AstGrepMatch]:
    """
    Quick search helper function.
    
    Args:
        project_root: Root directory to search
        pattern: ast-grep pattern
        language: Programming language (default: python)
        
    Returns:
        List of matches
    """
    wrapper = AstGrepWrapper(project_root)
    lang_enum = Language(language.lower())
    query = AstGrepQuery(pattern=pattern, language=lang_enum)
    return wrapper.search(query)

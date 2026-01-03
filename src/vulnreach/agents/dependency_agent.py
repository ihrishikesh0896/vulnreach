"""
Dependency Agent - Analyzes project dependencies and dependency tree
"""

import json
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path
import re


class DependencyAgent:
    """
    Agent specialized in dependency analysis
    Extracts and analyzes dependency trees from various package managers
    """
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.package_manager = self._detect_package_manager()
    
    def _detect_package_manager(self) -> str:
        """Detect package manager based on project files"""
        if (self.root_path / "requirements.txt").exists() or \
           (self.root_path / "pyproject.toml").exists():
            return "pip"
        elif (self.root_path / "package.json").exists():
            return "npm"
        elif (self.root_path / "pom.xml").exists():
            return "maven"
        elif (self.root_path / "build.gradle").exists():
            return "gradle"
        elif (self.root_path / "Gemfile").exists():
            return "bundler"
        return "unknown"
    
    def analyze(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis entry point
        
        Task format:
        {
            'type': 'get_dependencies' | 'get_tree' | 'check_package',
            'params': {...}
        }
        """
        task_type = task.get('type')
        params = task.get('params', {})
        
        if task_type == 'get_dependencies':
            return self._get_dependencies(params)
        elif task_type == 'get_tree':
            return self._get_dependency_tree(params)
        elif task_type == 'check_package':
            return self._check_package(params)
        else:
            return {'error': f'Unknown task type: {task_type}'}
    
    def _get_dependencies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get flat list of all dependencies"""
        if self.package_manager == "pip":
            return self._get_pip_dependencies()
        elif self.package_manager == "npm":
            return self._get_npm_dependencies()
        else:
            return {
                'error': f'Package manager {self.package_manager} not supported yet'
            }
    
    def _get_pip_dependencies(self) -> Dict[str, Any]:
        """Get Python dependencies using pipdeptree"""
        try:
            # Try pipdeptree first (more detailed)
            result = subprocess.run(
                ['pipdeptree', '--json'],
                capture_output=True,
                text=True,
                check=True,
                cwd=str(self.root_path)
            )
            
            if result.stdout:
                tree_data = json.loads(result.stdout)
                deps = {}
                
                for pkg in tree_data:
                    name = pkg.get('package', {}).get('key', '')
                    version = pkg.get('package', {}).get('installed_version', '')
                    dependencies = [
                        d.get('key', '') for d in pkg.get('dependencies', [])
                    ]
                    
                    if name:
                        deps[name] = {
                            'version': version,
                            'dependencies': dependencies
                        }
                
                return {
                    'task': 'get_dependencies',
                    'package_manager': 'pip',
                    'count': len(deps),
                    'dependencies': deps
                }
        except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
            pass
        
        # Fallback to pip list
        try:
            result = subprocess.run(
                ['pip', 'list', '--format=json'],
                capture_output=True,
                text=True,
                check=True,
                cwd=str(self.root_path)
            )
            
            if result.stdout:
                pip_list = json.loads(result.stdout)
                deps = {}
                
                for pkg in pip_list:
                    name = pkg.get('name', '')
                    version = pkg.get('version', '')
                    if name:
                        deps[name] = {
                            'version': version,
                            'dependencies': []
                        }
                
                return {
                    'task': 'get_dependencies',
                    'package_manager': 'pip',
                    'count': len(deps),
                    'dependencies': deps,
                    'note': 'Using pip list (no dependency tree)'
                }
        except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
            return {'error': 'Failed to get pip dependencies'}
    
    def _get_npm_dependencies(self) -> Dict[str, Any]:
        """Get Node.js dependencies using npm"""
        try:
            result = subprocess.run(
                ['npm', 'list', '--json', '--all'],
                capture_output=True,
                text=True,
                cwd=str(self.root_path)
            )
            
            if result.stdout:
                npm_data = json.loads(result.stdout)
                deps = self._flatten_npm_tree(npm_data.get('dependencies', {}))
                
                return {
                    'task': 'get_dependencies',
                    'package_manager': 'npm',
                    'count': len(deps),
                    'dependencies': deps
                }
        except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
            return {'error': f'Failed to get npm dependencies: {str(e)}'}
    
    def _flatten_npm_tree(self, tree: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten npm dependency tree"""
        deps = {}
        
        for name, info in tree.items():
            version = info.get('version', '')
            sub_deps = list(info.get('dependencies', {}).keys())
            
            deps[name] = {
                'version': version,
                'dependencies': sub_deps
            }
            
            # Recursively flatten
            if info.get('dependencies'):
                nested = self._flatten_npm_tree(info['dependencies'])
                deps.update(nested)
        
        return deps
    
    def _get_dependency_tree(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get full dependency tree with hierarchy"""
        if self.package_manager == "pip":
            try:
                result = subprocess.run(
                    ['pipdeptree', '--json'],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=str(self.root_path)
                )
                
                if result.stdout:
                    tree_data = json.loads(result.stdout)
                    return {
                        'task': 'get_tree',
                        'package_manager': 'pip',
                        'tree': tree_data
                    }
            except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
                return {'error': 'Failed to get dependency tree'}
        
        return {'error': f'Tree not supported for {self.package_manager}'}
    
    def _check_package(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check if a specific package is installed"""
        package_name = params.get('package_name')
        
        if not package_name:
            return {'error': 'package_name required'}
        
        deps = self._get_dependencies({})
        
        if 'error' in deps:
            return deps
        
        dependencies = deps.get('dependencies', {})
        package_info = dependencies.get(package_name)
        
        return {
            'task': 'check_package',
            'package_name': package_name,
            'installed': package_info is not None,
            'version': package_info.get('version') if package_info else None,
            'dependencies': package_info.get('dependencies', []) if package_info else []
        }
    
    def get_direct_dependencies(self) -> List[str]:
        """Get only direct dependencies (from requirements.txt, package.json, etc)"""
        if self.package_manager == "pip":
            return self._get_direct_pip_dependencies()
        elif self.package_manager == "npm":
            return self._get_direct_npm_dependencies()
        return []
    
    def _get_direct_pip_dependencies(self) -> List[str]:
        """Parse requirements.txt or pyproject.toml for direct dependencies"""
        deps = []
        
        # Try requirements.txt
        req_file = self.root_path / "requirements.txt"
        if req_file.exists():
            with open(req_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract package name (before version specifier)
                        match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                        if match:
                            deps.append(match.group(1))
        
        # Try pyproject.toml
        pyproject = self.root_path / "pyproject.toml"
        if pyproject.exists() and not deps:
            try:
                import tomli
                with open(pyproject, 'rb') as f:
                    data = tomli.load(f)
                    project_deps = data.get('project', {}).get('dependencies', [])
                    for dep in project_deps:
                        match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                        if match:
                            deps.append(match.group(1))
            except:
                pass
        
        return deps
    
    def _get_direct_npm_dependencies(self) -> List[str]:
        """Parse package.json for direct dependencies"""
        package_json = self.root_path / "package.json"
        
        if not package_json.exists():
            return []
        
        try:
            with open(package_json, 'r') as f:
                data = json.load(f)
                deps = list(data.get('dependencies', {}).keys())
                dev_deps = list(data.get('devDependencies', {}).keys())
                return deps + dev_deps
        except (json.JSONDecodeError, IOError):
            return []
    
    def get_capabilities(self) -> List[str]:
        """Return list of agent capabilities"""
        return [
            'get_dependencies',
            'get_dependency_tree',
            'check_package',
            'get_direct_dependencies',
            'detect_package_manager'
        ]

#!/usr/bin/env python3
"""
Dependency Tree Analyzer

Utilities to detect transitive/indirect dependencies across different package managers.
"""

import os
import json
import subprocess
from pathlib import Path
from typing import Dict, Set, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class DependencyInfo:
    """Information about a dependency"""
    name: str
    version: str
    is_direct: bool  # True if directly declared, False if transitive
    depth: int  # 0 for direct, 1+ for transitive
    parent_dependencies: List[str]  # List of packages that depend on this


class DependencyTreeAnalyzer:
    """Base class for analyzing dependency trees"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)

    def get_dependency_info(self, package_name: str) -> Optional[DependencyInfo]:
        """Get information about a specific dependency"""
        raise NotImplementedError("Subclasses must implement this method")

    def get_all_dependencies(self) -> Dict[str, DependencyInfo]:
        """Get information about all dependencies"""
        raise NotImplementedError("Subclasses must implement this method")


class PythonDependencyTreeAnalyzer(DependencyTreeAnalyzer):
    """Analyze Python dependency trees using pip and requirements files"""

    def get_declared_dependencies(self) -> Set[str]:
        """Get directly declared dependencies from requirements files"""
        declared = set()

        # Check common requirement files
        req_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements/base.txt',
            'requirements/production.txt',
            'requirements/dev.txt'
        ]

        for req_file in req_files:
            req_path = self.project_root / req_file
            if req_path.exists():
                try:
                    with open(req_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#') and not line.startswith('-'):
                                # Extract package name (handle pip install options)
                                if '==' in line or '>=' in line or '<=' in line or '~=' in line:
                                    pkg_name = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].strip()
                                    declared.add(self._normalize_package_name(pkg_name))
                except Exception as e:
                    print(f"Warning: Could not parse {req_path}: {e}")

        # Check setup.py
        setup_py = self.project_root / 'setup.py'
        if setup_py.exists():
            try:
                with open(setup_py, 'r') as f:
                    content = f.read()
                    # Simple regex to find install_requires
                    import re
                    matches = re.findall(r'["\']([a-zA-Z0-9_-]+)["\']', content)
                    for match in matches:
                        declared.add(self._normalize_package_name(match))
            except Exception:
                pass

        # Check pyproject.toml
        pyproject = self.project_root / 'pyproject.toml'
        if pyproject.exists():
            try:
                with open(pyproject, 'r') as f:
                    content = f.read()
                    import re
                    # Find dependencies in [tool.poetry.dependencies] or [project.dependencies]
                    matches = re.findall(r'([a-zA-Z0-9_-]+)\s*=\s*["\']', content)
                    for match in matches:
                        if match.lower() not in ('python', 'version', 'description', 'authors'):
                            declared.add(self._normalize_package_name(match))
            except Exception:
                pass

        return declared

    def get_dependency_tree_from_pip(self) -> Dict[str, List[str]]:
        """Get dependency tree using pip show"""
        dependency_tree = {}

        try:
            # Try to use pipdeptree if available
            if self._has_pipdeptree():
                result = subprocess.run(
                    ['pipdeptree', '--json'],
                    capture_output=True,
                    text=True,
                    cwd=self.project_root
                )

                if result.returncode == 0:
                    tree_data = json.loads(result.stdout)
                    for package in tree_data:
                        pkg_name = self._normalize_package_name(package['package']['package_name'])
                        dependencies = []
                        for dep in package.get('dependencies', []):
                            dependencies.append(self._normalize_package_name(dep['package_name']))
                        dependency_tree[pkg_name] = dependencies

                    return dependency_tree
        except Exception as e:
            print(f"Warning: Could not get pip dependency tree: {e}")

        return dependency_tree

    def _has_pipdeptree(self) -> bool:
        """Check if pipdeptree is installed"""
        try:
            result = subprocess.run(['pipdeptree', '--version'],
                                  capture_output=True,
                                  stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def get_dependency_info(self, package_name: str) -> Optional[DependencyInfo]:
        """Get information about a specific Python package"""
        normalized_name = self._normalize_package_name(package_name)
        declared_deps = self.get_declared_dependencies()

        is_direct = normalized_name in declared_deps

        # Try to find parent dependencies
        parent_deps = []
        dependency_tree = self.get_dependency_tree_from_pip()

        for parent, children in dependency_tree.items():
            if normalized_name in children:
                parent_deps.append(parent)

        depth = 0 if is_direct else (1 if parent_deps else 1)

        return DependencyInfo(
            name=package_name,
            version="unknown",  # Would need pip show to get this
            is_direct=is_direct,
            depth=depth,
            parent_dependencies=parent_deps
        )

    def get_all_dependencies(self) -> Dict[str, DependencyInfo]:
        """Get information about all dependencies"""
        all_deps = {}
        declared = self.get_declared_dependencies()
        dep_tree = self.get_dependency_tree_from_pip()

        # First add all declared dependencies
        for pkg in declared:
            all_deps[pkg] = DependencyInfo(
                name=pkg,
                version="unknown",
                is_direct=True,
                depth=0,
                parent_dependencies=[]
            )

        # Then add transitive dependencies
        for parent, children in dep_tree.items():
            for child in children:
                if child not in all_deps:
                    all_deps[child] = DependencyInfo(
                        name=child,
                        version="unknown",
                        is_direct=False,
                        depth=1,
                        parent_dependencies=[parent]
                    )
                else:
                    # Already exists, just add parent
                    if parent not in all_deps[child].parent_dependencies:
                        all_deps[child].parent_dependencies.append(parent)

        return all_deps

    def _normalize_package_name(self, package_name: str) -> str:
        """Normalize Python package name"""
        return package_name.lower().replace('_', '-').strip()


class JavaScriptDependencyTreeAnalyzer(DependencyTreeAnalyzer):
    """Analyze JavaScript/TypeScript dependency trees using package.json"""

    def get_declared_dependencies(self) -> Set[str]:
        """Get directly declared dependencies from package.json"""
        declared = set()

        package_json = self.project_root / 'package.json'
        if not package_json.exists():
            return declared

        try:
            with open(package_json, 'r') as f:
                data = json.load(f)

                # Get dependencies
                for dep in data.get('dependencies', {}).keys():
                    declared.add(dep)

                # Also check devDependencies if you want to include them
                for dep in data.get('devDependencies', {}).keys():
                    declared.add(dep)

        except Exception as e:
            print(f"Warning: Could not parse package.json: {e}")

        return declared

    def get_dependency_tree_from_npm(self) -> Dict[str, List[str]]:
        """Get dependency tree using npm ls"""
        dependency_tree = {}

        try:
            result = subprocess.run(
                ['npm', 'ls', '--json', '--all'],
                capture_output=True,
                text=True,
                cwd=self.project_root
            )

            if result.stdout:
                tree_data = json.loads(result.stdout)
                self._parse_npm_tree(tree_data, dependency_tree)

        except Exception as e:
            print(f"Warning: Could not get npm dependency tree: {e}")

        return dependency_tree

    def _parse_npm_tree(self, node: Dict, tree: Dict[str, List[str]], parent: str = None):
        """Recursively parse npm dependency tree"""
        if 'dependencies' in node:
            for dep_name, dep_data in node['dependencies'].items():
                if parent:
                    if parent not in tree:
                        tree[parent] = []
                    if dep_name not in tree[parent]:
                        tree[parent].append(dep_name)

                # Recurse
                self._parse_npm_tree(dep_data, tree, dep_name)

    def get_dependency_info(self, package_name: str) -> Optional[DependencyInfo]:
        """Get information about a specific npm package"""
        declared_deps = self.get_declared_dependencies()
        is_direct = package_name in declared_deps

        parent_deps = []
        dependency_tree = self.get_dependency_tree_from_npm()

        for parent, children in dependency_tree.items():
            if package_name in children:
                parent_deps.append(parent)

        depth = 0 if is_direct else (1 if parent_deps else 1)

        return DependencyInfo(
            name=package_name,
            version="unknown",
            is_direct=is_direct,
            depth=depth,
            parent_dependencies=parent_deps
        )


class JavaDependencyTreeAnalyzer(DependencyTreeAnalyzer):
    """Analyze Java dependency trees using Maven/Gradle"""

    def get_declared_dependencies(self) -> Set[str]:
        """Get directly declared dependencies from pom.xml or build.gradle"""
        declared = set()

        # Check Maven pom.xml
        pom_xml = self.project_root / 'pom.xml'
        if pom_xml.exists():
            try:
                with open(pom_xml, 'r') as f:
                    content = f.read()
                    # Simple regex to find dependencies
                    import re
                    # Find groupId:artifactId patterns
                    matches = re.findall(r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>', content)
                    for group_id, artifact_id in matches:
                        declared.add(f"{group_id}:{artifact_id}")
            except Exception:
                pass

        # Check Gradle build.gradle
        build_gradle = self.project_root / 'build.gradle'
        if build_gradle.exists():
            try:
                with open(build_gradle, 'r') as f:
                    content = f.read()
                    import re
                    # Find implementation/compile dependencies
                    matches = re.findall(r'["\']([^:"\']+):([^:"\']+):', content)
                    for group_id, artifact_id in matches:
                        declared.add(f"{group_id}:{artifact_id}")
            except Exception:
                pass

        return declared

    def get_dependency_info(self, package_name: str) -> Optional[DependencyInfo]:
        """Get information about a specific Java package"""
        declared_deps = self.get_declared_dependencies()

        # Java packages are in format groupId:artifactId
        is_direct = package_name in declared_deps

        return DependencyInfo(
            name=package_name,
            version="unknown",
            is_direct=is_direct,
            depth=0 if is_direct else 1,
            parent_dependencies=[]
        )


class PHPDependencyTreeAnalyzer(DependencyTreeAnalyzer):
    """Analyze PHP dependency trees using composer.json"""

    def get_declared_dependencies(self) -> Set[str]:
        """Get directly declared dependencies from composer.json"""
        declared = set()

        composer_json = self.project_root / 'composer.json'
        if not composer_json.exists():
            return declared

        try:
            with open(composer_json, 'r') as f:
                data = json.load(f)

                # Get dependencies
                for dep in data.get('require', {}).keys():
                    # Skip php itself
                    if dep.lower() != 'php':
                        declared.add(dep.lower())

                # Also check require-dev if you want to include them
                for dep in data.get('require-dev', {}).keys():
                    if dep.lower() != 'php':
                        declared.add(dep.lower())

        except Exception as e:
            print(f"Warning: Could not parse composer.json: {e}")

        return declared

    def get_dependency_tree_from_composer(self) -> Dict[str, List[str]]:
        """Get dependency tree using composer show"""
        dependency_tree = {}

        try:
            result = subprocess.run(
                ['composer', 'show', '--tree', '--format=json'],
                capture_output=True,
                text=True,
                cwd=self.project_root
            )

            if result.stdout:
                # Parse composer output
                tree_data = json.loads(result.stdout)
                # Process tree data (composer format may vary)
                self._parse_composer_tree(tree_data, dependency_tree)

        except Exception as e:
            print(f"Warning: Could not get composer dependency tree: {e}")

        return dependency_tree

    def _parse_composer_tree(self, node: Dict, tree: Dict[str, List[str]], parent: str = None):
        """Parse composer dependency tree"""
        if isinstance(node, dict):
            if 'requires' in node:
                for dep in node['requires']:
                    if parent:
                        if parent not in tree:
                            tree[parent] = []
                        tree[parent].append(dep.lower())

    def get_dependency_info(self, package_name: str) -> Optional[DependencyInfo]:
        """Get information about a specific PHP package"""
        declared_deps = self.get_declared_dependencies()
        normalized_name = package_name.lower()
        is_direct = normalized_name in declared_deps

        parent_deps = []
        dependency_tree = self.get_dependency_tree_from_composer()

        for parent, children in dependency_tree.items():
            if normalized_name in children:
                parent_deps.append(parent)

        depth = 0 if is_direct else (1 if parent_deps else 1)

        return DependencyInfo(
            name=package_name,
            version="unknown",
            is_direct=is_direct,
            depth=depth,
            parent_dependencies=parent_deps
        )

    def get_all_dependencies(self) -> Dict[str, DependencyInfo]:
        """Get information about all dependencies"""
        all_deps = {}
        declared = self.get_declared_dependencies()
        dep_tree = self.get_dependency_tree_from_composer()

        # Add declared dependencies
        for pkg in declared:
            all_deps[pkg] = DependencyInfo(
                name=pkg,
                version="unknown",
                is_direct=True,
                depth=0,
                parent_dependencies=[]
            )

        # Add transitive dependencies
        for parent, children in dep_tree.items():
            for child in children:
                if child not in all_deps:
                    all_deps[child] = DependencyInfo(
                        name=child,
                        version="unknown",
                        is_direct=False,
                        depth=1,
                        parent_dependencies=[parent]
                    )
                else:
                    if parent not in all_deps[child].parent_dependencies:
                        all_deps[child].parent_dependencies.append(parent)

        return all_deps


class GoDependencyTreeAnalyzer(DependencyTreeAnalyzer):
    """Analyze Go dependency trees using go.mod"""

    def get_declared_dependencies(self) -> Set[str]:
        """Get directly declared dependencies from go.mod"""
        declared = set()

        go_mod = self.project_root / 'go.mod'
        if not go_mod.exists():
            return declared

        try:
            with open(go_mod, 'r') as f:
                in_require_block = False
                for line in f:
                    line = line.strip()

                    # Start of require block
                    if line.startswith('require ('):
                        in_require_block = True
                        continue

                    # End of require block
                    if in_require_block and line == ')':
                        in_require_block = False
                        continue

                    # Single-line require
                    if line.startswith('require ') and '(' not in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            declared.add(parts[1])

                    # Multi-line require block
                    elif in_require_block and line:
                        parts = line.split()
                        if len(parts) >= 1 and not line.startswith('//'):
                            declared.add(parts[0])

        except Exception as e:
            print(f"Warning: Could not parse go.mod: {e}")

        return declared

    def get_dependency_tree_from_go(self) -> Dict[str, List[str]]:
        """Get dependency tree using go mod graph"""
        dependency_tree = {}

        try:
            result = subprocess.run(
                ['go', 'mod', 'graph'],
                capture_output=True,
                text=True,
                cwd=self.project_root
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if ' ' in line:
                        parent, child = line.strip().split(' ', 1)
                        # Strip version info
                        parent_pkg = parent.split('@')[0] if '@' in parent else parent
                        child_pkg = child.split('@')[0] if '@' in child else child

                        if parent_pkg not in dependency_tree:
                            dependency_tree[parent_pkg] = []
                        dependency_tree[parent_pkg].append(child_pkg)

        except Exception as e:
            print(f"Warning: Could not get go dependency tree: {e}")

        return dependency_tree

    def get_dependency_info(self, package_name: str) -> Optional[DependencyInfo]:
        """Get information about a specific Go package"""
        declared_deps = self.get_declared_dependencies()
        is_direct = package_name in declared_deps

        parent_deps = []
        dependency_tree = self.get_dependency_tree_from_go()

        for parent, children in dependency_tree.items():
            if package_name in children:
                parent_deps.append(parent)

        depth = 0 if is_direct else (1 if parent_deps else 1)

        return DependencyInfo(
            name=package_name,
            version="unknown",
            is_direct=is_direct,
            depth=depth,
            parent_dependencies=parent_deps
        )

    def get_all_dependencies(self) -> Dict[str, DependencyInfo]:
        """Get information about all dependencies"""
        all_deps = {}
        declared = self.get_declared_dependencies()
        dep_tree = self.get_dependency_tree_from_go()

        # Add declared dependencies
        for pkg in declared:
            all_deps[pkg] = DependencyInfo(
                name=pkg,
                version="unknown",
                is_direct=True,
                depth=0,
                parent_dependencies=[]
            )

        # Add transitive dependencies
        for parent, children in dep_tree.items():
            for child in children:
                if child not in all_deps:
                    all_deps[child] = DependencyInfo(
                        name=child,
                        version="unknown",
                        is_direct=False,
                        depth=1,
                        parent_dependencies=[parent]
                    )
                else:
                    if parent not in all_deps[child].parent_dependencies:
                        all_deps[child].parent_dependencies.append(parent)

        return all_deps


class CSharpDependencyTreeAnalyzer(DependencyTreeAnalyzer):
    """Analyze C# dependency trees using .csproj"""

    def get_declared_dependencies(self) -> Set[str]:
        """Get directly declared dependencies from .csproj files"""
        declared = set()

        # Find all .csproj files
        csproj_files = list(self.project_root.rglob("*.csproj"))

        for csproj_file in csproj_files:
            try:
                with open(csproj_file, 'r') as f:
                    content = f.read()
                    # Simple regex to find PackageReference
                    import re
                    matches = re.findall(r'<PackageReference\s+Include="([^"]+)"', content)
                    for match in matches:
                        declared.add(match.lower())
            except Exception as e:
                print(f"Warning: Could not parse {csproj_file}: {e}")

        # Also check packages.config (older format)
        packages_config = self.project_root / 'packages.config'
        if packages_config.exists():
            try:
                with open(packages_config, 'r') as f:
                    content = f.read()
                    import re
                    matches = re.findall(r'<package\s+id="([^"]+)"', content, re.IGNORECASE)
                    for match in matches:
                        declared.add(match.lower())
            except Exception:
                pass

        return declared

    def get_dependency_tree_from_dotnet(self) -> Dict[str, List[str]]:
        """Get dependency tree using dotnet list package"""
        dependency_tree = {}

        try:
            result = subprocess.run(
                ['dotnet', 'list', 'package', '--include-transitive'],
                capture_output=True,
                text=True,
                cwd=self.project_root
            )

            if result.returncode == 0:
                # Parse dotnet output
                # Format varies, basic parsing here
                current_parent = None
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if '>' in line and not line.startswith('Project'):
                        # This might be a dependency line
                        parts = line.split()
                        if len(parts) >= 2:
                            pkg_name = parts[1].lower()
                            if current_parent:
                                if current_parent not in dependency_tree:
                                    dependency_tree[current_parent] = []
                                dependency_tree[current_parent].append(pkg_name)

        except Exception as e:
            print(f"Warning: Could not get dotnet dependency tree: {e}")

        return dependency_tree

    def get_dependency_info(self, package_name: str) -> Optional[DependencyInfo]:
        """Get information about a specific C# package"""
        declared_deps = self.get_declared_dependencies()
        normalized_name = package_name.lower()
        is_direct = normalized_name in declared_deps

        parent_deps = []
        dependency_tree = self.get_dependency_tree_from_dotnet()

        for parent, children in dependency_tree.items():
            if normalized_name in children:
                parent_deps.append(parent)

        depth = 0 if is_direct else (1 if parent_deps else 1)

        return DependencyInfo(
            name=package_name,
            version="unknown",
            is_direct=is_direct,
            depth=depth,
            parent_dependencies=parent_deps
        )

    def get_all_dependencies(self) -> Dict[str, DependencyInfo]:
        """Get information about all dependencies"""
        all_deps = {}
        declared = self.get_declared_dependencies()
        dep_tree = self.get_dependency_tree_from_dotnet()

        # Add declared dependencies
        for pkg in declared:
            all_deps[pkg] = DependencyInfo(
                name=pkg,
                version="unknown",
                is_direct=True,
                depth=0,
                parent_dependencies=[]
            )

        # Add transitive dependencies
        for parent, children in dep_tree.items():
            for child in children:
                if child not in all_deps:
                    all_deps[child] = DependencyInfo(
                        name=child,
                        version="unknown",
                        is_direct=False,
                        depth=1,
                        parent_dependencies=[parent]
                    )
                else:
                    if parent not in all_deps[child].parent_dependencies:
                        all_deps[child].parent_dependencies.append(parent)

        return all_deps


def get_dependency_analyzer(project_root: str, language: str) -> Optional[DependencyTreeAnalyzer]:
    """Factory function to get the appropriate dependency analyzer"""
    language_lower = language.lower()

    if language_lower == 'python':
        return PythonDependencyTreeAnalyzer(project_root)
    elif language_lower in ('javascript', 'typescript', 'js', 'ts'):
        return JavaScriptDependencyTreeAnalyzer(project_root)
    elif language_lower == 'java':
        return JavaDependencyTreeAnalyzer(project_root)
    elif language_lower == 'php':
        return PHPDependencyTreeAnalyzer(project_root)
    elif language_lower == 'go':
        return GoDependencyTreeAnalyzer(project_root)
    elif language_lower in ('csharp', 'c#', 'cs', 'dotnet'):
        return CSharpDependencyTreeAnalyzer(project_root)
    else:
        return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python dependency_tree_analyzer.py <project_root> <language> [package_name]")
        print("\nSupported Languages:")
        print("  - python")
        print("  - javascript (or typescript, js, ts)")
        print("  - java")
        print("  - php")
        print("  - go")
        print("  - csharp (or c#, cs, dotnet)")
        print("\nExamples:")
        print("  python dependency_tree_analyzer.py ./my-python-app python")
        print("  python dependency_tree_analyzer.py ./my-python-app python requests")
        print("  python dependency_tree_analyzer.py ./my-php-app php symfony/console")
        print("  python dependency_tree_analyzer.py ./my-go-app go github.com/gorilla/mux")
        sys.exit(1)

    project_root = sys.argv[1]
    language = sys.argv[2]
    package_name = sys.argv[3] if len(sys.argv) > 3 else None

    analyzer = get_dependency_analyzer(project_root, language)
    if not analyzer:
        print(f"Error: Unsupported language '{language}'")
        sys.exit(1)

    if package_name:
        # Analyze specific package
        info = analyzer.get_dependency_info(package_name)
        if info:
            print(f"\n📦 Package: {info.name}")
            print(f"   Type: {'Direct (declared)' if info.is_direct else 'Transitive (indirect)'}")
            print(f"   Depth: {info.depth}")
            if info.parent_dependencies:
                print(f"   Required by: {', '.join(info.parent_dependencies)}")
        else:
            print(f"Package '{package_name}' not found")
    else:
        # Analyze all dependencies
        all_deps = analyzer.get_all_dependencies()
        direct = [d for d in all_deps.values() if d.is_direct]
        transitive = [d for d in all_deps.values() if not d.is_direct]

        print(f"\n📊 Dependency Analysis for {project_root}")
        print(f"   Total dependencies: {len(all_deps)}")
        print(f"   Direct dependencies: {len(direct)}")
        print(f"   Transitive dependencies: {len(transitive)}")

        if transitive:
            print(f"\n🔗 Transitive Dependencies:")
            for dep in transitive[:10]:  # Show first 10
                parents = ', '.join(dep.parent_dependencies) if dep.parent_dependencies else 'unknown'
                print(f"   • {dep.name} (required by: {parents})")


"""Container Detection Module

Detects if an application is containerized and can be run for dynamic analysis.
Checks for:
- Dockerfile
- docker-compose.yml
- Run instructions in README
- Container orchestration configs
"""

import os
import re
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass


@dataclass
class ContainerInfo:
    """Information about container setup"""
    is_containerized: bool
    has_dockerfile: bool = False
    has_compose: bool = False
    has_run_instructions: bool = False
    dockerfile_path: Optional[str] = None
    compose_path: Optional[str] = None
    run_command: Optional[str] = None
    entrypoint: Optional[str] = None
    readme_path: Optional[str] = None


class ContainerDetector:
    """Detects if application is containerized and can be run"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
    
    def detect(self) -> ContainerInfo:
        """
        Detect container setup
        
        Returns:
            ContainerInfo with detection results
        """
        info = ContainerInfo(is_containerized=False)
        
        # Check for Dockerfile
        dockerfile_path = self._find_dockerfile()
        if dockerfile_path:
            info.has_dockerfile = True
            info.dockerfile_path = str(dockerfile_path)
            info.is_containerized = True
        
        # Check for docker-compose
        compose_path = self._find_compose_file()
        if compose_path:
            info.has_compose = True
            info.compose_path = str(compose_path)
            info.is_containerized = True
        
        # Parse run instructions
        if info.is_containerized:
            run_cmd, entrypoint = self._parse_run_instructions(info)
            info.run_command = run_cmd
            info.entrypoint = entrypoint
            info.has_run_instructions = bool(run_cmd)
        
        return info
    
    def _find_dockerfile(self) -> Optional[Path]:
        """Find Dockerfile in project"""
        dockerfile_names = ['Dockerfile', 'dockerfile', 'Dockerfile.dev', 'Dockerfile.prod']
        
        for name in dockerfile_names:
            dockerfile = self.project_root / name
            if dockerfile.exists():
                return dockerfile
        
        return None
    
    def _find_compose_file(self) -> Optional[Path]:
        """Find docker-compose file"""
        compose_names = [
            'docker-compose.yml',
            'docker-compose.yaml',
            'docker-compose.dev.yml',
            'docker-compose.prod.yml',
            'compose.yml',
            'compose.yaml'
        ]
        
        for name in compose_names:
            compose_file = self.project_root / name
            if compose_file.exists():
                return compose_file
        
        return None
    
    def _parse_run_instructions(self, info: ContainerInfo) -> tuple[Optional[str], Optional[str]]:
        """
        Parse run instructions from various sources
        
        Returns:
            (run_command, entrypoint)
        """
        # Try docker-compose first (easiest)
        if info.has_compose:
            cmd, entry = self._parse_compose(info.compose_path)
            if cmd:
                return cmd, entry
        
        # Try Dockerfile
        if info.has_dockerfile:
            cmd, entry = self._parse_dockerfile(info.dockerfile_path)
            if cmd or entry:
                # If we found entrypoint but no full command, construct one
                if not cmd and entry:
                    cmd = "docker build -t app . && docker run app"
                return cmd, entry
        
        # Try README
        readme_path = self._find_readme()
        if readme_path:
            info.readme_path = str(readme_path)
            cmd, entry = self._parse_readme(readme_path)
            if cmd:
                return cmd, entry
        
        return None, None
    
    def _parse_compose(self, compose_path: str) -> tuple[Optional[str], Optional[str]]:
        """Parse docker-compose.yml for run command"""
        try:
            with open(compose_path, 'r') as f:
                content = f.read()
            
            # Simple command: docker-compose up
            run_cmd = "docker-compose up -d"
            
            # Try to find entrypoint in compose file
            entrypoint_match = re.search(r'entrypoint:\s*["\']?([^"\'\n]+)', content)
            entrypoint = entrypoint_match.group(1) if entrypoint_match else None
            
            # Try to find command in compose file
            if not entrypoint:
                cmd_match = re.search(r'command:\s*["\']?([^"\'\n]+)', content)
                entrypoint = cmd_match.group(1) if cmd_match else None
            
            return run_cmd, entrypoint
        except:
            return None, None
    
    def _parse_dockerfile(self, dockerfile_path: str) -> tuple[Optional[str], Optional[str]]:
        """Parse Dockerfile for CMD and ENTRYPOINT"""
        try:
            import json
            with open(dockerfile_path, 'r') as f:
                content = f.read()
            
            # Find ENTRYPOINT
            entrypoint_match = re.search(r'ENTRYPOINT\s+\[([^\]]+)\]', content)
            if not entrypoint_match:
                entrypoint_match = re.search(r'ENTRYPOINT\s+(.+)$', content, re.MULTILINE)
            
            entrypoint = None
            entrypoint_cmd = None
            if entrypoint_match:
                raw_entry = entrypoint_match.group(1).strip()
                # Try to parse as JSON array
                try:
                    entrypoint_cmd = json.loads('[' + raw_entry + ']')
                except:
                    entrypoint = raw_entry.strip('"\'')

            # Find CMD
            cmd_match = re.search(r'CMD\s+\[([^\]]+)\]', content)
            if not cmd_match:
                cmd_match = re.search(r'CMD\s+(.+)$', content, re.MULTILINE)
            
            if cmd_match and not entrypoint:
                raw_cmd = cmd_match.group(1).strip()
                # Try to parse as JSON array
                try:
                    cmd_array = json.loads('[' + raw_cmd + ']')
                    # For Python apps using gunicorn/flask/etc, extract the module name
                    if len(cmd_array) > 0:
                        # Look for Python module references like "src.app:app"
                        for arg in cmd_array:
                            if ':' in arg and '.' in arg:
                                # Format: src.app:app -> src/app.py
                                module_path = arg.split(':')[0].replace('.', '/') + '.py'
                                entrypoint = module_path
                                break
                        if not entrypoint:
                            # Just use the first argument if it's a .py file
                            for arg in cmd_array:
                                if arg.endswith('.py'):
                                    entrypoint = arg
                                    break
                except:
                    entrypoint = raw_cmd.strip('"\'')

            # Run command is generic docker build + run
            run_cmd = None
            if entrypoint or entrypoint_cmd:
                run_cmd = "docker build -t app . && docker run -p 8000:8000 app"
            
            return run_cmd, entrypoint
        except:
            return None, None
    
    def _find_readme(self) -> Optional[Path]:
        """Find README file"""
        readme_names = ['README.md', 'README.rst', 'README.txt', 'README', 'readme.md']
        
        for name in readme_names:
            readme = self.project_root / name
            if readme.exists():
                return readme
        
        return None
    
    def _parse_readme(self, readme_path: Path) -> tuple[Optional[str], Optional[str]]:
        """Parse README for run instructions"""
        try:
            with open(readme_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Look for docker-compose commands
            compose_match = re.search(r'(docker-compose\s+up[^\n]*)', content, re.IGNORECASE)
            if compose_match:
                return compose_match.group(1).strip(), None
            
            # Look for docker run commands
            docker_run_match = re.search(r'(docker\s+run[^\n]*)', content, re.IGNORECASE)
            if docker_run_match:
                return docker_run_match.group(1).strip(), None
            
            # Look for docker build + run
            docker_build_match = re.search(r'(docker\s+build[^\n]*)', content, re.IGNORECASE)
            if docker_build_match:
                build_cmd = docker_build_match.group(1).strip()
                # Try to find corresponding run command
                run_match = re.search(r'(docker\s+run[^\n]*)', content[docker_build_match.end():], re.IGNORECASE)
                if run_match:
                    return f"{build_cmd} && {run_match.group(1).strip()}", None
                return build_cmd, None
            
            # Look for Python app entrypoints
            python_match = re.search(r'python\s+(app\.py|main\.py|server\.py|run\.py)', content, re.IGNORECASE)
            if python_match:
                return None, python_match.group(0).strip()
            
            return None, None
        except:
            return None, None
    
    def can_run_dynamic_analysis(self, info: ContainerInfo) -> bool:
        """
        Determine if dynamic analysis can be run
        
        Args:
            info: ContainerInfo from detect()
            
        Returns:
            True if dynamic analysis is possible
        """
        # Need to be containerized
        if not info.is_containerized:
            return False
        
        # Need either run instructions or entrypoint
        if not (info.has_run_instructions or info.entrypoint):
            return False
        
        return True
    
    def print_detection_summary(self, info: ContainerInfo):
        """Print summary of container detection"""
        print("\n" + "=" * 70)
        print("🔍 Container Detection Summary")
        print("=" * 70)
        
        if info.is_containerized:
            print("✅ Application is containerized")
        else:
            print("❌ Application is NOT containerized")
            print("   Dynamic analysis requires Docker setup")
            return
        
        if info.has_dockerfile:
            print(f"✅ Dockerfile found: {info.dockerfile_path}")
        
        if info.has_compose:
            print(f"✅ Docker Compose found: {info.compose_path}")
        
        if info.has_run_instructions:
            print(f"✅ Run instructions found")
            print(f"   Command: {info.run_command}")
            if info.entrypoint:
                print(f"   Entrypoint: {info.entrypoint}")
        else:
            print("⚠️  No run instructions found")
            if info.entrypoint:
                print(f"   But found entrypoint: {info.entrypoint}")
        
        if info.readme_path:
            print(f"📄 README: {info.readme_path}")
        
        print("\n🎯 Dynamic Analysis Status:")
        if self.can_run_dynamic_analysis(info):
            print("   ✅ Can run dynamic analysis")
        else:
            print("   ❌ Cannot run dynamic analysis (missing run instructions)")
        
        print("=" * 70)


def detect_container_setup(project_root: str) -> ContainerInfo:
    """
    Convenience function to detect container setup
    
    Args:
        project_root: Root directory of the project
        
    Returns:
        ContainerInfo with detection results
    """
    detector = ContainerDetector(project_root)
    info = detector.detect()
    detector.print_detection_summary(info)
    return info

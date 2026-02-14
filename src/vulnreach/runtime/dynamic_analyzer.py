"""Dynamic Analysis Module using Runtime Hooks

This module runs the runtime_hooks system on a target application to collect
dynamic execution data including:
- Actual imports used at runtime
- Sink function calls (SQL, file I/O, network, deserialization, etc.)
- Taint propagation flows
- Audit events

The collected data is used for:
1. RBOM (Runtime Bill of Materials) generation
2. Correlation with static findings
3. Reducing false positives in vulnerability assessments
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class DynamicFinding:
    """Represents a dynamic finding from runtime execution"""
    finding_type: str  # "import", "sink", "taint", "audit"
    timestamp: str
    package_name: Optional[str] = None
    function_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    sink_type: Optional[str] = None  # SQL, FILE_WRITE, NETWORK, etc.
    taint_source: Optional[str] = None
    taint_sink: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class DynamicAnalyzer:
    """Analyzes application at runtime using hooks"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
        self.runtime_hooks_dir = self._find_runtime_hooks_dir()
        
    def _find_runtime_hooks_dir(self) -> Path:
        """Locate the runtime_hooks directory"""
        # Check in project root
        hooks_dir = Path(__file__).parent.parent.parent.parent / "runtime_hooks"
        if hooks_dir.exists():
            return hooks_dir
        
        # Check if we're in the vuln-reachability-sample directory
        current = Path.cwd()
        if (current / "runtime_hooks").exists():
            return current / "runtime_hooks"
        
        raise RuntimeError(
            "runtime_hooks directory not found. "
            "Please ensure you're running from the vuln-reachability-sample directory."
        )
    
    def run_dynamic_analysis(self, entrypoint: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Run dynamic analysis on the target application locally

        Args:
            entrypoint: Path to the application entrypoint (e.g., app.py, main.py)
            output_path: Optional path to save raw events JSON
        """
        entrypoint_path = Path(entrypoint).resolve()
        if not entrypoint_path.exists():
            raise FileNotFoundError(f"Entrypoint not found: {entrypoint}")
        
        print(f"\n🔄 Running dynamic analysis (Local)...")
        print(f"📍 Entrypoint: {entrypoint_path}")
        print(f"🪝 Runtime hooks: {self.runtime_hooks_dir}")
        
        runner_script = self.runtime_hooks_dir / "runner.py"
        cmd = [sys.executable, str(runner_script), str(entrypoint_path)]

        return self._execute_and_process(
            cmd,
            cwd=str(self.runtime_hooks_dir),
            entrypoint_display=str(entrypoint_path),
            output_path=output_path
        )

    def _execute_and_process(self, cmd: List[str], cwd: str, entrypoint_display: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Internal method to execute command and process results"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=cwd
            )

            raw_events = self._extract_json_from_stdout(result.stdout)

            if result.returncode != 0:
                print(f"⚠️  Application exited with code {result.returncode}")
                if result.stderr:
                    print(f"stderr: {result.stderr[:500]}")

            findings = self._process_events(raw_events)
            summary = self._generate_summary(findings)

            result_data = {
                "entrypoint": entrypoint_display,
                "raw_events": raw_events,
                "findings": [asdict(f) for f in findings],
                "summary": summary
            }

            if output_path:
                output_file = Path(output_path)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    json.dump(result_data, f, indent=2)
                print(f"✅ Dynamic findings saved to: {output_path}")

            return result_data

        except subprocess.TimeoutExpired:
            print("⚠️  Warning: Dynamic analysis timed out after 60 seconds")
            return {
                "entrypoint": entrypoint_display,
                "raw_events": [],
                "findings": [],
                "summary": {"error": "timeout"},
                "error": "Analysis timed out"
            }
        except Exception as e:
            print(f"❌ Error during dynamic analysis: {e}")
            return {
                "entrypoint": entrypoint_display,
                "raw_events": [],
                "findings": [],
                "summary": {"error": str(e)},
                "error": str(e)
            }

    def _extract_json_from_stdout(self, stdout: str) -> List[Dict[str, Any]]:
        """Extract valid JSON payload from mixed stdout"""
        if not stdout:
            return []

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            lines = stdout.strip().split('\n')

            for line in reversed(lines):
                line = line.strip()
                if line and (line.startswith('[') or line.startswith('{')):
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue

            print(f"⚠️  Warning: Could not find valid JSON in hook output")
            if len(stdout) > 0:
                print(f"Output preview: {stdout[:200]}...")
            return []

    def _process_events(self, raw_events: List[Dict[str, Any]]) -> List[DynamicFinding]:
        """Process raw events into structured findings"""
        findings = []
        
        for event in raw_events:
            event_type = event.get("event_type", "unknown")
            data = event.get("data", {})
            
            if event_type == "import":
                findings.append(DynamicFinding(
                    finding_type="import",
                    timestamp=data.get("timestamp", ""),
                    package_name=data.get("module") or data.get("name"),  # Try 'module' first, then 'name'
                    file_path=data.get("origin"),
                    data=data
                ))
            
            elif event_type == "sink":
                findings.append(DynamicFinding(
                    finding_type="sink",
                    timestamp=data.get("timestamp", ""),
                    function_name=data.get("function"),
                    file_path=data.get("file"),
                    line_number=data.get("line"),
                    sink_type=data.get("category"),
                    data=data
                ))
            
            elif event_type == "taint":
                findings.append(DynamicFinding(
                    finding_type="taint",
                    timestamp=data.get("timestamp", ""),
                    taint_source=data.get("source"),
                    taint_sink=data.get("sink"),
                    file_path=data.get("file"),
                    line_number=data.get("line"),
                    data=data
                ))
            
            elif event_type == "audit":
                findings.append(DynamicFinding(
                    finding_type="audit",
                    timestamp=data.get("timestamp", ""),
                    function_name=data.get("event"),
                    data=data
                ))
        
        return findings
    
    def _generate_summary(self, findings: List[DynamicFinding]) -> Dict[str, Any]:
        """Generate summary statistics from findings"""
        summary = {
            "total_findings": len(findings),
            "by_type": {},
            "unique_packages": set(),
            "unique_sinks": set(),
            "sink_categories": {}
        }
        
        for finding in findings:
            # Count by type
            ftype = finding.finding_type
            summary["by_type"][ftype] = summary["by_type"].get(ftype, 0) + 1
            
            # Track unique packages
            if finding.package_name:
                summary["unique_packages"].add(finding.package_name)
            
            # Track unique sinks
            if finding.function_name:
                summary["unique_sinks"].add(finding.function_name)
            
            # Track sink categories
            if finding.sink_type:
                cat = finding.sink_type
                summary["sink_categories"][cat] = summary["sink_categories"].get(cat, 0) + 1
        
        # Convert sets to lists for JSON serialization
        summary["unique_packages"] = sorted(list(summary["unique_packages"]))
        summary["unique_sinks"] = sorted(list(summary["unique_sinks"]))
        
        return summary


class ContainerDynamicAnalyzer(DynamicAnalyzer):
    """Analyzes application inside a Docker container"""

    def run_container_analysis(
        self,
        image_name: str,
        container_entrypoint: str,
        output_path: Optional[str] = None,
        build_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run dynamic analysis inside a Docker container

        Args:
            image_name: Name of the docker image (or tag to build)
            container_entrypoint: Relative path to entrypoint INSIDE container (e.g. app.py)
            output_path: Where to save results on the HOST
            build_context: If provided, builds the image from Dockerfile in this path first
        """
        print(f"\n🔄 Running dynamic analysis (Docker Container)...")

        if build_context:
            print(f"🔨 Building image from: {build_context}")
            self._build_image(build_context, image_name)

        print(f"🐳 Image: {image_name}")
        print(f"📍 Entrypoint: {container_entrypoint}")

        container_hooks_path = "/tmp/vulnreach_hooks"
        container_app_path = "/app"

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{self.runtime_hooks_dir.absolute()}:{container_hooks_path}",
            "-v", f"{self.project_root.absolute()}:{container_app_path}",
            "-w", container_app_path,
            "-e", f"PYTHONPATH={container_hooks_path}",
            image_name,
            "python3",
            f"{container_hooks_path}/runner.py",
            container_entrypoint
        ]

        print(f"🚀 Docker Command: {' '.join(cmd)}")

        return self._execute_and_process(
            cmd,
            cwd=str(self.project_root),
            entrypoint_display=f"{image_name}::{container_entrypoint}",
            output_path=output_path
        )

    def _build_image(self, build_context: str, image_name: str):
        """Build Docker image from Dockerfile"""
        build_path = Path(build_context).resolve()

        if not (build_path / "Dockerfile").exists():
            raise FileNotFoundError(f"Dockerfile not found in: {build_context}")

        print(f"   Building {image_name}...")
        result = subprocess.run(
            ["docker", "build", "-t", image_name, "."],
            cwd=str(build_path),
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"   ❌ Build failed: {result.stderr}")
            raise RuntimeError(f"Docker build failed: {result.stderr}")

        print(f"   ✅ Image built successfully")


def run_dynamic_analysis_pipeline(
    project_root: str,
    entrypoint: str,
    output_dir: str,
    docker_image: Optional[str] = None,
    build_context: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Run the complete dynamic analysis pipeline
    
    Args:
        project_root: Root directory of the project
        entrypoint: Path to application entrypoint
        output_dir: Directory to save results
        docker_image: If provided, runs analysis inside this container image
        build_context: If provided with docker_image, builds the image first
    """
    try:
        output_path = Path(output_dir) / "dynamic_findings.json"

        if docker_image:
            analyzer = ContainerDynamicAnalyzer(project_root)
            results = analyzer.run_container_analysis(
                docker_image,
                entrypoint,
                str(output_path),
                build_context
            )
        else:
            analyzer = DynamicAnalyzer(project_root)
            results = analyzer.run_dynamic_analysis(entrypoint, str(output_path))

        summary = results.get("summary", {})
        print(f"\n📊 Dynamic Analysis Summary:")
        print(f"   Total findings: {summary.get('total_findings', 0)}")
        print(f"   Unique packages: {len(summary.get('unique_packages', []))}")
        print(f"   Unique sinks: {len(summary.get('unique_sinks', []))}")
        
        by_type = summary.get("by_type", {})
        if by_type:
            print(f"   By type:")
            for ftype, count in by_type.items():
                print(f"     - {ftype}: {count}")
        
        if summary.get("error"):
            print(f"   ❌ Error: {summary.get('error')}")

        return results

    except Exception as e:
        print(f"❌ Dynamic analysis pipeline failed: {e}")
        return None
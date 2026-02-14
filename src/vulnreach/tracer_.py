#!/usr/bin/env python3
"""
Security SCA Tool using Syft and Trivy

This tool performs Software Composition Analysis (SCA) by:
1. Using Syft to generate SBOM from directory OR taking existing SBOM file
2. Using Trivy to perform vulnerability scanning on the SBOM
3. Parsing and reporting vulnerabilities with detailed information

Prerequisites:
- Syft: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
- Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/

Dependencies:
pip install requests
"""

from vulnreach.utils.multi_language_analyzer import run_multi_language_analysis
from vulnreach.utils.reachability_engine import run_reachability_engine
from vulnreach.utils.exploitability_analyzer import ExploitabilityAnalyzer
from vulnreach.config import get_config_loader
from vulnreach.utils.html_reporter import HtmlReporter
from vulnreach.rbom import create_rbom_from_analysis, save_rbom
from vulnreach.runtime.dynamic_analyzer import run_dynamic_analysis_pipeline
from vulnreach.correlation.correlator import run_correlation_pipeline
import os
import json
import sys
import argparse
import subprocess
import tempfile
import shutil
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import time
from urllib.parse import urlparse

@dataclass
class Component:
    """Represents a software component from SBOM"""
    name: str
    version: str
    type: str
    language: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    locations: List[str] = None


@dataclass
class Vulnerability:
    """Represents a vulnerability from Trivy scan"""
    vulnerability_id: str
    pkg_name: str
    pkg_version: str
    severity: str
    title: str
    description: str
    fixed_version: Optional[str] = None
    primary_url: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_ids: List[str] = None
    references: List[str] = None
    # Correlation fields (added for RBOM)
    verdict: Optional[str] = None
    confidence: Optional[str] = None
    priority: Optional[str] = None
    runtime_evidence: Optional[Dict[str, Any]] = None
    static_evidence: Optional[Dict[str, Any]] = None


class SyftSBOMGenerator:
    """Generate SBOM using Syft"""

    def __init__(self):
        self.syft_path = self._find_syft()
        if not self.syft_path:
            raise RuntimeError("Syft not found. Please install Syft first.")

    def _find_syft(self) -> Optional[str]:
        """Find Syft executable"""
        return shutil.which('syft')

    def check_syft_version(self) -> str:
        """Check Syft version"""
        try:
            result = subprocess.run([self.syft_path, 'version'],
                                    capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "Unknown"

    def generate_sbom(self, target: str, output_path: str, format: str = "spdx-json") -> bool:
        """
        Generate SBOM using Syft

        Args:
            target: Directory path or container image
            output_path: Output file path
            format: SBOM format (spdx-json, cyclonedx-json, syft-json)
        """
        try:
            print(f"🔍 Generating SBOM with Syft for: {target}")

            cmd = [
                self.syft_path,
                target,
                "-o", f"{format}={output_path}",
                "--quiet",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"❌ Syft failed: {result.stderr}")
                return False

            print(f"✅ SBOM generated successfully: {output_path}")

            # Enhance SBOM with transitive dependency information
            self._enhance_sbom_with_transitive_info(output_path, target)

            return True

        except Exception as e:
            print(f"❌ Error generating SBOM: {e}")
            return False

    def _enhance_sbom_with_transitive_info(self, sbom_path: str, project_root: str):
        """Enhance SBOM with transitive dependency information"""
        try:
            print(f"🔗 Enhancing SBOM with transitive dependency information...")

            # Load SBOM
            with open(sbom_path, 'r') as f:
                sbom_data = json.load(f)

            # Detect language
            from vulnreach.utils.multi_language_analyzer import ProjectLanguageDetector
            detector = ProjectLanguageDetector(project_root)
            language = detector.detect_language()

            print(f"   Detected language: {language}")

            # Get dependency tree
            from vulnreach.utils.dependency_tree_analyzer import get_dependency_analyzer
            analyzer = get_dependency_analyzer(project_root, language)

            if not analyzer:
                print(f"   ⚠️  No dependency analyzer available for {language}")
                return

            all_deps = analyzer.get_all_dependencies()

            if not all_deps:
                print(f"   ⚠️  No dependencies found")
                return

            enhanced_count = 0

            # Enhance SBOM packages with transitive info
            if 'packages' in sbom_data:
                for package in sbom_data['packages']:
                    pkg_name = package.get('name', '')
                    if not pkg_name or pkg_name == 'DOCUMENT':
                        continue

                    # Normalize package name for lookup
                    normalized_name = pkg_name.lower().replace('_', '-')

                    if normalized_name in all_deps:
                        dep_info = all_deps[normalized_name]
                        # Add custom properties
                        package['is_direct_dependency'] = dep_info.is_direct
                        package['dependency_depth'] = dep_info.depth
                        package['required_by'] = dep_info.parent_dependencies
                        enhanced_count += 1

            # Handle Syft native format
            elif 'artifacts' in sbom_data:
                for artifact in sbom_data['artifacts']:
                    pkg_name = artifact.get('name', '')
                    if not pkg_name:
                        continue

                    normalized_name = pkg_name.lower().replace('_', '-')

                    if normalized_name in all_deps:
                        dep_info = all_deps[normalized_name]
                        artifact['is_direct_dependency'] = dep_info.is_direct
                        artifact['dependency_depth'] = dep_info.depth
                        artifact['required_by'] = dep_info.parent_dependencies
                        enhanced_count += 1

            # Handle CycloneDX format
            elif 'components' in sbom_data:
                for component in sbom_data['components']:
                    pkg_name = component.get('name', '')
                    if not pkg_name:
                        continue

                    normalized_name = pkg_name.lower().replace('_', '-')

                    if normalized_name in all_deps:
                        dep_info = all_deps[normalized_name]
                        component['is_direct_dependency'] = dep_info.is_direct
                        component['dependency_depth'] = dep_info.depth
                        component['required_by'] = dep_info.parent_dependencies
                        enhanced_count += 1

            if enhanced_count > 0:
                # Save enhanced SBOM
                with open(sbom_path, 'w') as f:
                    json.dump(sbom_data, f, indent=2)

                print(f"   ✅ Enhanced {enhanced_count} package(s) with transitive dependency info")
            else:
                print(f"   ℹ️  No packages matched for enhancement")

        except Exception as e:
            print(f"   ⚠️  Could not enhance SBOM with transitive info: {e}")
            # Don't fail, just continue without enhancement

    def parse_sbom_components(self, sbom_path: str) -> List[Component]:
        """Parse components from generated SBOM"""
        components = []

        try:
            with open(sbom_path, 'r') as f:
                sbom_data = json.load(f)

            # Handle SPDX format
            if 'packages' in sbom_data:
                for package in sbom_data['packages']:
                    if package.get('name') == 'DOCUMENT':
                        continue

                    # Extract external references
                    purl = None
                    cpe = None

                    for ref in package.get('externalRefs', []):
                        if ref.get('referenceType') == 'purl':
                            purl = ref.get('referenceLocator')
                        elif ref.get('referenceType') == 'cpe23Type':
                            cpe = ref.get('referenceLocator')

                    # Extract language from PURL
                    language = None
                    if purl and purl.startswith('pkg:'):
                        try:
                            language = purl.split('/')[0].replace('pkg:', '')
                        except:
                            pass

                    component = Component(
                        name=package.get('name', ''),
                        version=package.get('versionInfo', ''),
                        type=package.get('packageType', 'library'),
                        language=language,
                        purl=purl,
                        cpe=cpe,
                        locations=[]
                    )
                    components.append(component)

            # Handle CycloneDX format
            elif 'components' in sbom_data:
                for comp_data in sbom_data['components']:
                    # Extract language from PURL
                    language = None
                    purl = comp_data.get('purl')
                    if purl and purl.startswith('pkg:'):
                        try:
                            language = purl.split('/')[0].replace('pkg:', '')
                        except:
                            pass

                    component = Component(
                        name=comp_data.get('name', ''),
                        version=comp_data.get('version', ''),
                        type=comp_data.get('type', 'library'),
                        language=language,
                        purl=purl,
                        cpe=comp_data.get('cpe'),
                        locations=[]
                    )
                    components.append(component)

            # Handle Syft native format
            elif 'artifacts' in sbom_data:
                for artifact in sbom_data['artifacts']:
                    # Extract language
                    language = None
                    if 'language' in artifact:
                        language = artifact['language']
                    elif artifact.get('type'):
                        # Map Syft types to languages
                        type_map = {
                            'python': 'python',
                            'npm': 'javascript',
                            'gem': 'ruby',
                            'java-archive': 'java',
                            'go-module': 'go'
                        }
                        language = type_map.get(artifact['type'])

                    locations = []
                    for loc in artifact.get('locations', []):
                        if 'path' in loc:
                            locations.append(loc['path'])

                    component = Component(
                        name=artifact.get('name', ''),
                        version=artifact.get('version', ''),
                        type=artifact.get('type', 'library'),
                        language=language,
                        purl=artifact.get('purl'),
                        cpe=artifact.get('cpe'),
                        locations=locations
                    )
                    components.append(component)

            print(f"📦 Parsed {len(components)} components from SBOM")
            return components

        except Exception as e:
            print(f"❌ Error parsing SBOM: {e}")
            return []


class TrivySCAScanner:
    """Perform SCA using Trivy"""

    def __init__(self):
        self.trivy_path = self._find_trivy()
        if not self.trivy_path:
            raise RuntimeError("Trivy not found. Please install Trivy first.")

    def _find_trivy(self) -> Optional[str]:
        """Find Trivy executable"""
        return shutil.which('trivy')

    def check_trivy_version(self) -> str:
        """Check Trivy version"""
        try:
            result = subprocess.run([self.trivy_path, 'version'],
                                    capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "Unknown"

    def scan_sbom(self, sbom_path: str, output_path: str = None) -> List[Vulnerability]:
        """
        Scan SBOM for vulnerabilities using Trivy

        Args:
            sbom_path: Path to SBOM file
            output_path: Optional path to save Trivy JSON output
        """
        vulnerabilities = []

        try:
            print(f"🛡️ Scanning SBOM with Trivy: {sbom_path}")

            # Create temporary file for Trivy output if not specified
            if not output_path:
                temp_fd, output_path = tempfile.mkstemp(suffix='.json')
                os.close(temp_fd)
                cleanup_temp = True
            else:
                cleanup_temp = False

            cmd = [
                self.trivy_path,
                'sbom',
                sbom_path,
                '--format', 'json',
                '--output', output_path,
                '--quiet'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"❌ Trivy scan failed: {result.stderr}")
                return vulnerabilities

            # Parse Trivy output
            vulnerabilities = self._parse_trivy_output(output_path)

            # Cleanup temporary file
            if cleanup_temp:
                try:
                    os.unlink(output_path)
                except:
                    pass

            print(f"🚨 Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            print(f"❌ Error scanning with Trivy: {e}")
            return vulnerabilities

    def scan_directory(self, directory: str, output_path: str = None) -> List[Vulnerability]:
        """
        Directly scan directory with Trivy (alternative to SBOM approach)

        Args:
            directory: Directory to scan
            output_path: Optional path to save Trivy JSON output
        """
        vulnerabilities = []

        try:
            print(f"🛡️ Scanning directory with Trivy: {directory}")

            # Create temporary file for Trivy output if not specified
            if not output_path:
                temp_fd, output_path = tempfile.mkstemp(suffix='.json')
                os.close(temp_fd)
                cleanup_temp = True
            else:
                cleanup_temp = False

            cmd = [
                self.trivy_path,
                'fs',
                directory,
                '--format', 'json',
                '--output', output_path,
                '--quiet'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"❌ Trivy scan failed: {result.stderr}")
                return vulnerabilities

            # Parse Trivy output
            vulnerabilities = self._parse_trivy_output(output_path)

            # Cleanup temporary file
            if cleanup_temp:
                try:
                    os.unlink(output_path)
                except:
                    pass

            print(f"🚨 Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except Exception as e:
            print(f"❌ Error scanning with Trivy: {e}")
            return vulnerabilities

    def _parse_trivy_output(self, output_path: str) -> List[Vulnerability]:
        """Parse Trivy JSON output"""
        vulnerabilities = []

        try:
            with open(output_path, 'r') as f:
                trivy_data = json.load(f)

            # Trivy output structure: Results -> Vulnerabilities
            for result in trivy_data.get('Results', []):
                target = result.get('Target', '')

                for vuln in result.get('Vulnerabilities', []):
                    # Extract CVSS information
                    cvss_score = None
                    cvss_vector = None

                    if 'CVSS' in vuln:
                        for vendor, cvss_data in vuln['CVSS'].items():
                            if 'V3Score' in cvss_data:
                                cvss_score = cvss_data['V3Score']
                                cvss_vector = cvss_data.get('V3Vector')
                                break
                            elif 'V2Score' in cvss_data:
                                cvss_score = cvss_data['V2Score']
                                cvss_vector = cvss_data.get('V2Vector')

                    # Extract CWE IDs
                    cwe_ids = []
                    if 'CweIDs' in vuln:
                        cwe_ids = vuln['CweIDs']

                    # Extract references
                    references = vuln.get('References', [])

                    vulnerability = Vulnerability(
                        vulnerability_id=vuln.get('VulnerabilityID', ''),
                        pkg_name=vuln.get('PkgName', ''),
                        pkg_version=vuln.get('InstalledVersion', ''),
                        severity=vuln.get('Severity', 'UNKNOWN'),
                        title=vuln.get('Title', ''),
                        description=vuln.get('Description', ''),
                        fixed_version=vuln.get('FixedVersion'),
                        primary_url=vuln.get('PrimaryURL'),
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        cwe_ids=cwe_ids,
                        references=references
                    )
                    vulnerabilities.append(vulnerability)

            return vulnerabilities

        except Exception as e:
            print(f"❌ Error parsing Trivy output: {e}")
            return []


class SecurityReporter:
    """Generate comprehensive security reports"""

    @staticmethod
    def generate_report(components: List[Component], vulnerabilities: List[Vulnerability],
                        output_path: str = None, scan_duration: float = None) -> Dict:
        """Generate comprehensive security report"""

        # Organize vulnerabilities by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        vulnerable_packages = set()

        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
            vulnerable_packages.add(f"{vuln.pkg_name}@{vuln.pkg_version}")

        report = {
            "scan_timestamp": datetime.now().isoformat(),
            "scan_duration": scan_duration,
            "tools": {
                "sbom_generator": "Syft",
                "vulnerability_scanner": "Trivy"
            },
            "summary": {
                "total_components": len(components),
                "vulnerable_components": len(vulnerable_packages),
                "total_vulnerabilities": len(vulnerabilities),
                "severity_breakdown": severity_counts
            },
            "components": [
                {
                    "name": comp.name,
                    "version": comp.version,
                    "type": comp.type,
                    "language": comp.language,
                    "purl": comp.purl,
                    "cpe": comp.cpe,
                    "locations": comp.locations or []
                }
                for comp in components
            ],
            "vulnerabilities": [
                {
                    "id": vuln.vulnerability_id,
                    "package_name": vuln.pkg_name,
                    "package_version": vuln.pkg_version,
                    "severity": vuln.severity,
                    "title": vuln.title,
                    "description": vuln.description,
                    "fixed_version": vuln.fixed_version,
                    "cvss_score": vuln.cvss_score,
                    "cvss_vector": vuln.cvss_vector,
                    "cwe_ids": vuln.cwe_ids or [],
                    "references": vuln.references or [],
                    "primary_url": vuln.primary_url,
                    # Correlation fields (RBOM enrichment)
                    "verdict": vuln.verdict,
                    "confidence": vuln.confidence,
                    "priority": vuln.priority,
                    "runtime_evidence": vuln.runtime_evidence,
                    "static_evidence": vuln.static_evidence
                }
                for vuln in vulnerabilities
            ]
        }

        # Save report to file
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)

        # Print summary
        SecurityReporter._print_summary(report)

        return report

    @staticmethod
    def _print_summary(report: Dict):
        """Print detailed report summary to console"""
        print("\n" + "=" * 80)
        print("🛡️  SECURITY SCAN RESULTS")
        print("=" * 80)

        summary = report["summary"]
        tools = report["tools"]

        # Add scan duration to report
        scan_duration = report.get("scan_duration", 0)

        print(f"📊 Scan completed at: {report['scan_timestamp']}")
        if scan_duration and scan_duration > 0:
            print(f"⏱️  Scan duration: {scan_duration:.2f} seconds")
        print(f"🔧 SBOM Generator: {tools['sbom_generator']}")
        print(f"🔍 Vulnerability Scanner: {tools['vulnerability_scanner']}")
        print()

        print(f"📦 Total Components: {summary['total_components']}")
        print(f"⚠️  Vulnerable Components: {summary['vulnerable_components']}")
        print(f"🚨 Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print()

        # Severity breakdown
        severity_breakdown = summary['severity_breakdown']
        if sum(severity_breakdown.values()) > 0:
            print("📈 Severity Breakdown:")
            if severity_breakdown['CRITICAL'] > 0:
                print(f"   🔴 CRITICAL: {severity_breakdown['CRITICAL']}")
            if severity_breakdown['HIGH'] > 0:
                print(f"   🟠 HIGH: {severity_breakdown['HIGH']}")
            if severity_breakdown['MEDIUM'] > 0:
                print(f"   🟡 MEDIUM: {severity_breakdown['MEDIUM']}")
            if severity_breakdown['LOW'] > 0:
                print(f"   🟢 LOW: {severity_breakdown['LOW']}")
            if severity_breakdown['UNKNOWN'] > 0:
                print(f"   ⚪ UNKNOWN: {severity_breakdown['UNKNOWN']}")
            print()

        # Top vulnerabilities
        if report['vulnerabilities']:
            print("🚨 TOP CRITICAL/HIGH VULNERABILITIES:")
            print("-" * 60)

            critical_high = [v for v in report['vulnerabilities']
                             if v['severity'] in ['CRITICAL', 'HIGH']][:10]

            for vuln in critical_high:
                severity_icon = "🔴" if vuln['severity'] == 'CRITICAL' else "🟠"
                cvss_info = f" (CVSS: {vuln['cvss_score']})" if vuln['cvss_score'] else ""

                print(f"{severity_icon} {vuln['id']} - {vuln['package_name']}@{vuln['package_version']}")
                print(f"   Severity: {vuln['severity']}{cvss_info}")
                print(f"   Title: {vuln['title']}")

                # Show correlation data if available
                if vuln.get('priority'):
                    priority_icon = "🚨" if vuln['priority'] == 'CRITICAL' else "⚠️" if vuln['priority'] == 'HIGH' else "ℹ️"
                    print(f"   {priority_icon} Priority: {vuln['priority']}")
                if vuln.get('verdict'):
                    verdict_icon = "🔴" if vuln['verdict'] == 'REACHABLE' else "🟢" if vuln['verdict'] == 'NOT_REACHABLE' else "🟡"
                    print(f"   {verdict_icon} Verdict: {vuln['verdict']}")
                if vuln.get('confidence'):
                    confidence_stars = "⭐" * {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'NONE': 0}.get(vuln['confidence'], 0)
                    if confidence_stars:
                        print(f"   {confidence_stars} Confidence: {vuln['confidence']}")

                if vuln['fixed_version']:
                    print(f"   🔧 Fixed in: {vuln['fixed_version']}")
                print()

        if summary['total_vulnerabilities'] == 0:
            print("✅ No vulnerabilities found! Your dependencies are secure.")
        else:
            print("⚠️  Please review and remediate the vulnerabilities above.")

        print("=" * 80)


def check_prerequisites(request_sast: bool = False):
    """Check if required tools are installed"""
    missing_tools = []

    if not shutil.which('syft'):
        missing_tools.append("Syft")

    if not shutil.which('trivy'):
        missing_tools.append("Trivy")

    if not shutil.which('git'):
        missing_tools.append("Git")

    if request_sast and not shutil.which('semgrep'):
        print("⚠️  Semgrep not found. Install Semgrep or skip --run-sast.")

    if missing_tools:
        print("❌ Missing required tools:")
        for tool in missing_tools:
            print(f"   - {tool}")
        print("\nInstallation instructions:")
        print(
            "Syft: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin")
        print("Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
        print("Git: https://git-scm.com/downloads")
        return False

    return True


def is_git_url(target: str) -> bool:
    """Check if the target is a git URL"""
    if not target:
        return False
    
    # Check for common git URL patterns
    git_patterns = [
        r'^https?://.*\.git$',  # https://github.com/user/repo.git
        r'^https?://github\.com/[^/]+/[^/]+/?$',  # https://github.com/user/repo
        r'^https?://gitlab\.com/[^/]+/[^/]+/?$',  # https://gitlab.com/user/repo
        r'^https?://bitbucket\.org/[^/]+/[^/]+/?$',  # https://bitbucket.org/user/repo
        r'^git@.*:.*\.git$',  # git@github.com:user/repo.git
        r'^ssh://git@.*/.*/.*\.git$',  # ssh://git@github.com/user/repo.git
    ]
    
    for pattern in git_patterns:
        if re.match(pattern, target, re.IGNORECASE):
            return True
    
    # Check if it looks like a URL
    try:
        parsed = urlparse(target)
        if parsed.scheme in ['http', 'https', 'ssh', 'git']:
            return True
    except:
        pass
    
    return False


def clone_git_repository(git_url: str, temp_dir: str = None) -> Tuple[str, bool]:
    """
    Clone a git repository to a temporary directory
    
    Args:
        git_url: Git repository URL
        temp_dir: Optional temporary directory path
        
    Returns:
        Tuple of (cloned_path, is_temporary)
    """
    if not temp_dir:
        temp_dir = tempfile.mkdtemp(prefix="vulnreach_clone_")
        is_temporary = True
    else:
        is_temporary = False
    
    try:
        print(f"📥 Cloning repository: {git_url}")
        
        # Clone the repository
        cmd = ['git', 'clone', '--depth', '1', git_url, temp_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"❌ Git clone failed: {result.stderr}")
            if is_temporary and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            return None, False
        
        print(f"✅ Repository cloned to: {temp_dir}")
        return temp_dir, is_temporary
        
    except subprocess.TimeoutExpired:
        print("❌ Git clone timed out (5 minutes)")
        if is_temporary and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        return None, False
    except Exception as e:
        print(f"❌ Error cloning repository: {e}")
        if is_temporary and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        return None, False


def extract_repo_name_from_url(git_url: str) -> str:
    """Extract repository name from git URL"""
    if not git_url:
        return "unknown_repo"
    
    # Remove .git suffix if present
    url = git_url.rstrip('/')
    if url.endswith('.git'):
        url = url[:-4]
    
    # Extract the last part of the path
    if '/' in url:
        repo_name = url.split('/')[-1]
    else:
        repo_name = url
    
    # Sanitize the name for filesystem use
    repo_name = re.sub(r'[^\w\-_.]', '_', repo_name)
    
    return repo_name or "unknown_repo"

def version_key(v: str) -> Tuple:
    """Simple numeric comparator for versions like 1.2.3, 5.3, 5.4.0."""
    if not v or not isinstance(v, str):
        return tuple()
    parts = []
    for token in v.split("."):
        num = ""
        for ch in token:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


def enrich_vulnerabilities_with_correlation(
    vulnerabilities: List[Vulnerability],
    project_findings_dir: str,
    enable_correlation: bool = True
) -> List[Vulnerability]:
    """Enrich vulnerabilities with correlation analysis (static + dynamic evidence)

    Args:
        vulnerabilities: List of vulnerabilities from Trivy scan
        project_findings_dir: Path to security_findings directory
        enable_correlation: Whether to run correlation (can be disabled with flag)

    Returns:
        Enriched list of vulnerabilities with verdict, confidence, and evidence
    """
    if not enable_correlation:
        return vulnerabilities

    try:
        from vulnreach.correlation.cve_runtime_mapper import CVERuntimeMapper
        from vulnreach.correlation.event_matcher import EventMatcher
        from vulnreach.rbom.schema import Priority

        print("\n🔗 Running correlation analysis (static + dynamic evidence)...")

        # Load runtime events if available
        runtime_events_path = os.path.join(project_findings_dir, "runtime_events.json")
        runtime_events = []
        if os.path.exists(runtime_events_path):
            try:
                with open(runtime_events_path, 'r') as f:
                    runtime_events = json.load(f)
                print(f"   ✅ Loaded {len(runtime_events)} runtime events")
            except Exception as e:
                print(f"   ⚠️  Could not load runtime events: {e}")

        # Load static analysis results if available (from reachability analysis)
        static_results = {}
        reachability_files = [
            f for f in os.listdir(project_findings_dir)
            if f.endswith('_vulnerability_reachability_report.json')
        ]

        if reachability_files:
            try:
                reach_file = os.path.join(project_findings_dir, reachability_files[0])
                with open(reach_file, 'r') as f:
                    reach_data = json.load(f)

                # Build static results dict from reachability report
                for vuln_data in reach_data.get('vulnerabilities', []):
                    pkg_name = vuln_data.get('package_name', '')
                    if pkg_name:
                        static_results[pkg_name] = {
                            'import_detected': vuln_data.get('usage_pattern', '') != 'NOT_USED',
                            'call_chain_exists': vuln_data.get('risk_level', '') in ['CRITICAL', 'HIGH'],
                            'entry_points': [],
                            'call_chains': [],
                            'vulnerable_functions': []
                        }
                print(f"   ✅ Loaded static analysis for {len(static_results)} packages")
            except Exception as e:
                print(f"   ⚠️  Could not load static analysis: {e}")

        # Build SBOM components for event matching
        sbom_components = []
        for vuln in vulnerabilities:
            sbom_components.append({
                'name': vuln.pkg_name,
                'version': vuln.pkg_version
            })

        # Match runtime events to packages
        correlations = {}
        if runtime_events:
            matcher = EventMatcher()
            correlations = matcher.match_import_events(runtime_events, sbom_components)
            print(f"   ✅ Matched runtime events to {len(correlations)} packages")

        # Run correlation analysis
        mapper = CVERuntimeMapper()
        enriched_count = 0

        for vuln in vulnerabilities:
            # Get correlation data for this package
            correlation = correlations.get(vuln.pkg_name)
            static = static_results.get(vuln.pkg_name)

            # Calculate reachability
            verdict, confidence, runtime_ev, static_ev = mapper.calculate_reachability(
                vuln.vulnerability_id,
                vuln.pkg_name,
                vuln.pkg_version,
                correlation,
                static
            )

            # Enrich vulnerability with correlation results
            vuln.verdict = verdict.value
            vuln.confidence = confidence.value

            # Calculate priority based on severity + reachability
            vuln.priority = _calculate_priority(vuln.severity, verdict.value, confidence.value)

            # Store evidence
            if runtime_ev:
                vuln.runtime_evidence = runtime_ev.to_dict()
            if static_ev:
                vuln.static_evidence = static_ev.to_dict()

            enriched_count += 1

        print(f"   ✅ Enriched {enriched_count} vulnerabilities with correlation data")

        # Print correlation summary
        _print_correlation_summary(vulnerabilities)

        return vulnerabilities

    except ImportError as e:
        print(f"   ⚠️  Correlation modules not available: {e}")
        return vulnerabilities
    except Exception as e:
        print(f"   ⚠️  Correlation analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return vulnerabilities


def _calculate_priority(severity: str, verdict: str, confidence: str) -> str:
    """Calculate remediation priority based on severity + reachability + confidence"""
    # CRITICAL: High/Critical severity + Reachable + High confidence
    if severity in ['CRITICAL', 'HIGH'] and verdict == 'REACHABLE' and confidence == 'HIGH':
        return 'CRITICAL'

    # HIGH: High severity + Reachable OR Medium severity + Reachable + High confidence
    if severity in ['CRITICAL', 'HIGH'] and verdict == 'REACHABLE':
        return 'HIGH'
    if severity == 'MEDIUM' and verdict == 'REACHABLE' and confidence == 'HIGH':
        return 'HIGH'

    # MEDIUM: Medium severity + some reachability signal
    if severity == 'MEDIUM' and verdict in ['REACHABLE', 'UNKNOWN']:
        return 'MEDIUM'

    # LOW: Low severity or not reachable
    if severity == 'LOW' or verdict == 'NOT_REACHABLE':
        return 'LOW'

    # INFO: Everything else
    return 'INFO'


def _print_correlation_summary(vulnerabilities: List[Vulnerability]):
    """Print summary of correlation analysis results"""
    verdict_counts = {'REACHABLE': 0, 'NOT_REACHABLE': 0, 'UNKNOWN': 0, None: 0}
    confidence_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0, None: 0}
    priority_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, None: 0}

    for vuln in vulnerabilities:
        verdict_counts[vuln.verdict] = verdict_counts.get(vuln.verdict, 0) + 1
        confidence_counts[vuln.confidence] = confidence_counts.get(vuln.confidence, 0) + 1
        priority_counts[vuln.priority] = priority_counts.get(vuln.priority, 0) + 1

    print("\n📊 Correlation Analysis Summary:")
    print("   Reachability Verdicts:")
    if verdict_counts.get('REACHABLE', 0) > 0:
        print(f"      🔴 REACHABLE: {verdict_counts['REACHABLE']}")
    if verdict_counts.get('NOT_REACHABLE', 0) > 0:
        print(f"      🟢 NOT_REACHABLE: {verdict_counts['NOT_REACHABLE']}")
    if verdict_counts.get('UNKNOWN', 0) > 0:
        print(f"      🟡 UNKNOWN: {verdict_counts['UNKNOWN']}")

    print("   Confidence Levels:")
    if confidence_counts.get('HIGH', 0) > 0:
        print(f"      ⭐⭐⭐ HIGH: {confidence_counts['HIGH']}")
    if confidence_counts.get('MEDIUM', 0) > 0:
        print(f"      ⭐⭐ MEDIUM: {confidence_counts['MEDIUM']}")
    if confidence_counts.get('LOW', 0) > 0:
        print(f"      ⭐ LOW: {confidence_counts['LOW']}")

    print("   Priority Distribution:")
    if priority_counts.get('CRITICAL', 0) > 0:
        print(f"      🚨 CRITICAL: {priority_counts['CRITICAL']} (FIX NOW)")
    if priority_counts.get('HIGH', 0) > 0:
        print(f"      🟠 HIGH: {priority_counts['HIGH']}")
    if priority_counts.get('MEDIUM', 0) > 0:
        print(f"      🟡 MEDIUM: {priority_counts['MEDIUM']}")
    if priority_counts.get('LOW', 0) > 0:
        print(f"      🟢 LOW: {priority_counts['LOW']}")


def consolidate_fixed_versions(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Map installed versions from components (case-insensitive name match)
    installed = {}
    for c in scan.get("components", []):
        name = (c.get("name") or "").lower()
        if name and c.get("version"):
            installed[name] = c["version"]

    # Collect fixed versions per package from vulnerabilities
    fixed = {}
    for v in scan.get("vulnerabilities", []):
        pkg = (v.get("package_name") or "").lower()
        fv = v.get("fixed_version")
        if not pkg or not fv:
            continue

        # Split comma-separated fixed_version fields into individual versions
        parts = []
        try:
            # Some scanners may return a comma-separated string like "2.4.2, 2.3.3"
            for part in str(fv).split(','):
                p = part.strip()
                if p:
                    parts.append(p)
        except Exception:
            parts = [str(fv).strip()]

        if parts:
            fixed.setdefault(pkg, []).extend(parts)

    out = []
    for pkg, fixes in fixed.items():
        # Normalize unique versions and sort them using version_key
        unique_fixes = sorted({f for f in fixes if f}, key=version_key)

        # Determine current installed version (may be None)
        current = installed.get(pkg)

        # If we can parse current version, filter to only include fixes strictly greater
        greater_fixes = []
        if current and isinstance(current, str):
            try:
                current_key = version_key(current)
                for fv in unique_fixes:
                    fv_key = version_key(fv)
                    # Only include if fv_key is a valid parsed tuple and strictly greater
                    if fv_key and fv_key > current_key:
                        greater_fixes.append(fv)
            except Exception:
                # If any parsing fails, fall back to including all unique fixes
                greater_fixes = unique_fixes[:]
        else:
            # No installed version known - include all unique fixes
            greater_fixes = unique_fixes[:]

        # Choose recommended fixed version(s): list of greater fixes (highest first)
        if greater_fixes:
            # Recommended string: highest-first, comma-separated
            recommended = ', '.join(sorted(greater_fixes, key=version_key, reverse=True))
            all_seen = greater_fixes
            upgrade_needed = True
        else:
            recommended = None
            all_seen = []
            upgrade_needed = False

        out.append({
            "package_name": pkg,
            "installed_version": current,
            "recommended_fixed_version": recommended,
            "all_seen_fixed_versions": all_seen,
            "upgrade_needed": upgrade_needed,
        })
    return out


def get_project_name(target_path: str) -> str:
    """Extract project name from target path"""
    if not target_path:
        return "unknown_project"

    # Get the basename (last component) of the path
    project_name = os.path.basename(os.path.abspath(target_path))

    # Sanitize the name for filesystem use
    import re
    project_name = re.sub(r'[^\w\-_.]', '_', project_name)

    return project_name or "unknown_project"


def create_security_findings_dir(project_name: str) -> str:
    """Create security_findings directory structure and return the project path"""
    base_dir = "security_findings"
    project_dir = os.path.join(base_dir, project_name)

    # Create directories if they don't exist
    os.makedirs(project_dir, exist_ok=True)

    return project_dir


def create_default_config():
    """Create default configuration file"""
    try:
        config_loader = get_config_loader()
        config_loader.create_default_config()
        print("✅ Default configuration file created successfully!")
        print(f"📁 Location: {config_loader.config_path}")
        print("💡 Edit this file to add your API keys and configure providers.")
        print("   Use environment variables for sensitive values: ${VAR_NAME}")
    except Exception as e:
        print(f"❌ Failed to create config file: {e}")
        sys.exit(1)



def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(
        description='Security SCA Tool using Syft and Trivy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan local directory with SBOM generation
  %(prog)s /path/to/project --output-report security_report.json

  # Scan git repository with SBOM generation  
  %(prog)s https://github.com/user/repo.git --output-report security_report.json

  # Scan GitHub repository (auto-detects .git)
  %(prog)s https://github.com/user/repo --output-report security_report.json

  # Use existing SBOM file
  %(prog)s --sbom existing_sbom.json --output-report report.json

  # Generate and save SBOM, then scan
  %(prog)s /path/to/project --output-sbom sbom.json --output-report report.json

  # Direct directory scan (no SBOM generation)
  %(prog)s /path/to/project --direct-scan

  # Clone and scan git repository with reachability analysis
  %(prog)s git@github.com:user/repo.git --run-reachability

  # Run comprehensive taint analysis (reduces false positives)
  %(prog)s /path/to/project --run-taint-analysis

  # Run taint analysis for specific vulnerability classes
  %(prog)s /path/to/project --run-taint-analysis --taint-vuln-classes SQLI,XSS,DESERIALIZE

  # Run dynamic analysis with runtime hooks to capture runtime behavior
  %(prog)s /path/to/project --run-dynamic --entrypoint app.py

  # Full security pipeline with static, dynamic, and correlation
  %(prog)s /path/to/project --run-reachability --run-dynamic --entrypoint app.py

  # Full pipeline: SBOM + Reachability + Dynamic + Exploitability + RBOM
  %(prog)s /path/to/project --run-reachability --run-dynamic --entrypoint app.py --run-exploitability --generate-rbom

  # Generate Runtime Bill of Materials (RBOM) with reachability analysis
  %(prog)s /path/to/project --generate-rbom
        """
    )

    parser.add_argument('target', nargs='?', help='Directory path or git repository URL to scan (if not using --sbom)')
    parser.add_argument('--target', dest='target_flag', help='Directory path or git repository URL to scan (alternative to positional argument)')
    parser.add_argument('--sbom', help='Use existing SBOM file instead of generating new one')
    parser.add_argument('--output-sbom', help='Save generated SBOM to file')
    parser.add_argument('--output-report', help='Output path for security report (default: security_report.json)')
    parser.add_argument('--sbom-format', choices=['spdx-json', 'cyclonedx-json', 'syft-json'],
                        default='spdx-json', help='SBOM format for generation')
    parser.add_argument('--direct-scan', action='store_true',
                        help='Skip SBOM generation and scan directory directly with Trivy')
    parser.add_argument('--trivy-output', help='Save raw Trivy output to file')
    parser.add_argument('--output-consolidated',
                        help='Output path for consolidated fixed-version recommendations (default: consolidated.json)',
                        default='consolidated.json')
    parser.add_argument('--run-reachability', action='store_true',
                        help='Run multi-language vulnerability reachability analysis after security scan')
    parser.add_argument('--run-exploitability', action='store_true',
                        help='Run exploitability analysis using SearchSploit to check for public exploits')
    parser.add_argument('--run-sast', action='store_true',
                        help='Run Semgrep SAST signal collection (V1 scope)')
    parser.add_argument('--semgrep-rules', help='Override Semgrep ruleset path/URL (default: p/security-audit)')
    parser.add_argument('--run-routes', action='store_true',
                        help='Extract HTTP routes (Flask/FastAPI/Express/Spring) to routes.json')
    parser.add_argument('--run-taint-analysis', action='store_true',
                        help='Run comprehensive taint analysis using Tainter (source-to-sink vulnerability flow detection)')
    parser.add_argument('--taint-vuln-classes', metavar='CLASSES',
                        help='Comma-separated vulnerability classes for taint analysis (e.g., SQLI,XSS,DESERIALIZE)')
    parser.add_argument('--taint-include-tests', action='store_true',
                        help='Include test files in taint analysis (default: excluded)')
    parser.add_argument('--run-reachability-engine', action='store_true',
                        help='Link Semgrep sinks to handlers/routes and score reachability')
    parser.add_argument('--generate-rbom', action='store_true',
                        help='Generate Runtime Bill of Materials (RBOM) with reachability analysis')
    parser.add_argument('--no-correlation', action='store_true',
                        help='Disable correlation analysis (static + dynamic evidence integration)')
    parser.add_argument('--run-dynamic', action='store_true',
                        help='Run dynamic analysis using runtime hooks to collect runtime behavior')
    parser.add_argument('--entrypoint', metavar='PATH',
                        help='Path to application entrypoint for dynamic analysis (e.g., app.py, main.py)')
    parser.add_argument('--init-config', action='store_true',
                        help='Create default configuration file at ~/.vulnreach/config/creds.yaml')


    args = parser.parse_args()

    # Handle both positional target and --target flag (--target takes precedence)
    if args.target_flag:
        args.target = args.target_flag


    # Handle config initialization
    if args.init_config:
        create_default_config()
        return


    # Validate arguments
    if not args.sbom and not args.target:
        print("❌ Error: Must specify either a target directory or --sbom file")
        parser.print_help()
        sys.exit(1)

    # Check prerequisites
    if not check_prerequisites(request_sast=args.run_sast):
        sys.exit(1)

    print("🚀 Starting Security Analysis with Syft and Trivy...")

    # Variables to track temporary directories for cleanup
    temp_clone_dir = None
    is_temp_clone = False
    exit_code = 0  # Initialize exit_code to avoid UnboundLocalError

    try:
        # Handle git repository cloning if target is a git URL
        actual_target = args.target
        if args.target and is_git_url(args.target):
            temp_clone_dir, is_temp_clone = clone_git_repository(args.target)
            if not temp_clone_dir:
                print("❌ Failed to clone git repository")
                sys.exit(1)
            actual_target = temp_clone_dir
        
        # Determine project name and create security_findings directory structure
        if actual_target:
            if is_git_url(args.target):
                project_name = extract_repo_name_from_url(args.target)
            else:
                project_name = get_project_name(actual_target)
        elif args.sbom:
            # If using existing SBOM, try to extract project name from SBOM path
            sbom_dir = os.path.dirname(os.path.abspath(args.sbom))
            project_name = get_project_name(sbom_dir)
        else:
            project_name = "unknown_project"

        # Create security_findings/project_name directory
        project_findings_dir = create_security_findings_dir(project_name)
        print(f"📁 Security findings will be saved to: {project_findings_dir}")

        # Update output paths to use the project findings directory
        if not args.output_report:
            args.output_report = os.path.join(project_findings_dir, "security_report.json")
        elif not os.path.isabs(args.output_report):
            args.output_report = os.path.join(project_findings_dir, args.output_report)

        if not args.output_consolidated:
            args.output_consolidated = os.path.join(project_findings_dir, "consolidated.json")
        elif not os.path.isabs(args.output_consolidated):
            args.output_consolidated = os.path.join(project_findings_dir, args.output_consolidated)

        if args.output_sbom and not os.path.isabs(args.output_sbom):
            args.output_sbom = os.path.join(project_findings_dir, args.output_sbom)

        if args.trivy_output and not os.path.isabs(args.trivy_output):
            args.trivy_output = os.path.join(project_findings_dir, args.trivy_output)

        # Initialize tools
        syft = SyftSBOMGenerator()
        trivy = TrivySCAScanner()

        print(f"📋 Syft version: {syft.check_syft_version()}")
        print(f"🛡️ Trivy version: {trivy.check_trivy_version()}")

        components = []
        vulnerabilities = []

        if args.direct_scan and actual_target:
            # Direct directory scan with Trivy (no SBOM)
            print("\n🎯 Performing direct vulnerability scan...")
            vulnerabilities = trivy.scan_directory(actual_target, args.trivy_output)

        elif args.sbom:
            # Use existing SBOM
            print(f"\n📄 Using existing SBOM: {args.sbom}")
            components = syft.parse_sbom_components(args.sbom)
            vulnerabilities = trivy.scan_sbom(args.sbom, args.trivy_output)

        else:
            # Generate SBOM first, then scan
            # Save SBOM to security_findings directory with repo name
            if not args.output_sbom:
                sbom_path = os.path.join(project_findings_dir, "sbom.json")
            else:
                sbom_path = args.output_sbom

            print(f"\n📋 Generating SBOM from: {actual_target}")
            if syft.generate_sbom(actual_target, sbom_path, args.sbom_format):
                components = syft.parse_sbom_components(sbom_path)
                vulnerabilities = trivy.scan_sbom(sbom_path, args.trivy_output)

                # SBOM now saved to security_findings directory - no deletion!
                print(f"💾 SBOM saved to: {sbom_path}")
            else:
                print("❌ Failed to generate SBOM")
                sys.exit(1)

        # Run correlation analysis (enrich vulnerabilities with static + dynamic evidence)
        # This runs by default but can be disabled with --no-correlation flag
        enable_correlation = not getattr(args, 'no_correlation', False)
        vulnerabilities = enrich_vulnerabilities_with_correlation(
            vulnerabilities,
            project_findings_dir,
            enable_correlation
        )

        # Calculate scan duration up to this point for the report
        scan_duration = time.time() - start_time
        
        # Generate security report
        print("\n📊 Generating security report...")
        report_path = args.output_report or "security_report.json"
        SecurityReporter.generate_report(components, vulnerabilities, report_path, scan_duration)

        print(f"\n💾 Full report saved to: {report_path}")

        # Build consolidated fixed-version recommendations from the report
        with open(report_path, 'r') as rf:
            report_json = json.load(rf)

        consolidated = consolidate_fixed_versions(report_json)

        with open(args.output_consolidated, 'w') as cf:
            json.dump(consolidated, cf, indent=2)

        print(f"🧩 Consolidated recommendations saved to: {args.output_consolidated}")

        # Run reachability analysis if requested
        reachability_completed = False
        if args.run_reachability:
            print("\n🔍 Running multi-language vulnerability reachability analysis...")
            detected_language = run_multi_language_analysis(actual_target or ".", args.output_consolidated, project_findings_dir)
            print(f"📊 Reachability analysis completed for {detected_language.upper()} project")
            reachability_completed = True
            
            # Generate Interactive HTML Report
            try:
                reach_json_path = os.path.join(project_findings_dir, f"{detected_language}_vulnerability_reachability_report.json")
                if os.path.exists(reach_json_path):
                   html_report_path = os.path.join(project_findings_dir, "report.html")
                   print(f"🎨 Generating interactive HTML report...")
                   with open(reach_json_path, 'r') as f:
                       reach_data = json.load(f)
                   HtmlReporter.generate(reach_data, html_report_path)
                   print(f"✅ HTML Report ready: {html_report_path}")
            except Exception as e:
                print(f"⚠️ Failed to generate HTML report: {e}")

        # Run Semgrep SAST if requested
        if args.run_sast:
            try:
                from vulnreach.utils.semgrep_runner import SemgrepRunner, SemgrepNotFoundError

                semgrep_output = os.path.join(project_findings_dir, "semgrep.json")
                runner = SemgrepRunner()
                runner.run_scan(actual_target or ".", semgrep_output, config=args.semgrep_rules)
                print(f"🧩 Semgrep findings saved to: {semgrep_output}")
            except SemgrepNotFoundError as err:
                print(f"⚠️  {err}")
            except Exception as err:
                print(f"❌ Semgrep scan failed: {err}")

        # Run route extraction if requested
        if args.run_routes:
            try:
                from vulnreach.utils.route_extractor import extract_and_save_routes

                routes_output = os.path.join(project_findings_dir, "routes.json")
                count = extract_and_save_routes(actual_target or ".", routes_output)
                print(f"🗺️  Extracted {count} routes to: {routes_output}")
            except Exception as err:
                print(f"⚠️  Route extraction failed: {err}")

        # Run taint analysis if requested
        taint_analysis_completed = False
        if args.run_taint_analysis:
            try:
                from vulnreach.agents.coordinator import AgentCoordinator

                print("\n🔬 Running Tainter taint analysis...")
                print("=" * 70)

                # Initialize coordinator
                coordinator = AgentCoordinator(actual_target or ".")

                # Parse vulnerability classes if specified
                vuln_classes = []
                if args.taint_vuln_classes:
                    vuln_classes = [vc.strip().upper() for vc in args.taint_vuln_classes.split(',')]
                    print(f"🎯 Focusing on vulnerability classes: {', '.join(vuln_classes)}")
                else:
                    print(f"🎯 Scanning for all vulnerability classes")

                # Run taint analysis
                taint_result = coordinator.run_taint_analysis(
                    vuln_classes=vuln_classes if vuln_classes else None,
                    include_tests=args.taint_include_tests
                )

                if taint_result['success']:
                    print(f"✅ Taint analysis complete!")
                    print(f"📊 Total flows detected: {taint_result['total_flows']}")
                    print(f"📁 Files analyzed: {taint_result['files_analyzed']}")
                    print(f"⏱️  Duration: {taint_result['summary'].get('duration_seconds', 0):.3f}s")

                    # Save taint analysis report
                    taint_report_path = os.path.join(project_findings_dir, "taint_analysis_report.json")
                    with open(taint_report_path, 'w') as f:
                        json.dump(taint_result, f, indent=2)

                    print(f"💾 Taint analysis report saved to: {taint_report_path}")

                    # Print summary by vulnerability class
                    if taint_result['flows']:
                        flows = taint_result['flows']
                        vuln_class_counts = {}
                        high_confidence_count = 0

                        for flow in flows:
                            vc = flow.get('vulnerability_class', 'UNKNOWN')
                            vuln_class_counts[vc] = vuln_class_counts.get(vc, 0) + 1
                            if flow.get('confidence', '').upper() == 'HIGH':
                                high_confidence_count += 1

                        print(f"\n📈 Flows by Vulnerability Class:")
                        for vc, count in sorted(vuln_class_counts.items(), key=lambda x: -x[1]):
                            print(f"   {vc:20s}: {count:3d} flows")

                        print(f"\n🚨 High confidence flows: {high_confidence_count}/{len(flows)}")

                        # Show top 3 critical flows
                        critical_flows = sorted(
                            [f for f in flows if f.get('confidence', '').upper() == 'HIGH'],
                            key=lambda f: f.get('vulnerability_class', '')
                        )[:3]

                        if critical_flows:
                            print(f"\n🔴 Sample Critical Flows:")
                            for i, flow in enumerate(critical_flows, 1):
                                file_name = os.path.basename(flow['sink']['location']['file'])
                                line_num = flow['sink']['location']['line']
                                print(f"   {i}. {flow['vulnerability_class']} - {flow['confidence']} confidence")
                                print(f"      → {file_name}:{line_num}")
                    else:
                        print(f"\n✅ No vulnerability flows detected!")

                    taint_analysis_completed = True
                    print("=" * 70)

                else:
                    error_msg = taint_result.get('error', 'Unknown error')
                    print(f"❌ Taint analysis failed: {error_msg}")

            except ImportError as e:
                print(f"⚠️  Taint analysis skipped: TainterAgent not available")
                print(f"   Error: {e}")
            except Exception as err:
                print(f"❌ Taint analysis failed: {err}")
                import traceback
                traceback.print_exc()

        # Run dynamic analysis if requested
        dynamic_results = None
        if args.run_dynamic:
            if not args.entrypoint:
                print("⚠️  Dynamic analysis requires --entrypoint flag (e.g., --entrypoint app.py)")
                print("   Skipping dynamic analysis...")
            else:
                print("\n" + "=" * 70)
                print("🔄 Starting Dynamic Analysis with Runtime Hooks")
                print("=" * 70)
                
                try:
                    # Run dynamic analysis pipeline
                    dynamic_results = run_dynamic_analysis_pipeline(
                        project_root=actual_target or ".",
                        entrypoint=args.entrypoint,
                        output_dir=project_findings_dir
                    )
                    
                    if dynamic_results and not dynamic_results.get("error"):
                        print("✅ Dynamic analysis completed successfully!")
                        print("=" * 70)
                    else:
                        print("⚠️  Dynamic analysis completed with errors")
                        
                except Exception as e:
                    print(f"❌ Dynamic analysis failed: {e}")
                    import traceback
                    traceback.print_exc()

        # Run correlation analysis (static + dynamic)
        correlated_findings = None
        if vulnerabilities and not args.no_correlation:
            try:
                # Convert vulnerabilities to dict format for correlation
                static_findings_dict = []
                for vuln in vulnerabilities:
                    vuln_dict = {
                        "vulnerability_id": vuln.vulnerability_id,
                        "pkg_name": vuln.pkg_name,
                        "pkg_version": vuln.pkg_version,
                        "severity": vuln.severity,
                        "title": vuln.title,
                        "description": vuln.description,
                        "cvss_score": vuln.cvss_score,
                        "cwe_ids": vuln.cwe_ids or [],
                        "fixed_version": vuln.fixed_version,
                    }
                    static_findings_dict.append(vuln_dict)
                
                # Run correlation
                correlated_findings = run_correlation_pipeline(
                    project_findings_dir=project_findings_dir,
                    static_findings=static_findings_dict,
                    dynamic_results=dynamic_results,
                    skip_correlation=args.no_correlation
                )
                
            except Exception as e:
                print(f"⚠️  Correlation analysis failed: {e}")
                import traceback
                traceback.print_exc()

        # Link Semgrep sinks to handlers/routes if requested
        reachability_engine_completed = False
        if args.run_reachability_engine:
            semgrep_output = os.path.join(project_findings_dir, "semgrep.json")
            engine_output = os.path.join(project_findings_dir, "sink_handler_reachability.json")
            if not os.path.exists(semgrep_output):
                print("⚠️  Reachability engine skipped: semgrep.json not found. Run with --run-sast.")
            else:
                try:
                    results = run_reachability_engine(actual_target or ".", project_findings_dir)
                    print(f"🧭 Reachability engine linked {len(results)} findings; saved to: {engine_output}")
                    reachability_engine_completed = True
                except Exception as err:
                    print(f"⚠️  Reachability engine failed: {err}")

        # Run exploitability analysis if requested
        exploitability_completed = False
        if args.run_exploitability and vulnerabilities:
            print("\n💥 Running exploitability analysis using SearchSploit...")
            exploit_analyzer = ExploitabilityAnalyzer()
            
            # Check if SearchSploit is available
            prereqs = exploit_analyzer.check_prerequisites()
            if not prereqs["searchsploit_available"]:
                print("⚠️  SearchSploit not found. Exploitability analysis will be limited.")
                print("   Install SearchSploit: apt update && apt install exploitdb")
            
            # Filter vulnerabilities based on reachability analysis if available
            filtered_vulnerabilities = vulnerabilities
            if reachability_completed:
                # Load reachability analysis results to filter out NOT_REACHABLE vulnerabilities
                reachable_packages = {}  # package_name -> (version, criticality) mapping
                reachability_report_paths = [
                    os.path.join(project_findings_dir, "vulnerability_reachability_report.json"),
                    os.path.join(project_findings_dir, "python_vulnerability_reachability_report.json"),
                    os.path.join(project_findings_dir, "php_vulnerability_reachability_report.json"),
                    os.path.join(project_findings_dir, "csharp_vulnerability_reachability_report.json"),
                    os.path.join(project_findings_dir, "go_vulnerability_reachability_report.json"),
                    os.path.join(project_findings_dir, "java_vulnerability_reachability_report.json"),
                    os.path.join(project_findings_dir, "javascript_vulnerability_reachability_report.json")
                ]
                
                for reachability_path in reachability_report_paths:
                    if os.path.exists(reachability_path):
                        try:
                            with open(reachability_path, 'r') as f:
                                reachability_data = json.load(f)
                            
                            # Extract packages and versions, filtering out NOT_REACHABLE
                            for vuln in reachability_data.get("vulnerabilities", []):
                                package_name = vuln.get("package_name", "").lower()
                                installed_version = vuln.get("installed_version", "")
                                criticality = vuln.get("criticality", "")

                                # Skip NOT_REACHABLE vulnerabilities - they're not actively used!
                                if criticality != "NOT_REACHABLE" and package_name and installed_version:
                                    reachable_packages[package_name] = (installed_version, criticality)

                            print(f"📊 Found reachability analysis with {len(reachability_data.get('vulnerabilities', []))} packages")
                            break
                        except Exception as e:
                            print(f"⚠️  Warning: Could not load reachability data from {reachability_path}: {e}")
                
                if reachable_packages:
                    # Filter vulnerabilities to only include reachable ones (excluding NOT_REACHABLE)
                    original_count = len(vulnerabilities)
                    filtered_vulnerabilities = []
                    not_reachable_count = 0

                    for vuln in vulnerabilities:
                        package_key = vuln.pkg_name.lower()
                        if package_key in reachable_packages:
                            version, criticality = reachable_packages[package_key]
                            if vuln.pkg_version == version:
                                filtered_vulnerabilities.append(vuln)
                        else:
                            # Track skipped vulnerabilities
                            not_reachable_count += 1

                    filtered_count = len(filtered_vulnerabilities)
                    print(f"🔍 Filtering exploit analysis:")
                    print(f"   Total vulnerabilities: {original_count}")
                    print(f"   Reachable (CRITICAL/HIGH/MEDIUM/LOW): {filtered_count}")
                    print(f"   Skipped (NOT_REACHABLE): {not_reachable_count}")
                    print(f"   ⚡ Focusing on {filtered_count} reachable vulnerabilities for exploit search")
                else:
                    print("⚠️  No reachability analysis packages found, analyzing all vulnerabilities")
            
            # Convert filtered vulnerabilities to the format expected by the analyzer
            vuln_data = []
            for vuln in filtered_vulnerabilities:
                vuln_dict = {
                    'vulnerability_id': vuln.vulnerability_id,
                    'pkg_name': vuln.pkg_name,
                    'pkg_version': vuln.pkg_version,
                    'severity': vuln.severity,
                    'cvss_score': vuln.cvss_score
                }
                vuln_data.append(vuln_dict)
            
            if vuln_data:
                # Perform exploitability analysis
                exploit_analyses = exploit_analyzer.analyze_vulnerability_batch(vuln_data)
                
                # Generate exploitability report
                exploit_report_path = os.path.join(project_findings_dir, "exploitability_report.json")
                exploit_analyzer.generate_exploitability_report(exploit_analyses, exploit_report_path)
                
                # Print summary
                exploit_analyzer.print_exploitability_summary(exploit_analyses)
                
                print(f"💥 Exploitability report saved to: {exploit_report_path}")
                exploitability_completed = True
            else:
                print("💥 No reachable vulnerabilities found for exploit analysis")
                exploitability_completed = False
        elif args.run_exploitability and not vulnerabilities:
            print("\n💥 No vulnerabilities found - skipping exploitability analysis")


        # Generate RBOM if requested
        if args.generate_rbom:
            print("\n🛡️  Generating Runtime Bill of Materials (RBOM)...")
            try:
                # Convert vulnerability dataclasses to dict format for RBOM
                vuln_dicts = []
                for vuln in vulnerabilities:
                    vuln_dict = {
                        'vulnerability_id': vuln.vulnerability_id,
                        'pkg_name': vuln.pkg_name,
                        'pkg_version': vuln.pkg_version,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'fixed_version': vuln.fixed_version
                    }
                    vuln_dicts.append(vuln_dict)

                # Load runtime events if available (from runtime_hooks)
                runtime_events = None
                runtime_events_path = os.path.join(project_findings_dir, "runtime_events.json")
                if os.path.exists(runtime_events_path):
                    with open(runtime_events_path, 'r') as f:
                        runtime_events = json.load(f)
                    print(f"   ✅ Found runtime events: {len(runtime_events)} events")

                # Load exploitability results if available
                exploitability_results = None
                exploit_report_path = os.path.join(project_findings_dir, "exploitability_report.json")
                if os.path.exists(exploit_report_path):
                    with open(exploit_report_path, 'r') as f:
                        exploit_data = json.load(f)
                        exploitability_results = exploit_data.get('vulnerabilities', [])
                    print(f"   ✅ Found exploitability data: {len(exploitability_results)} vulnerabilities")

                # Detect language
                detected_language = None
                if hasattr(args, '_detected_language'):
                    detected_language = args._detected_language
                elif reachability_completed:
                    # Try to infer from reachability analysis
                    detected_language = "python"  # Default assumption

                # Build correlation results for sophisticated analysis
                correlation_results = {}
                if runtime_events:
                    correlation_results['runtime_events'] = runtime_events

                # Create RBOM with full correlation pipeline
                from vulnreach.rbom import RBOMBuilder

                builder = RBOMBuilder()
                builder.set_target(
                    path=actual_target or ".",
                    target_type="directory",
                    language=detected_language
                )

                # Add SBOM components
                builder.add_sbom_components([c.__dict__ if hasattr(c, '__dict__') else c for c in components])

                # Add vulnerabilities
                builder.add_vulnerabilities(vuln_dicts)

                # Add runtime evidence (uses Phase 2 event matcher)
                if runtime_events:
                    builder.add_runtime_evidence(runtime_events)

                # Add exploitability
                if exploitability_results:
                    builder.add_exploitability_analysis(exploitability_results)

                # Update reachability verdicts (uses Phase 4 CVE mapper)
                builder.update_reachability_verdicts(correlation_results)

                # Build RBOM
                rbom = builder.build()

                # Save RBOM in all formats
                from vulnreach.rbom import save_rbom
                save_rbom(rbom, project_findings_dir, base_name="rbom")

                print(f"\n✅ RBOM generated successfully!")
                print(f"   📄 JSON: {os.path.join(project_findings_dir, 'rbom.json')}")
                print(f"   📝 Report: {os.path.join(project_findings_dir, 'rbom_report.md')}")

                # Print enhanced statistics
                stats = rbom.get_statistics()
                if stats.get('runtime_loaded_components', 0) > 0:
                    print(f"\n📊 RBOM Statistics:")
                    print(f"   • Runtime loaded: {stats['runtime_loaded_components']}/{stats['total_components']} ({stats['runtime_load_percentage']:.1f}%)")
                    print(f"   • Reachable vulnerabilities: {stats['reachable_vulnerabilities']}/{stats['total_vulnerabilities']}")
                    if stats.get('false_positive_reduction', 0) > 0:
                        print(f"   • False positive reduction: {stats['false_positive_reduction']:.1f}%")

            except Exception as e:
                print(f"\n⚠️  RBOM generation failed: {e}")
                import traceback
                traceback.print_exc()

        # Print completion summary for individual analysis types
        if reachability_completed and exploitability_completed:
            print(f"\n📁 All analysis reports saved to: {project_findings_dir}")

        # Exit with appropriate code based on findings
        critical_high_vulns = len([v for v in vulnerabilities
                                   if v.severity in ['CRITICAL', 'HIGH']])

        # Calculate final scan duration
        final_scan_duration = time.time() - start_time
        
        if critical_high_vulns > 0:
            print(f"\n🚨 Found {critical_high_vulns} CRITICAL/HIGH vulnerabilities!")
            print(f"\n⏱️  Total scan duration: {final_scan_duration:.2f} seconds")
            exit_code = 1
        elif vulnerabilities:
            print(f"\n⚠️  Found {len(vulnerabilities)} vulnerabilities (MEDIUM/LOW)")
            print(f"\n⏱️  Total scan duration: {final_scan_duration:.2f} seconds")
            exit_code = 0
        else:
            print("\n✅ No vulnerabilities found!")
            print(f"\n⏱️  Total scan duration: {final_scan_duration:.2f} seconds")
            exit_code = 0

    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        exit_code = 130
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        exit_code = 1
    finally:
        # Clean up temporary git clone directory
        if is_temp_clone and temp_clone_dir and os.path.exists(temp_clone_dir):
            try:
                print(f"🧹 Cleaning up temporary clone directory: {temp_clone_dir}")
                shutil.rmtree(temp_clone_dir, ignore_errors=True)
            except Exception as e:
                print(f"⚠️  Warning: Failed to clean up temporary directory: {e}")
        
        sys.exit(exit_code)


if __name__ == "__main__":
    main()


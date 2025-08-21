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

import os
import json
import sys
import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import requests
from utils.vuln_reachability_analyzer import run_reachability_analysis
from utils.multi_language_analyzer import run_multi_language_analysis


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
                "--quiet"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"❌ Syft failed: {result.stderr}")
                return False

            print(f"✅ SBOM generated successfully: {output_path}")
            return True

        except Exception as e:
            print(f"❌ Error generating SBOM: {e}")
            return False

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
                        output_path: str = None) -> Dict:
        """Generate comprehensive security report"""

        # Organize vulnerabilities by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        vulnerable_packages = set()

        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
            vulnerable_packages.add(f"{vuln.pkg_name}@{vuln.pkg_version}")

        report = {
            "scan_timestamp": datetime.now().isoformat(),
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
                    "primary_url": vuln.primary_url
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

        print(f"📊 Scan completed at: {report['scan_timestamp']}")
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
                if vuln['fixed_version']:
                    print(f"   🔧 Fixed in: {vuln['fixed_version']}")
                print()

        if summary['total_vulnerabilities'] == 0:
            print("✅ No vulnerabilities found! Your dependencies are secure.")
        else:
            print("⚠️  Please review and remediate the vulnerabilities above.")

        print("=" * 80)


def check_prerequisites():
    """Check if required tools are installed"""
    missing_tools = []

    if not shutil.which('syft'):
        missing_tools.append("Syft")

    if not shutil.which('trivy'):
        missing_tools.append("Trivy")

    if missing_tools:
        print("❌ Missing required tools:")
        for tool in missing_tools:
            print(f"   - {tool}")
        print("\nInstallation instructions:")
        print(
            "Syft: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin")
        print("Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
        return False

    return True

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
        if pkg and fv:
            fixed.setdefault(pkg, []).append(fv)

    out = []
    for pkg, fixes in fixed.items():
        fixes_unique_sorted = sorted(set(fixes), key=version_key)
        best = fixes_unique_sorted[-1] if fixes_unique_sorted else None
        current = installed.get(pkg)
        upgrade_needed = bool(best and current and version_key(current) < version_key(best))
        out.append({
            "package_name": pkg,
            "installed_version": current,
            "recommended_fixed_version": best,
            "all_seen_fixed_versions": fixes_unique_sorted,
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


def main():
    parser = argparse.ArgumentParser(
        description='Security SCA Tool using Syft and Trivy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan directory with SBOM generation
  %(prog)s /path/to/project --output-report security_report.json

  # Use existing SBOM file
  %(prog)s --sbom existing_sbom.json --output-report report.json

  # Generate and save SBOM, then scan
  %(prog)s /path/to/project --output-sbom sbom.json --output-report report.json

  # Direct directory scan (no SBOM generation)
  %(prog)s /path/to/project --direct-scan
        """
    )

    parser.add_argument('target', nargs='?', help='Directory to scan (if not using --sbom)')
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

    args = parser.parse_args()

    # Validate arguments
    if not args.sbom and not args.target:
        print("❌ Error: Must specify either a target directory or --sbom file")
        parser.print_help()
        sys.exit(1)

    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)

    print("🚀 Starting Security Analysis with Syft and Trivy...")

    try:
        # Determine project name and create security_findings directory structure
        if args.target:
            project_name = get_project_name(args.target)
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

        if args.direct_scan and args.target:
            # Direct directory scan with Trivy (no SBOM)
            print("\n🎯 Performing direct vulnerability scan...")
            vulnerabilities = trivy.scan_directory(args.target, args.trivy_output)

        elif args.sbom:
            # Use existing SBOM
            print(f"\n📄 Using existing SBOM: {args.sbom}")
            components = syft.parse_sbom_components(args.sbom)
            vulnerabilities = trivy.scan_sbom(args.sbom, args.trivy_output)

        else:
            # Generate SBOM first, then scan
            sbom_path = args.output_sbom or "temp_sbom.json"
            temp_sbom = not args.output_sbom

            print(f"\n📋 Generating SBOM from: {args.target}")
            if syft.generate_sbom(args.target, sbom_path, args.sbom_format):
                components = syft.parse_sbom_components(sbom_path)
                vulnerabilities = trivy.scan_sbom(sbom_path, args.trivy_output)

                # Clean up temporary SBOM
                if temp_sbom:
                    try:
                        os.unlink(sbom_path)
                    except:
                        pass
            else:
                print("❌ Failed to generate SBOM")
                sys.exit(1)

        # Generate security report
        print("\n📊 Generating security report...")
        report_path = args.output_report or "security_report.json"
        SecurityReporter.generate_report(components, vulnerabilities, report_path)

        print(f"\n💾 Full report saved to: {report_path}")

        # Build consolidated fixed-version recommendations from the report
        with open(report_path, 'r') as rf:
            report_json = json.load(rf)

        consolidated = consolidate_fixed_versions(report_json)

        with open(args.output_consolidated, 'w') as cf:
            json.dump(consolidated, cf, indent=2)

        print(f"🧩 Consolidated recommendations saved to: {args.output_consolidated}")
        print(f"🧩 Consolidated recommendations saved to: {args.output_consolidated}")

        # Run reachability analysis if requested
        if args.run_reachability:
            print("\n🔍 Running multi-language vulnerability reachability analysis...")
            detected_language = run_multi_language_analysis(args.target or ".", args.output_consolidated, project_findings_dir)
            print(f"📊 Reachability analysis completed for {detected_language.upper()} project")
            print(f"📁 Reports saved to: {project_findings_dir}")

        # Exit with appropriate code based on findings
        critical_high_vulns = len([v for v in vulnerabilities
                                   if v.severity in ['CRITICAL', 'HIGH']])

        if critical_high_vulns > 0:
            print(f"\n🚨 Found {critical_high_vulns} CRITICAL/HIGH vulnerabilities!")
            sys.exit(1)
        elif vulnerabilities:
            print(f"\n⚠️  Found {len(vulnerabilities)} vulnerabilities (MEDIUM/LOW)")
            sys.exit(0)
        else:
            print("\n✅ No vulnerabilities found!")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


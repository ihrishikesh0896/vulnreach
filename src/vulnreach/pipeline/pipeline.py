"""VulnReach Pipeline Orchestrator

Coordinates the complete vulnerability analysis flow:
1. SBOM Generation → SCA Scanning → Exploit Analysis
2. Static Taint Analysis
3. Container Detection → Dynamic Analysis (conditional)
4. Correlation (Static ↔ Dynamic)
5. Unified Output Generation
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

# Import existing components
from vulnreach.tracer_ import SyftSBOMGenerator, TrivySCAScanner
from vulnreach.utils.exploitability_analyzer import ExploitabilityAnalyzer
from vulnreach.taint.static_taint import analyze_project_taint
from vulnreach.pipeline.container_detector import ContainerDetector
from vulnreach.runtime.dynamic_analyzer import DynamicAnalyzer, ContainerDynamicAnalyzer
from vulnreach.correlation.correlator import FindingCorrelator


@dataclass
class PipelineConfig:
    """Pipeline configuration"""
    enable_sbom: bool = True
    enable_sca: bool = True
    enable_exploitability: bool = True
    enable_static_taint: bool = True
    enable_dynamic: bool = True  # Auto-disabled if not containerized
    enable_correlation: bool = True
    sbom_format: str = 'spdx-json'
    output_dir: Optional[str] = None
    docker_image: Optional[str] = None
    use_container: bool = False


class VulnReachPipeline:
    """Main pipeline orchestrator"""
    
    def __init__(self, project_root: str, config: Optional[PipelineConfig] = None):
        self.project_root = Path(project_root).resolve()
        self.config = config or PipelineConfig()
        
        # Create output directory
        if self.config.output_dir:
            self.output_dir = Path(self.config.output_dir)
        else:
            self.output_dir = Path("security_findings") / self.project_root.name
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Results containers
        self.sbom_path = None
        self.components = []
        self.vulnerabilities = []
        self.exploitability_results = []
        self.taint_flows = {}
        self.dynamic_results = None
        self.correlated_findings = []
        
    def run_full_analysis(self) -> Dict[str, Any]:
        """
        Run complete analysis pipeline
        
        Returns:
            Analysis results with path to unified findings file
        """
        start_time = time.time()
        
        print("\n" + "=" * 70)
        print("🚀 VulnReach Full Security Analysis Pipeline")
        print("=" * 70)
        print(f"📁 Project: {self.project_root}")
        print(f"📊 Output: {self.output_dir}")
        print("=" * 70)
        
        try:
            # Phase 1: Static Analysis
            self._run_static_phase()
            
            # Phase 2: Dynamic Analysis (conditional)
            self._run_dynamic_phase()
            
            # Phase 3: Correlation
            if self.config.enable_correlation:
                self._run_correlation_phase()
            
            # Phase 4: Generate Unified Output
            output_path = self._generate_unified_output()
            
            duration = time.time() - start_time
            
            print("\n" + "=" * 70)
            print("✅ Analysis Complete!")
            print("=" * 70)
            print(f"⏱️  Duration: {duration:.2f} seconds")
            print(f"📄 Unified findings: {output_path}")
            print("=" * 70)
            
            return {
                'success': True,
                'output_path': str(output_path),
                'duration': duration,
                'summary': self._generate_summary()
            }
            
        except Exception as e:
            print(f"\n❌ Pipeline failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }
    
    def _run_static_phase(self):
        """Run static analysis phase"""
        print("\n" + "=" * 70)
        print("📊 Phase 1: Static Analysis")
        print("=" * 70)
        
        # 1.1 SBOM Generation
        if self.config.enable_sbom:
            print("\n1️⃣ Generating SBOM...")
            self.sbom_path = self.output_dir / "sbom.json"
            
            syft = SyftSBOMGenerator()
            if syft.generate_sbom(str(self.project_root), str(self.sbom_path), self.config.sbom_format):
                self.components = syft.parse_sbom_components(str(self.sbom_path))
                print(f"   ✅ SBOM generated: {len(self.components)} components")
            else:
                print("   ❌ SBOM generation failed")
                raise RuntimeError("SBOM generation failed")
        
        # 1.2 SCA Scanning
        if self.config.enable_sca and self.sbom_path:
            print("\n2️⃣ Running SCA scan...")
            trivy = TrivySCAScanner()
            trivy_output = self.output_dir / "trivy_output.json"
            self.vulnerabilities = trivy.scan_sbom(str(self.sbom_path), str(trivy_output))
            print(f"   ✅ Found {len(self.vulnerabilities)} vulnerabilities")
        
        # 1.3 Exploit Analysis
        if self.config.enable_exploitability and self.vulnerabilities:
            print("\n3️⃣ Analyzing exploitability...")
            try:
                analyzer = ExploitabilityAnalyzer()
                
                # Convert vulnerabilities to dict format
                vuln_dicts = []
                for vuln in self.vulnerabilities:
                    vuln_dicts.append({
                        'vulnerability_id': vuln.vulnerability_id,
                        'pkg_name': vuln.pkg_name,
                        'pkg_version': vuln.pkg_version,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score
                    })
                
                self.exploitability_results = analyzer.analyze_vulnerability_batch(vuln_dicts)
                
                exploit_report = self.output_dir / "exploitability_report.json"
                analyzer.generate_exploitability_report(self.exploitability_results, str(exploit_report))
                print(f"   ✅ Exploitability analysis complete")
            except Exception as e:
                print(f"   ⚠️  Exploitability analysis failed: {e}")
        
        # 1.4 Static Taint Analysis
        if self.config.enable_static_taint:
            print("\n4️⃣ Running static taint analysis...")
            try:
                # Convert vulnerabilities to dict format
                vuln_dicts = []
                for vuln in self.vulnerabilities:
                    vuln_dicts.append({
                        'pkg_name': vuln.pkg_name,
                        'pkg_version': vuln.pkg_version,
                        'vulnerability_id': vuln.vulnerability_id
                    })
                
                taint_output = self.output_dir / "static_taint_flows.json"
                self.taint_flows = analyze_project_taint(
                    str(self.project_root),
                    vuln_dicts,
                    str(taint_output)
                )
                print(f"   ✅ Found taint flows for {len(self.taint_flows)} packages")
            except Exception as e:
                print(f"   ⚠️  Static taint analysis failed: {e}")
                import traceback
                traceback.print_exc()
    
    def _run_dynamic_phase(self):
        """Run dynamic analysis phase (conditional on container detection)"""
        if not self.config.enable_dynamic:
            print("\n⏭️  Skipping dynamic analysis (disabled)")
            return
        
        print("\n" + "=" * 70)
        print("🔄 Phase 2: Dynamic Analysis")
        print("=" * 70)
        
        # 2.1 Container Detection
        print("\n1️⃣ Detecting container setup...")
        detector = ContainerDetector(str(self.project_root))
        container_info = detector.detect()
        detector.print_detection_summary(container_info)
        
        # 2.2 Conditional Dynamic Analysis
        if not container_info.is_containerized:
            print("\n⏭️  Skipping dynamic analysis - app not containerized")
            return
        
        if not detector.can_run_dynamic_analysis(container_info):
            print("\n⏭️  Skipping dynamic analysis - no run instructions found")
            return
        
        # Find entrypoint
        entrypoint = container_info.entrypoint

        # If entrypoint is provided, resolve it
        if entrypoint:
            # Handle relative paths from container detector
            if not os.path.isabs(entrypoint):
                entry_path = self.project_root / entrypoint
                if entry_path.exists():
                    entrypoint = str(entry_path)
                else:
                    # Try common subdirectories
                    for subdir in ['src', 'app', '.']:
                        entry_path = self.project_root / subdir / entrypoint
                        if entry_path.exists():
                            entrypoint = str(entry_path)
                            break

        # If still no entrypoint, search for common Python entrypoints
        if not entrypoint or not os.path.exists(entrypoint):
            print("   🔍 Searching for Python entrypoint...")
            found = False
            for subdir in ['src', 'app', '.']:
                for possible_entry in ['app.py', 'main.py', 'server.py', 'run.py', '__main__.py']:
                    entry_path = self.project_root / subdir / possible_entry
                    if entry_path.exists():
                        entrypoint = str(entry_path)
                        print(f"   ✅ Found entrypoint: {entrypoint}")
                        found = True
                        break
                if found:
                    break

        if not entrypoint or not os.path.exists(entrypoint):
            print("\n⏭️  Skipping dynamic analysis - no valid entrypoint found")
            return
        
        # 2.3 Run Dynamic Analysis
        print(f"\n2️⃣ Running dynamic analysis with entrypoint: {entrypoint}")
        try:
            dynamic_output = self.output_dir / "dynamic_findings.json"

            if self.config.use_container and self.config.docker_image:
                analyzer = ContainerDynamicAnalyzer(str(self.project_root))
                relative_entrypoint = os.path.relpath(entrypoint, self.project_root)
                build_ctx = str(self.project_root) if container_info.has_dockerfile else None
                self.dynamic_results = analyzer.run_container_analysis(
                    self.config.docker_image,
                    relative_entrypoint,
                    str(dynamic_output),
                    build_context=build_ctx
                )
            else:
                analyzer = DynamicAnalyzer(str(self.project_root))
                self.dynamic_results = analyzer.run_dynamic_analysis(entrypoint, str(dynamic_output))

            if self.dynamic_results and not self.dynamic_results.get('error'):
                summary = self.dynamic_results.get('summary', {})
                print(f"   ✅ Dynamic analysis complete")
                print(f"   📊 Findings: {summary.get('total_findings', 0)}")
            else:
                print(f"   ⚠️  Dynamic analysis completed with errors")
        except Exception as e:
            print(f"   ⚠️  Dynamic analysis failed: {e}")
            import traceback
            traceback.print_exc()


    def _run_correlation_phase(self):
        """Run correlation between static and dynamic findings"""
        print("\n" + "=" * 70)
        print("🔗 Phase 3: Correlation Analysis")
        print("=" * 70)
        
        if not self.vulnerabilities:
            print("⏭️  No vulnerabilities to correlate")
            return
        
        # Convert vulnerabilities to dict format
        static_findings = []
        for vuln in self.vulnerabilities:
            static_findings.append({
                'vulnerability_id': vuln.vulnerability_id,
                'pkg_name': vuln.pkg_name,
                'pkg_version': vuln.pkg_version,
                'severity': vuln.severity,
                'title': vuln.title,
                'description': vuln.description,
                'cvss_score': vuln.cvss_score,
                'cwe_ids': vuln.cwe_ids or [],
                'fixed_version': vuln.fixed_version
            })
        
        # Run correlation
        correlator = FindingCorrelator(str(self.output_dir))
        self.correlated_findings = correlator.correlate_findings(static_findings, self.dynamic_results)
        
        # Save correlation results
        corr_output = self.output_dir / "correlated_findings.json"
        correlator.save_correlated_findings(self.correlated_findings, str(corr_output))
        
        print(f"✅ Correlated {len(self.correlated_findings)} findings")
    
    def _generate_unified_output(self) -> Path:
        """Generate unified findings file"""
        print("\n" + "=" * 70)
        print("📝 Phase 4: Generating Unified Output")
        print("=" * 70)
        
        unified_findings = {
            'metadata': {
                'project_name': self.project_root.name,
                'project_root': str(self.project_root),
                'scan_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'tools_used': self._get_tools_used(),
                'analysis_types': self._get_analysis_types()
            },
            'summary': self._generate_summary(),
            'findings': self._build_unified_findings()
        }
        
        output_path = self.output_dir / "complete_findings.json"
        with open(output_path, 'w') as f:
            json.dump(unified_findings, f, indent=2)
        
        print(f"✅ Unified findings saved: {output_path}")
        return output_path
    
    def _build_unified_findings(self) -> List[Dict[str, Any]]:
        """Build unified findings list"""
        findings = []
        
        # Create exploit lookup
        exploit_lookup = {}
        for exploit_result in self.exploitability_results:
            cve_id = exploit_result.cve_id
            exploit_lookup[cve_id] = {
                'has_public_exploits': exploit_result.has_public_exploits,
                'exploit_count': exploit_result.exploit_count,
                'exploits': [asdict(e) for e in exploit_result.exploits_found],
                'risk_level': exploit_result.exploit_risk_level
            }
        
        # Process each vulnerability
        for vuln in self.vulnerabilities:
            # Get taint flows for this package
            pkg_taint_flows = self.taint_flows.get(vuln.pkg_name, [])
            
            # Get exploitability info
            exploit_info = exploit_lookup.get(vuln.vulnerability_id, {
                'has_public_exploits': False,
                'exploit_count': 0,
                'exploits': [],
                'risk_level': 'UNKNOWN'
            })
            
            # Get correlation verdict if available
            verdict = "POSSIBLE"
            confidence = "LOW"
            dynamic_evidence = None
            
            if self.correlated_findings:
                for corr in self.correlated_findings:
                    if corr.vulnerability_id == vuln.vulnerability_id:
                        verdict = corr.verdict
                        confidence = corr.confidence
                        dynamic_evidence = corr.dynamic_evidence
                        break
            
            # Build taint flow structure - simplified format per user spec
            taint_flow_dict = {}
            affected_files = set()

            if pkg_taint_flows:
                taint_flow_dict[vuln.pkg_name] = []
                for flow in pkg_taint_flows:
                    # Add simplified source -> sink mapping
                    taint_flow_dict[vuln.pkg_name].append({
                        'source': flow.source.source_expr,
                        'sink': flow.sink.sink_expr,
                        # Extended info for debugging
                        'source_file': flow.source.file_path,
                        'source_line': flow.source.line_number,
                        'sink_file': flow.sink.file_path,
                        'sink_line': flow.sink.line_number,
                        'confidence': flow.confidence
                    })
                    affected_files.add(flow.sink.file_path)

            # Populate filename from taint flows or dynamic evidence
            filename = ''
            if affected_files:
                # Use the first affected file
                filename = list(affected_files)[0]
            elif dynamic_evidence and dynamic_evidence.get('files_affected'):
                filename = dynamic_evidence.get('files_affected', [{}])[0].get('file', '')

            # Build unified finding - matching user's exact format
            finding = {
                'finding_id': f"{vuln.pkg_name}_{vuln.vulnerability_id}",
                'filename': filename,
                'vulnerable_package': vuln.pkg_name,
                'package_version': vuln.pkg_version,
                'fixed_version': [vuln.fixed_version] if vuln.fixed_version else [],  # User spec says 'fixed_version' not 'fixed_versions'
                'cve_ids': [vuln.vulnerability_id],
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'cwe_ids': vuln.cwe_ids or [],
                'description': vuln.description,
                
                # User's required fields
                'public_external_exploits': exploit_info['exploits'],
                'taint_flow': taint_flow_dict,  # User spec says 'taint_flow' not 'taint_flows'

                # Additional useful fields
                'has_public_exploits': exploit_info['has_public_exploits'],
                'exploit_risk_level': exploit_info['risk_level'],
                'verdict': verdict,
                'confidence': confidence,
                'dynamic_evidence': dynamic_evidence
            }
            
            findings.append(finding)
        
        return findings
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate analysis summary"""
        summary = {
            'total_components': len(self.components),
            'total_vulnerabilities': len(self.vulnerabilities),
            'total_findings': len(self.vulnerabilities)
        }
        
        # Count by severity
        by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1
        summary['by_severity'] = by_severity
        
        # Count by verdict if correlation was run
        if self.correlated_findings:
            by_verdict = {}
            for corr in self.correlated_findings:
                verdict = corr.verdict
                by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
            summary['by_verdict'] = by_verdict
        
        # Taint flow stats
        summary['packages_with_taint_flows'] = len(self.taint_flows)
        summary['total_taint_flows'] = sum(len(flows) for flows in self.taint_flows.values())
        
        # Dynamic analysis status
        summary['dynamic_analysis_run'] = self.dynamic_results is not None
        
        return summary
    
    def _get_tools_used(self) -> List[str]:
        """Get list of tools used"""
        tools = []
        if self.config.enable_sbom:
            tools.append('Syft')
        if self.config.enable_sca:
            tools.append('Trivy')
        if self.config.enable_exploitability:
            tools.append('SearchSploit')
        if self.config.enable_static_taint:
            tools.append('Static Taint Analyzer')
        if self.dynamic_results:
            tools.append('Runtime Hooks')
        if self.config.enable_correlation:
            tools.append('Correlation Engine')
        return tools
    
    def _get_analysis_types(self) -> List[str]:
        """Get list of analysis types performed"""
        types = []
        if self.config.enable_sbom:
            types.append('SBOM')
        if self.config.enable_sca:
            types.append('SCA')
        if self.config.enable_exploitability:
            types.append('Exploitability')
        if self.config.enable_static_taint:
            types.append('Static Taint')
        if self.dynamic_results:
            types.append('Dynamic Taint')
        if self.config.enable_correlation:
            types.append('Correlation')
        return types


def run_vulnreach_pipeline(project_root: str, config: Optional[PipelineConfig] = None) -> Dict[str, Any]:
    """
    Convenience function to run VulnReach pipeline
    
    Args:
        project_root: Root directory of the project
        config: Optional pipeline configuration
        
    Returns:
        Pipeline results
    """
    pipeline = VulnReachPipeline(project_root, config)
    return pipeline.run_full_analysis()

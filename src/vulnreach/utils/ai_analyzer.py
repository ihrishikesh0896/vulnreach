#!/usr/bin/env python3
"""
AI-Powered Vulnerability Analysis Module

Integrates basic vulnerability scanning, reachability analysis, and exploitability analysis
to provide intelligent security recommendations using AI/LLM providers.
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from pathlib import Path
import requests

from ..config import get_config_loader, VulnReachConfig, ProviderConfig
logger = logging.getLogger(__name__)


@dataclass
class AIAnalysisResult:
    """Result of AI-powered vulnerability analysis"""
    vulnerability_id: str
    package_name: str
    package_version: str
    severity: str
    reachability_status: str
    exploitability_risk: str
    ai_priority_score: float  # 0-10 scale
    ai_recommendation: str
    reasoning: str
    remediation_steps: List[str]
    estimated_effort: str  # LOW, MEDIUM, HIGH
    business_impact: str
    technical_complexity: str
    # New fields: short-term and long-term actions + risk summary (optional)
    short_term_actions: List[str] = field(default_factory=list)
    long_term_actions: List[str] = field(default_factory=list)
    risk_associated: Optional[str] = None


@dataclass
class AIAnalysisSummary:
    """Summary of AI analysis results"""
    total_vulnerabilities: int
    critical_recommendations: int
    high_priority_actions: int
    medium_priority_actions: int
    low_priority_actions: int
    overall_security_score: float  # 0-100 scale
    top_recommendations: List[str]
    security_trends: Dict[str, Any]
    compliance_considerations: List[str]


class AIVulnerabilityAnalyzer:
    """
    FastAPI-based LLM proxy that sends vulnerability analysis requests to a local OSS LLM server
    (e.g., Ollama at http://localhost:11434/api/generate)

    Features:
    - Accepts structured package vulnerability data
    - Builds prompts requesting short-term and long-term fixes
    - Calls local model endpoint with retries and timeouts
    - Safe validation, mock mode for offline testing
    """

    def __init__(self, config: Optional[VulnReachConfig] = None):
        """
        Initialize AI analyzer
        
        Args:
            config: Optional VulnReach configuration. If None, loads from default location.
        """
        if config is None:
            config_loader = get_config_loader()
            config = config_loader.get_config()
        
        self.config = config
        self.analysis_timestamp = datetime.now().isoformat()
        
        # LLM configuration
        self.llm_host = os.getenv("LLM_HOST", "http://localhost:11434")
        self.llm_generate_path = os.getenv("LLM_GENERATE_PATH", "/api/generate")
        self.llm_url = self.llm_host.rstrip('/') + self.llm_generate_path
        self.default_timeout = int(os.getenv("LLM_TIMEOUT", "60"))
        self.retry_count = int(os.getenv("LLM_RETRIES", "2"))
        self.mock_mode = os.getenv("VULNREACH_AI_MOCK", "0") == "1"

    def analyze_integrated_results(self,
                                 vulnerability_data: List[Dict],
                                 reachability_data: Dict,
                                 exploitability_data: Dict) -> Tuple[List[AIAnalysisResult], AIAnalysisSummary]:
        """
        Perform comprehensive AI analysis of integrated security results
        
        Args:
            vulnerability_data: Basic vulnerability scan results
            reachability_data: Reachability analysis results
            exploitability_data: Exploitability analysis results
            
        Returns:
            Tuple of (individual analyses, summary)
        """
        logger.info("Starting AI-powered vulnerability analysis...")
        
        # Integrate all data sources
        integrated_vulnerabilities = self._integrate_vulnerability_data(
            vulnerability_data, reachability_data, exploitability_data
        )
        
        # Perform AI analysis on each integrated vulnerability
        ai_analyses = []
        for vuln in integrated_vulnerabilities:
            analysis = self._analyze_single_vulnerability_with_ai(vuln)
            ai_analyses.append(analysis)
        
        # Generate comprehensive summary
        summary = self._generate_ai_summary(ai_analyses, integrated_vulnerabilities)
        
        logger.info(f"Completed AI analysis of {len(ai_analyses)} vulnerabilities")
        return ai_analyses, summary

    def _integrate_vulnerability_data(self,
                                      vuln_data: List[Dict],
                                      reach_data: Dict,
                                      exploit_data: Dict) -> List[Dict]:
        """
        Integrate data from all analysis phases with robust matching strategies.
        Attempts to match on:
          - package name (case-insensitive)
          - package name + version
          - vulnerability id (vuln['id'])
          - CVE id if available
        """
        integrated = []

        # Build reachability lookup by multiple keys
        reachability_lookup = {}
        if reach_data and 'vulnerabilities' in reach_data:
            for vuln in reach_data['vulnerabilities']:
                pkg = (vuln.get('package_name') or '').lower()
                ver = vuln.get('installed_version', '')
                if pkg:
                    reachability_lookup[pkg] = vuln
                if pkg and ver:
                    reachability_lookup[f"{pkg}@{ver}"] = vuln
                # also index by normalized alias if present
                alias = vuln.get('package', None)
                if alias:
                    reachability_lookup[(alias or '').lower()] = vuln

        # Build exploitability lookup by CVE and other ids
        exploitability_lookup = {}
        if exploit_data and 'vulnerability_analyses' in exploit_data:
            for vuln in exploit_data['vulnerability_analyses']:
                cve = (vuln.get('cve_id') or '').upper()
                vid = vuln.get('vulnerability_id') or vuln.get('id') or ''
                if cve:
                    exploitability_lookup[cve] = vuln
                if vid:
                    exploitability_lookup[vid] = vuln

        # Integrate
        for vuln in vuln_data:
            integrated_vuln = vuln.copy()

            # build candidate keys
            pkg = (vuln.get('package_name') or '').lower()
            ver = vuln.get('package_version', '')
            vuln_id = (vuln.get('id') or '').upper()

            # reachability match: prefer package@version, then package
            reach_info = None
            if pkg and ver and f"{pkg}@{ver}" in reachability_lookup:
                reach_info = reachability_lookup[f"{pkg}@{ver}"]
            elif pkg and pkg in reachability_lookup:
                reach_info = reachability_lookup[pkg]

            if reach_info:
                integrated_vuln.update({
                    'reachability_criticality': reach_info.get('criticality', 'UNKNOWN'),
                    'is_reachable': reach_info.get('is_used', False),
                    'reachability_reason': reach_info.get('risk_reason', ''),
                    'usage_details': reach_info.get('usage_details', {}),
                    'files_affected': reach_info.get('usage_details', {}).get('files_affected', 0),
                    'total_usages': reach_info.get('usage_details', {}).get('total_usages', 0)
                })
            else:
                integrated_vuln.update({
                    'reachability_criticality': 'NOT_ANALYZED',
                    'is_reachable': False,
                    'reachability_reason': 'Reachability analysis not performed',
                    'usage_details': {},
                    'files_affected': 0,
                    'total_usages': 0
                })

            # exploitability match: try CVE (vuln_id often contains CVE), then vulnerability id
            exploit_info = None
            if vuln_id and vuln_id in exploitability_lookup:
                exploit_info = exploitability_lookup[vuln_id]
            else:
                # try uppercase CVE style if id looks like CVE-...
                if vuln_id.startswith('CVE-') and vuln_id in exploitability_lookup:
                    exploit_info = exploitability_lookup[vuln_id]

            if exploit_info:
                integrated_vuln.update({
                    'exploit_risk_level': exploit_info.get('exploit_risk_level', 'NONE'),
                    'has_public_exploits': exploit_info.get('has_public_exploits', False),
                    'exploit_count': exploit_info.get('exploit_count', 0),
                    'exploits_found': exploit_info.get('exploits_found', [])
                })
            else:
                integrated_vuln.update({
                    'exploit_risk_level': 'NOT_ANALYZED',
                    'has_public_exploits': False,
                    'exploit_count': 0,
                    'exploits_found': []
                })

            integrated.append(integrated_vuln)

        return integrated



    def _build_prompt(self, packages_data: List[Dict[str, Any]]) -> str:
        """Build prompt for LLM from package vulnerability data"""
        prompt_header = (
            "Analyze the following security vulnerability data (Python packages) and provide clear,\n"
            "actionable Short-Term Fixes and Long-Term Fixes for the entire set of packages.\n"
            "Focus on the recommended fixed versions and explain the urgency.\n\n"
        )

        prompt_footer = (
            "\n\nOutput format: valid JSON only. Top-level object with keys:\n"
            "  - short_term_fixes: array of {package, installed_version, recommended_fixed_version, reason, urgency}\n"
            "  - long_term_fixes: array of {package, recommendation, rationale}\n"
            "  - summary: one-line summary of urgency and recommended next steps\n"
        )

        try:
            data_str = json.dumps(packages_data, indent=2)
        except Exception:
            data_str = str(packages_data)

        return prompt_header + "Data:\n\n" + data_str + prompt_footer

    def _call_provider(self, prompt: str, timeout: int = None, model: str = None) -> Optional[str]:
        """
        Call local LLM server with retry logic.

        Args:
            prompt: The prompt string to send
            timeout: Request timeout in seconds
            model: Model name (uses env OLLAMA_MODEL or config default if None)

        Returns:
            LLM response text or None on failure
        """
        if timeout is None:
            timeout = self.default_timeout

        # Mock mode for offline testing
        if self.mock_mode:
            logger.info("MOCK_MODE enabled: returning deterministic sample response")
            sample = {
                "short_term_fixes": [
                    {
                        "package": "flask",
                        "installed_version": "1.0.0",
                        "recommended_fixed_version": "2.3.2",
                        "reason": "Multiple critical CVEs fixed in 2.3.x",
                        "urgency": "HIGH"
                    }
                ],
                "long_term_fixes": [
                    {
                        "package": "all",
                        "recommendation": "Adopt pinned dependencies and automated updates",
                        "rationale": "Reduce upgrade churn and automate security updates"
                    }
                ],
                "summary": "Urgent: Patch critical packages immediately; schedule upgrades within next sprint"
            }
            return json.dumps(sample)

        # Determine model to use
        if model is None:
            model = os.getenv('OLLAMA_MODEL', 'gpt-oss:120b-cloud')

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }

        logger.info(f"Calling LLM at {self.llm_url} with model={model}")
        print(f"🔁 Attempting LLM call at {self.llm_url} using model={model}")

        # Retry loop
        for attempt in range(self.retry_count + 1):
            try:
                resp = requests.post(
                    self.llm_url,
                    json=payload,
                    headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                    timeout=timeout
                )
                resp.raise_for_status()

                # Try to parse response
                content_type = resp.headers.get('content-type', '')
                body = resp.text

                if 'application/json' in content_type:
                    return body

                # Try to parse as JSON
                try:
                    json.loads(body)
                    return body
                except Exception:
                    # Try to extract first JSON object
                    import re
                    match = re.search(r'\{.*\}', body, re.DOTALL)
                    if match:
                        candidate = match.group(0)
                        try:
                            json.loads(candidate)
                            return candidate
                        except Exception:
                            pass

                # Return raw body as fallback
                return body

            except Exception as e:
                logger.warning(f"LLM call attempt {attempt+1}/{self.retry_count+1} failed: {e}")
                if attempt < self.retry_count:
                    import time
                    time.sleep(1)
                    continue
                logger.exception(f"All LLM call attempts failed")
                return None

        return None

    def _analyze_single_vulnerability_with_ai(self, vuln_data: Dict) -> AIAnalysisResult:
        """
        Analyze a single vulnerability using heuristic scoring

        Args:
            vuln_data: Integrated vulnerability data
            
        Returns:
            AI analysis result
        """
        # Extract key vulnerability information
        vuln_id = vuln_data.get('id', 'Unknown')
        package_name = vuln_data.get('package_name', 'Unknown')
        package_version = vuln_data.get('package_version', 'Unknown')
        severity = vuln_data.get('severity', 'UNKNOWN')
        cvss_score = vuln_data.get('cvss_score', 0.0)
        
        # Reachability information
        reachability_status = vuln_data.get('reachability_criticality', 'NOT_ANALYZED')
        is_reachable = vuln_data.get('is_reachable', False)
        files_affected = vuln_data.get('files_affected', 0)
        total_usages = vuln_data.get('total_usages', 0)
        
        # Exploitability information
        exploit_risk = vuln_data.get('exploit_risk_level', 'NOT_ANALYZED')
        has_exploits = vuln_data.get('has_public_exploits', False)
        exploit_count = vuln_data.get('exploit_count', 0)
        
        # AI-powered priority calculation
        priority_score = self._calculate_ai_priority_score(
            severity, cvss_score, reachability_status, exploit_risk, 
            has_exploits, files_affected, total_usages
        )
        
        # Generate heuristic recommendations (no per-vuln LLM calls)
        recommendation, reasoning, remediation_steps = self._generate_ai_recommendation(
            vuln_data, priority_score
        )

        # Use heuristic actions
        short_term_actions = remediation_steps[:2] if len(remediation_steps) >= 2 else remediation_steps
        long_term_actions = remediation_steps[2:5] if len(remediation_steps) > 2 else []
        risk_associated = f"{severity} severity with priority score {priority_score:.1f}/10"

        # Estimate effort and complexity
        effort = self._estimate_remediation_effort(vuln_data, reachability_status)
        complexity = self._assess_technical_complexity(vuln_data)
        business_impact = self._assess_business_impact(vuln_data, priority_score)
        
        return AIAnalysisResult(
            vulnerability_id=vuln_id,
            package_name=package_name,
            package_version=package_version,
            severity=severity,
            reachability_status=reachability_status,
            exploitability_risk=exploit_risk,
            ai_priority_score=priority_score,
            ai_recommendation=recommendation,
            reasoning=reasoning,
            remediation_steps=remediation_steps,
            estimated_effort=effort,
            business_impact=business_impact,
            technical_complexity=complexity,
            short_term_actions=short_term_actions,
            long_term_actions=long_term_actions,
            risk_associated=risk_associated
        )
        
    def _calculate_ai_priority_score(self, 
                                   severity: str, 
                                   cvss_score: float,
                                   reachability: str, 
                                   exploit_risk: str,
                                   has_exploits: bool,
                                   files_affected: int,
                                   total_usages: int) -> float:
        """
        Calculate AI-driven priority score (0-10 scale)
        
        Uses weighted scoring based on multiple factors
        """
        score = 0.0
        
        # Base score from severity (0-3 points)
        severity_weights = {
            'CRITICAL': 3.0,
            'HIGH': 2.5,
            'MEDIUM': 1.5,
            'LOW': 0.5
        }
        score += severity_weights.get(severity, 0.0)
        
        # CVSS score contribution (0-2 points)
        if cvss_score > 0:
            score += min(cvss_score / 5.0, 2.0)
        
        # Reachability multiplier (0.1x to 2.0x)
        reachability_multipliers = {
            'CRITICAL': 2.0,
            'HIGH': 1.7,
            'MEDIUM': 1.3,
            'LOW': 1.0,
            'NOT_REACHABLE': 0.1,
            'NOT_ANALYZED': 0.8
        }
        score *= reachability_multipliers.get(reachability, 0.8)
        
        # Exploitability boost (0-2 points)
        if has_exploits:
            exploit_weights = {
                'CRITICAL': 2.0,
                'HIGH': 1.5,
                'MEDIUM': 1.0,
                'LOW': 0.5
            }
            score += exploit_weights.get(exploit_risk, 0.5)
        
        # Usage intensity boost (0-1 points)
        if files_affected > 0:
            usage_boost = min(files_affected * 0.1 + total_usages * 0.01, 1.0)
            score += usage_boost
        
        # Ensure score is within bounds
        return min(max(score, 0.0), 10.0)
        
    def _generate_ai_recommendation(self, vuln_data: Dict, priority_score: float) -> Tuple[str, str, List[str]]:
        """
        Generate AI-powered recommendations
        
        Returns:
            Tuple of (recommendation, reasoning, remediation_steps)
        """
        package_name = vuln_data.get('package_name', 'Unknown')
        severity = vuln_data.get('severity', 'UNKNOWN')
        reachability = vuln_data.get('reachability_criticality', 'NOT_ANALYZED')
        has_exploits = vuln_data.get('has_public_exploits', False)
        fixed_version = vuln_data.get('fixed_version', 'latest')
        
        # Generate contextual recommendation
        if priority_score >= 8.0:
            recommendation = f"IMMEDIATE ACTION REQUIRED: Upgrade {package_name} immediately"
            reasoning = f"Critical vulnerability with high exploitability risk and active usage in codebase"
        elif priority_score >= 6.0:
            recommendation = f"HIGH PRIORITY: Schedule upgrade of {package_name} within 1-2 weeks"
            reasoning = f"Significant vulnerability with potential impact on application security"
        elif priority_score >= 4.0:
            recommendation = f"MEDIUM PRIORITY: Plan upgrade of {package_name} in next sprint"
            reasoning = f"Moderate vulnerability requiring attention but not immediately critical"
        elif priority_score >= 2.0:
            recommendation = f"LOW PRIORITY: Consider upgrading {package_name} during next maintenance cycle"
            reasoning = f"Low-impact vulnerability with limited risk to application"
        else:
            recommendation = f"MONITOR: Keep {package_name} on watch list for future updates"
            reasoning = f"Minimal risk vulnerability with very low impact on application security"
        
        # Generate specific remediation steps
        steps = []
        
        if reachability == 'NOT_REACHABLE':
            steps.append("Consider removing this unused dependency to reduce attack surface")
        else:
            steps.append(f"Update {package_name} to version {fixed_version} or later")
            
        if has_exploits:
            steps.append("Apply security patches immediately - public exploits are available")
            steps.append("Monitor security advisories for additional patches")
            
        if vuln_data.get('files_affected', 0) > 5:
            steps.append("Review all affected files for potential security implications")
            steps.append("Consider refactoring to reduce dependency usage surface")
            
        steps.append("Test application thoroughly after applying updates")
        steps.append("Update security documentation and change logs")
        
        return recommendation, reasoning, steps
        
    def _estimate_remediation_effort(self, vuln_data: Dict, reachability: str) -> str:
        """Estimate remediation effort level"""
        files_affected = vuln_data.get('files_affected', 0)
        has_breaking_changes = vuln_data.get('major_version_change', False)
        
        if reachability == 'NOT_REACHABLE':
            return "LOW"  # Just remove the dependency
        elif files_affected > 10 or has_breaking_changes:
            return "HIGH"
        elif files_affected > 3:
            return "MEDIUM"
        else:
            return "LOW"
            
    def _assess_technical_complexity(self, vuln_data: Dict) -> str:
        """Assess technical complexity of remediation"""
        fixed_version = vuln_data.get('fixed_version', '')
        current_version = vuln_data.get('package_version', '')
        
        # Simple heuristic based on version changes
        if not fixed_version or fixed_version == 'latest':
            return "MEDIUM"
        
        # Check if major version change is required
        try:
            if '.' in current_version and '.' in fixed_version:
                current_major = int(current_version.split('.')[0])
                fixed_major = int(fixed_version.split('.')[0])
                if fixed_major > current_major:
                    return "HIGH"
        except (ValueError, IndexError):
            pass
            
        return "LOW"
        
    def _assess_business_impact(self, vuln_data: Dict, priority_score: float) -> str:
        """Assess potential business impact"""
        severity = vuln_data.get('severity', 'UNKNOWN')
        has_exploits = vuln_data.get('has_public_exploits', False)
        is_reachable = vuln_data.get('is_reachable', False)
        
        if priority_score >= 8.0 and has_exploits and is_reachable:
            return "CRITICAL - Potential for data breach, service disruption, or compliance violations"
        elif priority_score >= 6.0:
            return "HIGH - Could impact application availability or data integrity"
        elif priority_score >= 4.0:
            return "MEDIUM - May affect application functionality or user experience"
        else:
            return "LOW - Minimal impact on business operations"
            
    def _generate_ai_summary(self, analyses: List[AIAnalysisResult], vulnerabilities: List[Dict]) -> AIAnalysisSummary:
        """Generate comprehensive AI analysis summary"""
        
        total_vulns = len(analyses)
        if total_vulns == 0:
            return AIAnalysisSummary(
                total_vulnerabilities=0,
                critical_recommendations=0,
                high_priority_actions=0,
                medium_priority_actions=0,
                low_priority_actions=0,
                overall_security_score=100.0,
                top_recommendations=[],
                security_trends={},
                compliance_considerations=[]
            )
        
        # Count priority levels
        critical_count = len([a for a in analyses if a.ai_priority_score >= 8.0])
        high_count = len([a for a in analyses if 6.0 <= a.ai_priority_score < 8.0])
        medium_count = len([a for a in analyses if 4.0 <= a.ai_priority_score < 6.0])
        low_count = len([a for a in analyses if a.ai_priority_score < 4.0])
        
        # Calculate overall security score (0-100)
        avg_priority = sum(a.ai_priority_score for a in analyses) / total_vulns
        security_score = max(0, 100 - (avg_priority * 10))  # Inverse relationship
        
        # Generate top recommendations
        top_analyses = sorted(analyses, key=lambda x: x.ai_priority_score, reverse=True)[:5]
        top_recommendations = [a.ai_recommendation for a in top_analyses]
        
        # Analyze security trends
        security_trends = {
            'most_vulnerable_packages': self._get_most_vulnerable_packages(analyses),
            'common_severity_levels': self._get_severity_distribution(analyses),
            'reachability_patterns': self._get_reachability_patterns(analyses),
            'exploit_availability_trends': self._get_exploit_trends(analyses)
        }
        
        # Generate compliance considerations
        compliance_considerations = self._generate_compliance_recommendations(analyses)
        
        return AIAnalysisSummary(
            total_vulnerabilities=total_vulns,
            critical_recommendations=critical_count,
            high_priority_actions=high_count,
            medium_priority_actions=medium_count,
            low_priority_actions=low_count,
            overall_security_score=security_score,
            top_recommendations=top_recommendations,
            security_trends=security_trends,
            compliance_considerations=compliance_considerations
        )
        
    def _get_most_vulnerable_packages(self, analyses: List[AIAnalysisResult]) -> List[Dict]:
        """Get packages with highest vulnerability counts"""
        package_counts = {}
        for analysis in analyses:
            pkg = analysis.package_name
            if pkg not in package_counts:
                package_counts[pkg] = {'count': 0, 'max_score': 0.0}
            package_counts[pkg]['count'] += 1
            package_counts[pkg]['max_score'] = max(package_counts[pkg]['max_score'], analysis.ai_priority_score)
        
        # Sort by count, then by max score
        sorted_packages = sorted(
            package_counts.items(), 
            key=lambda x: (x[1]['count'], x[1]['max_score']), 
            reverse=True
        )[:5]
        
        return [
            {'package': pkg, 'vulnerability_count': data['count'], 'max_priority_score': data['max_score']}
            for pkg, data in sorted_packages
        ]
        
    def _get_severity_distribution(self, analyses: List[AIAnalysisResult]) -> Dict[str, int]:
        """Get distribution of vulnerability severities"""
        severity_counts = {}
        for analysis in analyses:
            sev = analysis.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return severity_counts
        
    def _get_reachability_patterns(self, analyses: List[AIAnalysisResult]) -> Dict[str, int]:
        """Get reachability status distribution"""
        reachability_counts = {}
        for analysis in analyses:
            reach = analysis.reachability_status
            reachability_counts[reach] = reachability_counts.get(reach, 0) + 1
        return reachability_counts
        
    def _get_exploit_trends(self, analyses: List[AIAnalysisResult]) -> Dict[str, int]:
        """Get exploit availability trends"""
        exploit_counts = {}
        for analysis in analyses:
            exploit = analysis.exploitability_risk
            exploit_counts[exploit] = exploit_counts.get(exploit, 0) + 1
        return exploit_counts
        
    def _generate_compliance_recommendations(self, analyses: List[AIAnalysisResult]) -> List[str]:
        """Generate compliance-related recommendations"""
        recommendations = []
        
        critical_count = len([a for a in analyses if a.ai_priority_score >= 8.0])
        high_count = len([a for a in analyses if 6.0 <= a.ai_priority_score < 8.0])
        
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical vulnerabilities to maintain SOC 2 compliance")
            recommendations.append("Implement emergency patching procedures for critical vulnerabilities")
        
        if high_count > 5:
            recommendations.append("Consider implementing automated vulnerability scanning in CI/CD pipeline")
            
        recommendations.append("Document vulnerability remediation process for audit purposes")
        recommendations.append("Establish vulnerability disclosure policy for discovered issues")
        
        return recommendations
        
    def generate_ai_report(self, 
                          analyses: List[AIAnalysisResult], 
                          summary: AIAnalysisSummary, 
                          output_path: str) -> Dict[str, Any]:
        """
        Generate comprehensive AI analysis report
        
        Args:
            analyses: Individual vulnerability analyses
            summary: Analysis summary
            output_path: Path to save the report
            
        Returns:
            Report dictionary
        """
        provider_used = self.config.default_provider if self.config else 'none'
        provider_model = None
        if self.config and getattr(self.config, 'providers', None):
            prov = self.config.providers.get(provider_used)
            if prov and getattr(prov, 'models', None):
                provider_model = prov.models.get('chat')

        report = {
            'metadata': {
                'analysis_timestamp': self.analysis_timestamp,
                'tool_version': 'vulnreach-ai-1.0',
                'ai_provider': provider_used,
                'ai_model_used': provider_model or 'n/a',
                'analysis_type': 'AI-powered integrated vulnerability analysis'
            },
            'summary': asdict(summary),
            'detailed_analyses': [asdict(analysis) for analysis in analyses],
            'actionable_insights': self._generate_actionable_insights(analyses, summary),
            'executive_summary': self._generate_executive_summary(summary)
        }
        
        # Save report to file
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        logger.info(f"AI analysis report saved to: {output_path}")
        return report

    def _generate_actionable_insights(self, analyses: List[AIAnalysisResult], summary: AIAnalysisSummary) -> Dict[str, Any]:
        """Generate actionable insights from the analysis"""
        immediate_actions = [a for a in analyses if a.ai_priority_score >= 8.0]
        items = [
            {
                'vulnerability': ia.vulnerability_id,
                'package': ia.package_name,
                'recommendation': ia.ai_recommendation,
                'short_term_actions': ia.short_term_actions or ia.remediation_steps[:2],
                'long_term_actions': ia.long_term_actions
            }
            for ia in immediate_actions[:10]
        ]

        insights = {
            'immediate_actions_required': len(immediate_actions),
            'immediate_action_items': items,
            'security_improvement_roadmap': [
                'Address critical vulnerabilities within 24-48 hours',
                'Implement automated security scanning in CI/CD pipeline',
                'Establish regular dependency update cadence',
                'Maintain an incident response runbook for security issues'
            ],
            'recommended_tools_and_processes': [
                'Automated dependency scanning (e.g., Dependabot, Snyk)',
                'Security-focused code review process',
                'Regular penetration testing',
                'Vulnerability management workflow'
            ]
        }
        return insights

    def _generate_executive_summary(self, summary: AIAnalysisSummary) -> Dict[str, str]:
        """Generate executive-level summary (compact)"""
        return {
            'overall_assessment': self._get_overall_assessment(summary.overall_security_score),
            'key_findings': f"Analysis identified {summary.total_vulnerabilities} vulnerabilities with {summary.critical_recommendations} requiring immediate attention",
            'business_risk': self._assess_overall_business_risk(summary),
            'recommended_timeline': self._get_recommended_timeline(summary),
            'resource_requirements': self._estimate_resource_requirements(summary)
        }

    # Helper methods used by executive summary (restored)
    def _get_overall_assessment(self, security_score: float) -> str:
        """Get overall security assessment"""
        if security_score >= 90:
            return "EXCELLENT - Application has strong security posture with minimal vulnerabilities"
        elif security_score >= 75:
            return "GOOD - Application is relatively secure but has some areas for improvement"
        elif security_score >= 60:
            return "FAIR - Application has moderate security risks that should be addressed"
        elif security_score >= 40:
            return "POOR - Application has significant security vulnerabilities requiring immediate attention"
        else:
            return "CRITICAL - Application has severe security issues that pose immediate risk"

    def _assess_overall_business_risk(self, summary: AIAnalysisSummary) -> str:
        """Assess overall business risk"""
        if summary.critical_recommendations > 5:
            return "HIGH - Multiple critical vulnerabilities pose significant risk to business operations"
        elif summary.critical_recommendations > 0:
            return "MEDIUM - Some critical vulnerabilities require immediate attention"
        elif summary.high_priority_actions > 10:
            return "MEDIUM - Numerous high-priority vulnerabilities need addressing"
        else:
            return "LOW - Manageable number of vulnerabilities with standard remediation process"

    def _get_recommended_timeline(self, summary: AIAnalysisSummary) -> str:
        """Get recommended remediation timeline"""
        if summary.critical_recommendations > 0:
            return "URGENT - Address critical issues within 24-48 hours, complete all high-priority items within 2 weeks"
        elif summary.high_priority_actions > 5:
            return "ACCELERATED - Complete high-priority items within 1-2 weeks, medium priority within 1 month"
        else:
            return "STANDARD - Address items during regular maintenance cycles over next 2-3 months"

    def _estimate_resource_requirements(self, summary: AIAnalysisSummary) -> str:
        """Estimate resource requirements"""
        total_actions = summary.critical_recommendations + summary.high_priority_actions + summary.medium_priority_actions
        if total_actions > 20:
            return "SIGNIFICANT - May require dedicated security sprint or external security consulting"
        elif total_actions > 10:
            return "MODERATE - Requires focused effort from development team over several sprints"
        else:
            return "MINIMAL - Can be addressed during regular development cycles"

    def request_llm_fix_from_files(self, consolidated_path: str, reachability_paths: List[str], output_path: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
        """
        Read consolidated.json and reachability report(s), build prompt and call local LLM.

        Args:
            consolidated_path: Path to consolidated.json with package vulnerability data
            reachability_paths: List of paths to reachability analysis reports
            output_path: Where to save the LLM's JSON response
            timeout: Request timeout in seconds

        Returns:
            Parsed JSON dict from LLM or None on failure
        """
        try:
            # Load consolidated package data
            consolidated = []
            if consolidated_path and os.path.exists(consolidated_path):
                with open(consolidated_path, 'r') as f:
                    consolidated = json.load(f)
                    if not isinstance(consolidated, list):
                        consolidated = [consolidated]
            else:
                logger.warning(f"Consolidated file not found: {consolidated_path}")

            if not consolidated:
                logger.warning("No package data to analyze")
                return None

            # Build prompt using the new template
            prompt = self._build_prompt(consolidated)

            # Get model name
            model = os.getenv('OLLAMA_MODEL') or 'gpt-oss:120b-cloud'

            # Call LLM
            logger.info(f"Requesting LLM analysis for {len(consolidated)} packages")
            llm_text = self._call_provider(prompt, timeout=timeout, model=model)

            if not llm_text:
                logger.warning("LLM returned no result")
                return None

            # Parse JSON response
            try:
                parsed = json.loads(llm_text)
            except Exception:
                # Try to extract JSON substring
                import re
                match = re.search(r'\{.*\}', llm_text, re.DOTALL)
                if match:
                    try:
                        parsed = json.loads(match.group(0))
                    except Exception:
                        logger.exception("Failed to parse JSON from LLM response")
                        return None
                else:
                    logger.exception("No JSON found in LLM response")
                    return None

            # Validate response has expected keys
            if not any(k in parsed for k in ("short_term_fixes", "long_term_fixes", "summary")):
                logger.warning("LLM response missing expected keys; returning as-is")

            # Write output
            try:
                with open(output_path, 'w') as f:
                    json.dump(parsed, f, indent=2)
                logger.info(f"LLM recommendations saved to: {output_path}")
                print(f"✅ LLM recommendations saved to: {output_path}")
            except Exception as e:
                logger.exception(f"Failed to write output to {output_path}: {e}")

            return parsed

        except Exception as e:
            logger.exception(f"Error in request_llm_fix_from_files: {e}")
            return None
def print_ai_analysis_summary(summary: AIAnalysisSummary):
    """Print AI analysis summary to console"""
    print("\n🤖 AI-POWERED SECURITY ANALYSIS RESULTS")
    print("=" * 70)
    print(f"📊 Overall Security Score: {summary.overall_security_score:.1f}/100")
    print(f"🔍 Total Vulnerabilities Analyzed: {summary.total_vulnerabilities}")
    print()
    
    print("📋 PRIORITY BREAKDOWN:")
    print(f"   🔴 Critical Actions Required: {summary.critical_recommendations}")
    print(f"   🟠 High Priority Actions: {summary.high_priority_actions}")
    print(f"   🟡 Medium Priority Actions: {summary.medium_priority_actions}")
    print(f"   🟢 Low Priority Actions: {summary.low_priority_actions}")
    print()
    
    if summary.top_recommendations:
        print("🎯 TOP AI RECOMMENDATIONS:")
        for i, rec in enumerate(summary.top_recommendations[:3], 1):
            print(f"   {i}. {rec}")
        print()
    
    if summary.compliance_considerations:
        print("⚖️ COMPLIANCE CONSIDERATIONS:")
        for consideration in summary.compliance_considerations[:3]:
            print(f"   • {consideration}")
        print()


if __name__ == "__main__":
    # Example usage
    print("AI Vulnerability Analyzer - Example usage:")
    print("This module should be imported and used within the main VulnReach workflow")

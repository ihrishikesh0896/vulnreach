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
from dataclasses import dataclass, asdict
from pathlib import Path

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
    """AI-powered vulnerability analyzer that integrates all security analysis results"""
    
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
        Integrate data from all analysis phases
        
        Returns:
            List of integrated vulnerability records with all available data
        """
        integrated = []
        
        # Create lookup dictionaries for efficient integration
        reachability_lookup = {}
        if reach_data and 'vulnerabilities' in reach_data:
            for vuln in reach_data['vulnerabilities']:
                key = f"{vuln.get('package_name', '')}"
                reachability_lookup[key] = vuln
        
        exploitability_lookup = {}
        if exploit_data and 'vulnerability_analyses' in exploit_data:
            for vuln in exploit_data['vulnerability_analyses']:
                key = f"{vuln.get('cve_id', '')}"
                exploitability_lookup[key] = vuln
        
        # Integrate data for each vulnerability
        for vuln in vuln_data:
            integrated_vuln = vuln.copy()
            
            # Add reachability data
            reach_key = vuln.get('package_name', '')
            if reach_key in reachability_lookup:
                reach_info = reachability_lookup[reach_key]
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
            
            # Add exploitability data
            exploit_key = vuln.get('id', '')
            if exploit_key in exploitability_lookup:
                exploit_info = exploitability_lookup[exploit_key]
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
        
    def _analyze_single_vulnerability_with_ai(self, vuln_data: Dict) -> AIAnalysisResult:
        """
        Analyze a single vulnerability using AI reasoning
        
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
        
        # Generate AI recommendations
        recommendation, reasoning, remediation_steps = self._generate_ai_recommendation(
            vuln_data, priority_score
        )
        
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
            technical_complexity=complexity
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
        report = {
            'metadata': {
                'analysis_timestamp': self.analysis_timestamp,
                'tool_version': 'vulnreach-ai-1.0',
                'ai_model_used': self.config.default_provider if self.config else 'none',
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
        immediate_actions = [
            analysis for analysis in analyses 
            if analysis.ai_priority_score >= 8.0
        ]
        
        return {
            'immediate_actions_required': len(immediate_actions),
            'immediate_action_items': [
                {
                    'vulnerability': action.vulnerability_id,
                    'package': action.package_name,
                    'recommendation': action.ai_recommendation,
                    'steps': action.remediation_steps[:3]  # Top 3 steps
                }
                for action in immediate_actions[:5]  # Top 5 most critical
            ],
            'security_improvement_roadmap': [
                'Address critical vulnerabilities within 24-48 hours',
                'Implement automated security scanning in CI/CD pipeline',
                'Establish regular dependency update schedule',
                'Create incident response plan for security vulnerabilities',
                'Train development team on secure coding practices'
            ],
            'recommended_tools_and_processes': [
                'Automated dependency scanning (e.g., Dependabot, Snyk)',
                'Security-focused code review process',
                'Regular penetration testing',
                'Vulnerability management workflow',
                'Security awareness training program'
            ]
        }
        
    def _generate_executive_summary(self, summary: AIAnalysisSummary) -> Dict[str, str]:
        """Generate executive-level summary"""
        return {
            'overall_assessment': self._get_overall_assessment(summary.overall_security_score),
            'key_findings': f"Analysis identified {summary.total_vulnerabilities} vulnerabilities with {summary.critical_recommendations} requiring immediate attention",
            'business_risk': self._assess_overall_business_risk(summary),
            'recommended_timeline': self._get_recommended_timeline(summary),
            'resource_requirements': self._estimate_resource_requirements(summary)
        }
        
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
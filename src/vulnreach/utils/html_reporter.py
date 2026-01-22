"""
VulnReach HTML Report Generator
Generates an interactive HTML report with Mermaid call chain graphs
"""

import json
import os
from typing import Dict, List, Any

class HtmlReporter:
    """Generates HTML reports for security findings"""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnReach Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 1.1em; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .stat-label { color: #666; font-size: 0.9em; text-transform: uppercase; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .not-reachable { color: #6c757d; }
        .vulnerabilities {
            padding: 40px;
        }
        .vuln-card {
            background: white;
            border-left: 5px solid;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .vuln-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .vuln-card.CRITICAL { border-left-color: #dc3545; }
        .vuln-card.HIGH { border-left-color: #fd7e14; }
        .vuln-card.MEDIUM { border-left-color: #ffc107; }
        .vuln-card.LOW { border-left-color: #28a745; }
        .vuln-card.NOT_REACHABLE { border-left-color: #6c757d; opacity: 0.7; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .vuln-title { font-size: 1.3em; font-weight: bold; }
        .badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }
        .badge.CRITICAL { background: #dc3545; }
        .badge.HIGH { background: #fd7e14; }
        .badge.MEDIUM { background: #ffc107; color: #333; }
        .badge.LOW { background: #28a745; }
        .badge.NOT_REACHABLE { background: #6c757d; }
        .vuln-details { margin: 15px 0; color: #555; line-height: 1.6; }
        .graph-container {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .graph-title {
            font-weight: bold;
            margin-bottom: 15px;
            color: #333;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .verified-badge {
            background: #28a745;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
        }
        .mermaid { background: white; padding: 20px; border-radius: 8px; }
        .usage-list {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
        }
        .usage-item {
            padding: 8px;
            margin: 5px 0;
            background: white;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        .footer {
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VulnReach Security Report</h1>
            <p>Deep Reachability Analysis with Call Graph Verification</p>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{total_vulns}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value critical">{critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium">{medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low">{low_count}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value not-reachable">{not_reachable_count}</div>
                <div class="stat-label">Not Reachable</div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2 style="margin-bottom: 30px;">📊 Vulnerability Details</h2>
            {vulnerability_cards}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>VulnReach</strong> - Deep Reachability Analysis Engine</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Powered by Static Call Graph Analysis</p>
        </div>
    </div>
    
    <script>
        mermaid.initialize({ startOnLoad: true, theme: 'default' });
    </script>
</body>
</html>
"""

    VULN_CARD_TEMPLATE = """
<div class="vuln-card {criticality}">
    <div class="vuln-header">
        <div class="vuln-title">{package_name} @ {version}</div>
        <span class="badge {criticality}">{criticality}</span>
    </div>
    <div class="vuln-details">
        <p><strong>Risk Reason:</strong> {risk_reason}</p>
        <p><strong>Recommended Fix:</strong> Upgrade to {recommended_version}</p>
        {dependency_info}
    </div>
    {call_graph}
    {usage_details}
</div>
"""

    @staticmethod
    def generate(reachability_data: Dict[str, Any], output_path: str):
        """Generate interactive HTML report from reachability data objects"""
        
        vulnerabilities = reachability_data.get('vulnerabilities', [])
        
        # Count by criticality
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NOT_REACHABLE': 0}
        for vuln in vulnerabilities:
            crit = vuln.get('criticality', 'UNKNOWN')
            counts[crit] = counts.get(crit, 0) + 1
        
        # Generate vulnerability cards
        cards_html = []
        for vuln in vulnerabilities:
            package_name = vuln.get('package_name', 'Unknown')
            version = vuln.get('installed_version', 'Unknown')
            criticality = vuln.get('criticality', 'UNKNOWN')
            risk_reason = vuln.get('risk_reason', 'No information')
            recommended = vuln.get('recommended_version', 'N/A')
            
            # Dependency info
            dep_info = vuln.get('dependency_info', {})
            is_direct = dep_info.get('is_direct', False)
            dep_type = "📦 Direct Dependency" if is_direct else "⚠️ Transitive Dependency"
            dep_html = f'<p><strong>Dependency Type:</strong> {dep_type}</p>'
            
            # Call graph
            call_graph_html = ""
            call_graph = vuln.get('call_chain_graph')
            # Check if graph is valid (has content beyond header) using simple heuristic
            if call_graph and ("-->" in call_graph or ";" in call_graph.replace("graph TD;", "")):
                call_graph_html = f"""
                <div class="graph-container">
                    <div class="graph-title">
                        🕸️ Call Chain Graph
                        <span class="verified-badge">VERIFIED PATH</span>
                    </div>
                    <div class="mermaid">
{call_graph}
                    </div>
                </div>
                """
            
            # Usage details
            usage_html = ""
            usage_details = vuln.get('usage_details', {})
            usage_contexts = usage_details.get('usage_contexts', [])[:5]  # Show top 5
            if usage_contexts:
                usage_items = "".join([
                    f'<div class="usage-item">📄 {ctx.get("file", "?")}:{ctx.get("line", "?")} - {ctx.get("code", "")[:80]}</div>'
                    for ctx in usage_contexts
                ])
                usage_html = f"""
                <div class="usage-list">
                    <strong>Usage Locations:</strong>
                    {usage_items}
                </div>
                """
            
            card = HtmlReporter.VULN_CARD_TEMPLATE
            card = card.replace('{package_name}', str(package_name))
            card = card.replace('{version}', str(version))
            card = card.replace('{criticality}', str(criticality))
            card = card.replace('{risk_reason}', str(risk_reason))
            card = card.replace('{recommended_version}', str(recommended))
            card = card.replace('{dependency_info}', str(dep_html))
            card = card.replace('{call_graph}', str(call_graph_html))
            card = card.replace('{usage_details}', str(usage_html))
            
            cards_html.append(card)
        
        # Generate final HTML using manual replacement
        html = HtmlReporter.HTML_TEMPLATE
        html = html.replace('{total_vulns}', str(len(vulnerabilities)))
        html = html.replace('{critical_count}', str(counts.get('CRITICAL', 0)))
        html = html.replace('{high_count}', str(counts.get('HIGH', 0)))
        html = html.replace('{medium_count}', str(counts.get('MEDIUM', 0)))
        html = html.replace('{low_count}', str(counts.get('LOW', 0)))
        html = html.replace('{not_reachable_count}', str(counts.get('NOT_REACHABLE', 0)))
        html = html.replace('{vulnerability_cards}', "\n".join(cards_html))
        
        with open(output_path, 'w') as f:
            f.write(html)

# src/vulnreach/web_server.py
from flask import Flask, render_template, jsonify, send_from_directory
import json
import os
from pathlib import Path

app = Flask(__name__, template_folder='../../templates', static_folder='../../static')


class VulnReachWebServer:
    def __init__(self, findings_dir="security_findings"):
        self.findings_dir = Path(findings_dir)

    def get_latest_report(self, project_name=None):
        """Get the latest security report"""
        if project_name:
            report_path = self.findings_dir / project_name / "security_report.json"
        else:
            # Find most recent report
            reports = list(self.findings_dir.glob("**/security_report.json"))
            if not reports:
                return None
            report_path = max(reports, key=os.path.getctime)

        if report_path.exists():
            with open(report_path) as f:
                return json.load(f)
        return None

    def get_exploitability_report(self, project_name=None):
        """Get exploitability analysis"""
        if project_name:
            report_path = self.findings_dir / project_name / "exploitability_report.json"
        else:
            reports = list(self.findings_dir.glob("**/exploitability_report.json"))
            if not reports:
                return None
            report_path = max(reports, key=os.path.getctime)

        if report_path.exists():
            with open(report_path) as f:
                return json.load(f)
        return None

    def get_reachability_report(self, project_name):
        """Get vulnerability reachability analysis"""
        # Try both possible filenames
        report_paths = [
            self.findings_dir / project_name / "vulnerability_reachability_report.json",
            self.findings_dir / project_name / "python_vulnerability_reachability_report.json"
        ]
        
        for report_path in report_paths:
            if report_path.exists():
                with open(report_path) as f:
                    return json.load(f)
        return None

    def get_sbom_report(self, project_name):
        """Get SBOM data"""
        report_path = self.findings_dir / project_name / "project.sbom.json"
        if report_path.exists():
            with open(report_path) as f:
                return json.load(f)
        return None

    def get_dashboard_overview(self):
        """Get overview statistics across all projects"""
        projects = [d.name for d in self.findings_dir.iterdir() if d.is_dir()]
        overview = {
            "total_projects": len(projects),
            "projects": [],
            "total_vulnerabilities": 0,
            "severity_totals": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "reachable_vulnerabilities": 0
        }

        for project in projects:
            security_report = self.get_latest_report(project)
            reachability_report = self.get_reachability_report(project)
            
            project_data = {
                "name": project,
                "vulnerabilities": 0,
                "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "reachable_count": 0
            }

            if security_report and security_report.get("summary"):
                summary = security_report["summary"]
                project_data["vulnerabilities"] = summary.get("total_vulnerabilities", 0)
                severity_breakdown = summary.get("severity_breakdown", {})
                project_data["severity_breakdown"] = severity_breakdown
                
                overview["total_vulnerabilities"] += project_data["vulnerabilities"]
                for severity, count in severity_breakdown.items():
                    if severity in overview["severity_totals"]:
                        overview["severity_totals"][severity] += count

            if reachability_report:
                reachable_vulns = reachability_report.get("reachable_vulnerabilities", [])
                project_data["reachable_count"] = len(reachable_vulns)
                overview["reachable_vulnerabilities"] += project_data["reachable_count"]

            overview["projects"].append(project_data)

        return overview


# Initialize server
server = VulnReachWebServer()


@app.route('/')
def dashboard():
    """Serve the React dashboard"""
    return render_template('dashboard.html')


@app.route('/api/reports')
def list_reports():
    """List available security reports"""
    projects = [d.name for d in server.findings_dir.iterdir() if d.is_dir()]
    return jsonify(projects)


@app.route('/api/reports/<project_name>')
def get_report(project_name):
    """Get security report for specific project"""
    report = server.get_latest_report(project_name)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    return jsonify(report)


@app.route('/api/exploitability/<project_name>')
def get_exploitability(project_name):
    """Get exploitability report for specific project"""
    report = server.get_exploitability_report(project_name)
    if not report:
        return jsonify({"error": "Exploitability report not found"}), 404
    return jsonify(report)


@app.route('/api/consolidated/<project_name>')
def get_consolidated(project_name):
    """Get consolidated report for specific project"""
    consolidated_path = server.findings_dir / project_name / "consolidated.json"
    if consolidated_path.exists():
        with open(consolidated_path) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "Consolidated report not found"}), 404


@app.route('/api/overview')
def get_overview():
    """Get dashboard overview with cross-project statistics"""
    return jsonify(server.get_dashboard_overview())


@app.route('/api/reachability/<project_name>')
def get_reachability(project_name):
    """Get vulnerability reachability report for specific project"""
    report = server.get_reachability_report(project_name)
    if not report:
        return jsonify({"error": "Reachability report not found"}), 404
    return jsonify(report)


@app.route('/api/sbom/<project_name>')
def get_sbom(project_name):
    """Get SBOM report for specific project"""
    report = server.get_sbom_report(project_name)
    if not report:
        return jsonify({"error": "SBOM report not found"}), 404
    return jsonify(report)


@app.route('/api/latest')
def get_latest():
    """Get the most recent security report"""
    security_report = server.get_latest_report()
    exploit_report = server.get_exploitability_report()

    return jsonify({
        "security_report": security_report,
        "exploitability_report": exploit_report
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
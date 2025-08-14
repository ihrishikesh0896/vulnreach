# 🛡️ VulnReach - Smart Vulnerability Reachability Analyzer

[![Security](https://img.shields.io/badge/security-focused-red.svg)]()
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> **Beyond version checking**: Discover which vulnerabilities in your dependencies actually matter by analyzing real code usage patterns.

VulnReach is an intelligent vulnerability analysis tool that goes beyond traditional dependency scanning. While most tools simply check versions, VulnReach analyzes your actual codebase to determine which vulnerable packages are **truly reachable** and pose real risk to your application.

## 🎯 Why VulnReach?

Traditional vulnerability scanners overwhelm you with alerts, but VulnReach answers the critical question:

> **"Is this vulnerability actually exploitable in MY codebase?"**

### The Problem
- 📊 **Traditional scanners**: "You have 147 vulnerabilities!"
- 😰 **You**: "Which ones should I fix first? Are they even used?"
- ⏰ **Result**: Analysis paralysis and wasted time on unused dependencies

### The VulnReach Solution
- 🎯 **VulnReach**: "You have 8 CRITICAL vulnerabilities that are actively used in your code"
- ✅ **You**: Clear priorities, actionable insights, efficient remediation
- 🚀 **Result**: Focus on what matters, fix real risks first

## 🚀 Features

### 🔍 **Smart Vulnerability Discovery**
- **SBOM Generation**: Uses [Syft](https://github.com/anchore/syft) to create comprehensive Software Bill of Materials
- **Vulnerability Scanning**: Leverages [Trivy](https://aquasecurity.github.io/trivy/) for industry-leading vulnerability detection
- **Multi-format Support**: SPDX, CycloneDX, and Syft native formats

### 🧠 **Intelligent Reachability Analysis**
- **Static Code Analysis**: Parses your entire codebase using AST analysis
- **Usage Pattern Detection**: Identifies imports, function calls, and attribute access
- **Dynamic Package Mapping**: Handles complex import-to-package mappings (e.g., `import yaml` → `PyYAML`)

### 📊 **Risk Prioritization**
- **CRITICAL**: Actively used across multiple files with direct function calls
- **HIGH**: Used with direct function calls
- **MEDIUM**: Imported across multiple files
- **LOW**: Limited usage detected
- **NOT_REACHABLE**: Not used in codebase (safe to ignore)

### 📈 **Comprehensive Reporting**
- **Executive Summary**: High-level risk overview
- **Detailed Analysis**: File-by-file usage contexts
- **Remediation Guidance**: Version upgrade recommendations
- **JSON Output**: Machine-readable for CI/CD integration

## 📋 Prerequisites

Install the required security tools:

```bash
# Install Syft (SBOM generation)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy (vulnerability scanning)
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Or see: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
```

Install Python dependencies:
```bash
pip install requests
```

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/vulnreach.git
cd vulnreach
pip install -r requirements.txt
```

## 🚀 Quick Start

### Basic Vulnerability Scan
```bash
# Scan your project directory
python security_sca_tool.py /path/to/your/project

# Generate comprehensive report
python security_sca_tool.py /path/to/your/project --output-report security_report.json
```

### With Reachability Analysis (Recommended)
```bash
# Full analysis with reachability insights
python security_sca_tool.py /path/to/your/project --run-reachability
```

### Advanced Usage
```bash
# Use existing SBOM
python security_sca_tool.py --sbom existing_sbom.json --run-reachability

# Save SBOM for reuse
python security_sca_tool.py /path/to/project --output-sbom project_sbom.json --run-reachability

# Direct scan (skip SBOM generation)
python security_sca_tool.py /path/to/project --direct-scan --run-reachability
```

## 📊 Sample Output

```
🛡️  SECURITY SCAN RESULTS
================================================================================
📊 Scan completed at: 2024-08-14T10:30:45
🔧 SBOM Generator: Syft
🔍 Vulnerability Scanner: Trivy

📦 Total Components: 127
⚠️  Vulnerable Components: 8
🚨 Total Vulnerabilities: 23

📈 Severity Breakdown:
   🔴 CRITICAL: 3
   🟠 HIGH: 5
   🟡 MEDIUM: 12
   🟢 LOW: 3

🚨 TOP CRITICAL/HIGH VULNERABILITIES:
------------------------------------------------------------
🔴 CVE-2024-1234 - requests@2.25.1
   Severity: CRITICAL (CVSS: 9.8)
   Title: Remote Code Execution in HTTP parsing
   🔧 Fixed in: 2.32.0

=== Vulnerability Reachability Analysis ===
Total vulnerabilities analyzed: 23
Critical (actively used): 2
High (used with calls): 1
Medium (imported): 3
Low (limited usage): 5
Not reachable: 12

🚨 CRITICAL: requests v2.25.1
   Reason: Package requests is actively used across 8 files with direct function calls
   Upgrade to: 2.32.0
   📍 src/api/client.py:15 - import requests
   📍 src/utils/http.py:23 - response = requests.get(url)
   📍 src/auth/oauth.py:45 - requests.post(token_url, data=payload)
   ... and 12 more usages
```

## 🏗️ Project Structure

```
vulnreach/
├── security_sca_tool.py           # Main CLI tool
├── utils/
│   ├── vuln_reachability_analyzer.py   # Core reachability analysis
│   └── get_metadata.py             # Dynamic package mapping
├── security_findings/              # Generated reports (auto-created)
│   └── project_name/
│       ├── security_report.json
│       ├── consolidated.json
│       └── vulnerability_reachability_report.json
└── requirements.txt
```

## 📋 Report Structure

### Security Report (`security_report.json`)
```json
{
  "summary": {
    "total_vulnerabilities": 23,
    "severity_breakdown": {
      "CRITICAL": 3,
      "HIGH": 5,
      "MEDIUM": 12,
      "LOW": 3
    }
  },
  "vulnerabilities": [...],
  "components": [...]
}
```

### Consolidated Recommendations (`consolidated.json`)
```json
[
  {
    "package_name": "requests",
    "installed_version": "2.25.1",
    "recommended_fixed_version": "2.32.0",
    "upgrade_needed": true
  }
]
```

### Reachability Analysis (`vulnerability_reachability_report.json`)
```json
{
  "summary": {
    "critical_reachable": 2,
    "not_reachable": 12
  },
  "vulnerabilities": [
    {
      "package_name": "requests",
      "criticality": "CRITICAL",
      "risk_reason": "Package requests is actively used across 8 files",
      "usage_details": {
        "files_affected": 8,
        "usage_contexts": [...]
      }
    }
  ]
}
```

## 🔧 Configuration

### Supported SBOM Formats
- `spdx-json` (default)
- `cyclonedx-json`
- `syft-json`

### Command Line Options
```bash
# Core functionality
--sbom SBOM_FILE                 # Use existing SBOM
--output-sbom SBOM_FILE         # Save generated SBOM
--sbom-format FORMAT            # SBOM format (spdx-json, cyclonedx-json, syft-json)

# Analysis options
--direct-scan                   # Skip SBOM, scan directly with Trivy
--run-reachability             # Enable reachability analysis

# Output control
--output-report REPORT_FILE     # Security report path
--output-consolidated CONS_FILE # Consolidated recommendations path
--trivy-output TRIVY_FILE      # Save raw Trivy output
```

## 🎛️ CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install tools
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
      
      - name: Run VulnReach Analysis
        run: |
          python security_sca_tool.py . --run-reachability
          
      - name: Upload Security Reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: security_findings/
```

### Exit Codes
- `0`: No vulnerabilities or only LOW/MEDIUM severity
- `1`: CRITICAL or HIGH severity vulnerabilities found
- `130`: Interrupted by user
- Other: Unexpected errors

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/yourusername/vulnreach.git
cd vulnreach
pip install -e .
```

### Running Tests
```bash
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [Syft](https://github.com/anchore/syft) - SBOM generation
- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanning
- [Grype](https://github.com/anchore/grype) - Alternative vulnerability scanner
- [OSV](https://osv.dev/) - Open Source Vulnerability database

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/yourusername/vulnreach/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/yourusername/vulnreach/discussions)
- 📚 **Documentation**: [Wiki](https://github.com/yourusername/vulnreach/wiki)

---

<div align="center">

**Built with ❤️ for security-conscious developers**

[⭐ Star us on GitHub](https://github.com/yourusername/vulnreach) | [📖 Read the Docs](https://vulnreach.readthedocs.io) | [💬 Join the Discussion](https://github.com/yourusername/vulnreach/discussions)

</div>
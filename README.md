# 🛡️ VulnReach - Smart Vulnerability Reachability Analyzer

[![Security](https://img.shields.io/badge/security-focused-red.svg)]()
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Git Support](https://img.shields.io/badge/git-supported-orange.svg)]()

> **Beyond version checking**: Discover which vulnerabilities in your dependencies actually matter by analyzing real code usage patterns and exploitability.

VulnReach is an intelligent vulnerability analysis tool that goes beyond traditional dependency scanning. While most tools simply check versions, VulnReach analyzes your actual codebase to determine which vulnerable packages are **truly reachable** and pose real risk to your application. Now with **git repository support** and **exploitability analysis**.

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

### 🤖 **Agent-Based Reachability Analysis** *(NEW - Recommended)*
- **ast-grep Foundation**: Fast, accurate AST-based code analysis across languages
- **Call Chain Tracing**: Traces execution paths from entry points to vulnerable functions
- **Confidence Scoring**: High/Medium/Low confidence levels for reachability assessment
- **4 Specialized Agents**:
  - **AST Agent**: Code structure analysis via ast-grep
  - **Dependency Agent**: Dependency tree analysis (pip, npm)
  - **Vulnerability Agent**: OSV/CVE database queries
  - **Reachability Agent**: Orchestrates full vulnerability analysis
- **Git Repository Support**: Analyze remote repos directly with auto-cleanup
- **Fast & Lightweight**: No SBOM generation overhead
- **Precise Results**: Know exactly which vulnerabilities can reach your code

### 🔍 **Smart Vulnerability Discovery**
- **SBOM Generation**: Uses [Syft](https://github.com/anchore/syft) to create comprehensive Software Bill of Materials
- **Vulnerability Scanning**: Leverages [Trivy](https://aquasecurity.github.io/trivy/) for industry-leading vulnerability detection
- **Multi-format Support**: SPDX, CycloneDX, and Syft native formats
- **Performance Tracking**: Detailed scan duration timing and metrics

### 🌐 **Git Repository Support**
- **Remote Repository Analysis**: Scan repositories directly from URLs without manual cloning
- **Multi-Platform Support**: GitHub, GitLab, Bitbucket, and custom git servers
- **SSH & HTTPS**: Supports both authentication methods
- **Automatic Cleanup**: Temporary clones are automatically cleaned up after analysis
- **Smart Naming**: Automatically extracts repository names for organized reporting

### 🧠 **Traditional Reachability Analysis**
- **Multi-Language Support**: Python, Java, JavaScript, Go, C#, PHP with automatic language detection
- **Static Code Analysis**: Parses your entire codebase using AST analysis (Python) or regex patterns (others)
- **Usage Pattern Detection**: Identifies imports, function calls, method calls, and instantiations
- **Dynamic Package Mapping**: Handles complex import-to-package mappings (e.g., `import yaml` → `PyYAML`)
- **Transitive Dependency Tracking**: Maps dependency relationships

### 💥 **Exploitability Analysis**
- **Public Exploit Detection**: Checks for publicly available exploits using SearchSploit
- **CVE Intelligence**: Enhanced vulnerability context and exploit availability
- **Risk Amplification**: Identifies vulnerabilities with known exploits in the wild
- **Prioritization Support**: Helps focus on vulnerabilities with active exploitation

### 🤖 **AI-Powered Analysis**
- **Intelligent Recommendations**: AI-powered vulnerability analysis and remediation guidance
- **Smart Prioritization**: Machine learning-based risk assessment and fix suggestions
- **Auto Configuration**: Automatic setup with `--init-config` for first-time users
- **Multi-Provider Support**: OpenAI, Anthropic, Google, Cohere, and more AI providers

### 📊 **Risk Prioritization**
- **CRITICAL**: Actively used across multiple files with direct function calls
- **HIGH**: Used with direct function calls
- **MEDIUM**: Imported across multiple files
- **LOW**: Limited usage detected
- **NOT_REACHABLE**: Not used in codebase (safe to ignore)

### 📈 **Comprehensive Reporting**
- **Executive Summary**: High-level risk overview with timing metrics
- **Detailed Analysis**: File-by-file usage contexts with call chains
- **Exploitability Reports**: Public exploit availability and context
- **Remediation Guidance**: Version upgrade recommendations
- **JSON + Markdown**: Multiple output formats for different use cases
- **Organized Output**: Structured reporting in `security_findings/project_name/` directories

## 📋 Prerequisites

### Required Tools

**For Agent-Based Analysis (Recommended):**
```bash
# Install ast-grep
brew install ast-grep  # macOS
# OR
cargo install ast-grep  # via Rust
# OR
npm install -g @ast-grep/cli  # via npm
```

**For Traditional Analysis:**
```bash
# Install Syft (SBOM generation)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy (vulnerability scanning)
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Or see: https://aquasecurity.github.io/trivy/latest/getting-started/installation/

# Git (for repository cloning - usually pre-installed)
# macOS: Xcode Command Line Tools
xcode-select --install

# Linux (Ubuntu/Debian)
sudo apt update && sudo apt install git

# Optional: SearchSploit for exploitability analysis
sudo apt update && sudo apt install exploitdb
```

Install Python dependencies:
```bash
pip install requests
```

## 🛠️ Installation

### Option 1: Install from PyPI (Recommended)
```bash
pip install vulnreach
```

### Option 2: Install from Source
```bash
git clone https://github.com/ihrishikesh0896/vulnreach.git
cd vulnreach
pip install -e .
```

### Option 3: Development Setup
```bash
git clone https://github.com/ihrishikesh0896/vulnreach.git
cd vulnreach
pip install -e ".[dev]"
```

## 🚀 Quick Start

### 🤖 Agent-Based Analysis (Recommended)

**Fast, precise reachability analysis with call chain tracing:**

```bash
# Full project analysis with agent system
vulnreach . --agent-mode

# Analyze remote git repository
vulnreach https://github.com/user/repo.git --agent-mode

# Analyze specific package
vulnreach . --analyze-package requests

# Analyze specific CVE
vulnreach . --analyze-cve CVE-2023-12345 --package-name urllib3

# Custom entry points
vulnreach . --agent-mode --entry-points "app.route,api.handler,main"

# Multi-language support
vulnreach . --agent-mode --language python --ecosystem PyPI
```

**Output:**
- 🟢 Risk Level: LOW/MEDIUM/HIGH/CRITICAL
- 📊 Reachable Vulnerabilities: X of Y total
- ✅ High Confidence Findings
- 📝 JSON + Markdown reports in `security_findings/`

---

### 🔍 Traditional SBOM-Based Analysis

**Comprehensive SBOM generation + vulnerability scanning:**

```bash
# Basic vulnerability scan
vulnreach /path/to/your/project

# Scan remote git repository
vulnreach https://github.com/user/repo.git

# With reachability analysis
vulnreach /path/to/your/project --run-reachability

# With exploitability analysis
vulnreach /path/to/your/project --run-exploitability

# Full traditional analysis (recommended)
vulnreach https://github.com/user/repo.git --run-reachability --run-exploitability
```

---

### 🤖 AI-Powered Analysis

```bash
# First time setup - creates config file
vulnreach --init-config

# AI-powered vulnerability analysis
vulnreach /path/to/your/project --llm-fix

# Note: Edit ~/.vulnreach/config/creds.yaml to add AI provider API keys
# Supports: OpenAI, Anthropic, Google, Cohere, Groq, and more
```

---

### 📊 Comparison: Agent vs Traditional

| Feature | Agent-Based (`--agent-mode`) | Traditional (`--run-reachability`) |
|---------|------------------------------|-----------------------------------|
| **Speed** | ⚡ Fast (no SBOM) | 🐢 Slower (SBOM + scan) |
| **Accuracy** | 🎯 High (ast-grep) | 📊 Medium (regex for most langs) |
| **Reachability** | 🔗 Call chain tracing | 📥 Import detection only |
| **Confidence** | ✅ Scored (high/med/low) | ❌ Binary (used/not used) |
| **Languages** | 🐍 Python (expanding) | 🌐 Python, Java, JS, Go, C#, PHP |
| **SBOM** | ❌ Not generated | ✅ Full SBOM compliance |
| **Exploits** | ❌ Not yet | ✅ SearchSploit integration |

**Recommendation:** Use both for comprehensive coverage!

```bash
vulnreach . --run-reachability --run-exploitability  # Traditional
vulnreach . --agent-mode                              # Agent-based
```

---

### Advanced Usage
```bash
# Use existing SBOM
vulnreach --sbom existing_sbom.json --run-reachability

# Save SBOM for reuse
vulnreach /path/to/project --output-sbom project_sbom.json --run-reachability

# Direct scan (skip SBOM generation)
vulnreach /path/to/project --direct-scan --run-reachability

# SSH git repository with custom analysis
vulnreach git@github.com:user/private-repo.git --run-reachability --run-exploitability

# Specify different SBOM formats
vulnreach /path/to/project --sbom-format cyclonedx-json --run-reachability
```

## 📊 Sample Output

### Basic Scan Output
```
🚀 Starting Security Analysis with Syft and Trivy...
📥 Cloning repository: https://github.com/user/vulnerable-app.git
✅ Repository cloned to: /tmp/vulnreach_clone_abc123
📁 Security findings will be saved to: security_findings/vulnerable-app

🛡️  SECURITY SCAN RESULTS
================================================================================
📊 Scan completed at: 2024-08-14T10:30:45
⏱️  Scan duration: 23.45 seconds
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

🧹 Cleaning up temporary clone directory: /tmp/vulnreach_clone_abc123
⏱️  Total scan duration: 23.45 seconds
```

### With Reachability Analysis
```
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

### With Exploitability Analysis *(NEW)*
```
💥 Running exploitability analysis using SearchSploit...

=== Exploitability Analysis Results ===
Total vulnerabilities analyzed: 23
Vulnerabilities with public exploits: 5
High-risk exploitable vulnerabilities: 2

💥 HIGH EXPLOITABILITY: CVE-2024-1234 - requests@2.25.1
   📊 CVSS Score: 9.8 (CRITICAL)
   🎯 Public Exploits Found: 3
   🔍 SearchSploit Results:
     - Python Requests 2.25.1 - Remote Code Execution
     - HTTP Parser Buffer Overflow Exploit
     - Multiple PoC exploits available
   
💥 Exploitability report saved to: security_findings/vulnerable-app/exploitability_report.json
```

## 🏗️ Project Structure

```
vulnreach/
├── src/
│   └── vulnreach/
│       ├── cli.py                      # CLI entry point
│       ├── core.py                     # Core components export
│       ├── tracer_.py                  # Main analysis engine
│       └── utils/
│           ├── __init__.py
│           ├── vuln_reachability_analyzer.py    # Core reachability analysis
│           ├── java_reachability_analyzer.py    # Java-specific analysis
│           ├── multi_language_analyzer.py       # Multi-language support
│           ├── exploitability_analyzer.py       # Exploitability analysis
│           └── get_metadata.py         # Dynamic package mapping
├── security_findings/                  # Generated reports (auto-created)
│   └── project_name/                   # Organized by project/repo name
│       ├── security_report.json       # Main vulnerability report
│       ├── consolidated.json          # Upgrade recommendations
│       ├── vulnerability_reachability_report.json  # Reachability analysis
│       ├── exploitability_report.json # Exploit analysis (NEW)
│       └── project.sbom.json         # Generated SBOM (optional)
├── tests/                             # Test suite
├── pyproject.toml                     # Modern Python packaging
└── README.md
```

### Report Organization *(NEW)*
Reports are now automatically organized by project name:
- **Local projects**: Uses directory name (e.g., `my-app` → `security_findings/my-app/`)
- **Git repositories**: Uses repo name (e.g., `vulnerable-app.git` → `security_findings/vulnerable-app/`)
- **Clean separation**: Each project gets its own directory for easy management

## 📋 Report Structure

### Security Report (`security_report.json`) *(ENHANCED)*
```json
{
  "scan_timestamp": "2024-08-14T10:30:45.123456",
  "scan_duration": 23.45,
  "tools": {
    "sbom_generator": "Syft",
    "vulnerability_scanner": "Trivy"
  },
  "summary": {
    "total_components": 127,
    "vulnerable_components": 8,
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

### Exploitability Analysis (`exploitability_report.json`) *(NEW)*
```json
{
  "scan_timestamp": "2024-08-14T10:30:45.123456",
  "analysis_summary": {
    "total_vulnerabilities_analyzed": 23,
    "vulnerabilities_with_exploits": 5,
    "high_risk_exploitable": 2,
    "searchsploit_available": true
  },
  "exploitable_vulnerabilities": [
    {
      "vulnerability_id": "CVE-2024-1234",
      "package_name": "requests",
      "package_version": "2.25.1",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "exploit_analysis": {
        "exploits_found": 3,
        "exploit_risk": "HIGH",
        "searchsploit_results": [
          "Python Requests 2.25.1 - Remote Code Execution",
          "HTTP Parser Buffer Overflow Exploit"
        ]
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

### Command Line Options *(UPDATED)*
```bash
# Target specification
target                          # Directory path OR git repository URL

# Core functionality
--sbom SBOM_FILE                 # Use existing SBOM file
--output-sbom SBOM_FILE         # Save generated SBOM
--sbom-format FORMAT            # SBOM format (spdx-json, cyclonedx-json, syft-json)

# Analysis options
--direct-scan                   # Skip SBOM, scan directly with Trivy
--run-reachability             # Enable multi-language reachability analysis
--run-exploitability           # Enable exploitability analysis (NEW)
--llm-fix                      # Use AI-powered analysis workflow (LATEST)
--init-config                  # Create default AI configuration file

# Output control
--output-report REPORT_FILE     # Security report path (includes scan timing)
--output-consolidated CONS_FILE # Consolidated recommendations path
--trivy-output TRIVY_FILE      # Save raw Trivy output

# Git repository support (automatic detection)
# Supports: https://github.com/user/repo.git
#          https://github.com/user/repo
#          git@github.com:user/repo.git
#          ssh://git@server.com/user/repo.git
```

### Supported Git Platforms *(NEW)*
- **GitHub**: `https://github.com/user/repo.git` or `https://github.com/user/repo`
- **GitLab**: `https://gitlab.com/user/repo.git` or `https://gitlab.com/user/repo`
- **Bitbucket**: `https://bitbucket.org/user/repo.git`
- **Custom Git servers**: Any valid git URL
- **SSH access**: `git@server.com:user/repo.git`
- **Private repositories**: Supported if git credentials are configured

## 🎛️ CI/CD Integration

### GitHub Actions Example *(ENHANCED)*
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
          # Core security tools
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          
          # Optional: Install SearchSploit for exploitability analysis
          sudo apt update && sudo apt install exploitdb
      
      - name: Run Complete VulnReach Analysis
        run: |
          # Full analysis with all features
          vulnreach . --run-reachability --run-exploitability
          
      - name: Upload Security Reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: security_findings/
          
      - name: Comment PR with Results
        if: github.event_name == 'pull_request'
        run: |
          # Example: Post summary to PR (customize as needed)
          echo "Security scan completed. Check artifacts for detailed reports."

  # Alternative: Scan external repository
  external-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install tools
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          
      - name: Scan External Repository
        run: |
          # Scan any public repository directly
          vulnreach https://github.com/user/target-repo.git --run-reachability --run-exploitability
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
git clone https://github.com/ihrishikesh0896/vulnreach.git
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

## 🚀 What's New

### Version 2.0 Features *(NEW)*
- 🌐 **Git Repository Support**: Scan remote repositories directly from URLs
- 💥 **Exploitability Analysis**: Check for public exploits using SearchSploit
- 🤖 **AI-Powered Analysis**: Intelligent vulnerability analysis with multiple AI providers
- ⏱️ **Performance Tracking**: Detailed scan duration metrics and timing
- 📁 **Smart Organization**: Auto-organized reports by project/repository name
- 🧹 **Automatic Cleanup**: Temporary git clones are cleaned up automatically
- 🔒 **Enhanced Security Reports**: Include scan timing and exploitability data

### Supported Workflows
- **Local Development**: Scan your development projects
- **Remote Analysis**: Analyze any public git repository
- **CI/CD Integration**: Automated security scanning in pipelines
- **Security Research**: Bulk analysis of multiple repositories
- **Compliance Checking**: Generate comprehensive security reports

## 📞 Support & Community

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/ihrishikesh0896/vulnreach/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/ihrishikesh0896/vulnreach/discussions)
- 📖 **Documentation**: [Official Docs](https://github.com/ihrishikesh0896/vulnreach/wiki)
- 🤝 **Contributing**: [Contributing Guide](CONTRIBUTING.md)

### Quick Help
```bash
# Get help with command options
vulnreach --help

# Examples with different targets
vulnreach https://github.com/user/repo.git --help
vulnreach /path/to/project --help
```

---

<div align="center">

**🛡️ Built with ❤️ for security-conscious developers**

*Now with Git repository support and exploitability analysis*

[⭐ Star us on GitHub](https://github.com/ihrishikesh0896/vulnreach) | [💬 Join the Discussion](https://github.com/ihrishikesh0896/vulnreach/discussions) | [📖 Read the Docs](https://github.com/ihrishikesh0896/vulnreach/wiki)

</div>
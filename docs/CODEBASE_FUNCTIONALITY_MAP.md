# VulnReach Codebase - Complete Functionality Map

**Document Version:** 1.0  
**Date:** February 14, 2026  
**Purpose:** Comprehensive documentation of all functionalities, flows, dependencies, and interdependencies before refactoring

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Entry Points](#entry-points)
4. [Core Components Map](#core-components-map)
5. [Detailed Flow Analysis](#detailed-flow-analysis)
6. [Module Dependencies](#module-dependencies)
7. [Data Flow Diagrams](#data-flow-diagrams)
8. [External Tool Dependencies](#external-tool-dependencies)
9. [Configuration System](#configuration-system)
10. [Output Artifacts](#output-artifacts)
11. [Inter-Module Communication](#inter-module-communication)
12. [Refactoring Recommendations](#refactoring-recommendations)

---

## Executive Summary

**VulnReach** is a Python vulnerability reachability analyzer that combines:
- **Static Analysis** (SBOM, SCA, Taint Analysis, SAST)
- **Dynamic Analysis** (Runtime Hooks, Container Execution)
- **Intelligence Layer** (AI Analysis, Exploitability Assessment, Correlation)
- **Multi-language Support** (Python, Java, JavaScript, Go, C#, PHP)

**Primary Goal:** Reduce false positives by determining which vulnerabilities are actually reachable and exploitable.

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Entry Points                             │
├─────────────────────────────────────────────────────────────────┤
│  • run_vulnreach.py (CLI wrapper)                               │
│  • src/vulnreach/cli.py (Main CLI entry)                        │
│  • src/vulnreach/tracer_.py (Legacy main entry)                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   Pipeline Orchestrator                         │
├─────────────────────────────────────────────────────────────────┤
│  src/vulnreach/pipeline/pipeline.py                             │
│  • VulnReachPipeline class                                      │
│  • Coordinates all analysis phases                              │
│  • Manages configuration and output                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────┬──────────────────┬────────────────────────────┐
│   Phase 1:       │   Phase 2:       │   Phase 3:                 │
│   Static         │   Dynamic        │   Correlation              │
│   Analysis       │   Analysis       │   & Intelligence           │
└──────────────────┴──────────────────┴────────────────────────────┘
```

### Conceptual Flow

```
Input Project
    ↓
1. Language Detection
    ↓
2. SBOM Generation (Syft)
    ↓
3. SCA Scanning (Trivy)
    ↓
4. Static Analysis Branch
    ├── Taint Analysis (Python AST)
    ├── SAST Analysis (Semgrep)
    ├── Call Graph Generation
    ├── Route Extraction
    └── Reachability Scoring
    ↓
5. Dynamic Analysis Branch (Conditional)
    ├── Container Detection
    ├── Runtime Hook Injection
    ├── Application Execution
    └── Event Collection
    ↓
6. Intelligence & Correlation
    ├── Static ↔ Dynamic Correlation
    ├── Exploitability Analysis
    ├── AI-Powered Prioritization
    └── RBOM Generation
    ↓
7. Output Generation
    ├── JSON Reports
    ├── HTML Dashboard
    ├── Markdown RBOM
    └── Unified Findings
```

---

## Entry Points

### 1. Primary Entry: `run_vulnreach.py`

**Location:** `/run_vulnreach.py`

**Purpose:** User-facing CLI wrapper that provides a simplified interface

**Functionality:**
- Parses command-line arguments
- Creates `PipelineConfig` from arguments
- Instantiates `VulnReachPipeline`
- Invokes `run_full_analysis()`

**Arguments:**
```bash
project_path          # Required: Path to project
--output, -o         # Output directory
--no-sbom            # Skip SBOM generation
--no-sca             # Skip SCA scanning
--no-exploits        # Skip exploitability analysis
--no-taint           # Skip static taint analysis
--no-dynamic         # Skip dynamic analysis
--no-correlation     # Skip correlation
--sbom-format        # SBOM format (spdx-json, cyclonedx-json, syft-json)
--docker-image       # Docker image for container analysis
--use-container      # Force container-based dynamic analysis
```

**Calls:**
- `vulnreach.pipeline.pipeline.VulnReachPipeline`

---

### 2. Main CLI: `src/vulnreach/cli.py`

**Purpose:** Package entry point (used when running `vulnreach` command)

**Functionality:**
- Initializes configuration system
- Calls `tracer_main()` (legacy main function)
- Handles exceptions and keyboard interrupts

**Functions:**
- `main()` - Entry point
- `_initialize_config()` - Loads configuration from `~/.vulnreach/config/creds.yaml`

**Calls:**
- `vulnreach.tracer_.main()`
- `vulnreach.config.get_config_loader()`

---

### 3. Legacy Main: `src/vulnreach/tracer_.py`

**Purpose:** Original main module with monolithic implementation

**Contains:**
- `Component` - Data class for SBOM components
- `Vulnerability` - Data class for vulnerabilities
- `SyftSBOMGenerator` - SBOM generation using Syft
- `TrivySCAScanner` - SCA scanning using Trivy
- `SecurityReporter` - Report generation
- `main()` - Legacy orchestration function

**Status:** Being deprecated in favor of pipeline architecture

---

## Core Components Map

### Component Hierarchy

```
vulnreach/
├── cli.py                          # CLI entry point
├── core.py                         # Core component exports
├── tracer_.py                      # Legacy main (2146 lines - needs refactoring)
├── config.py                       # Configuration management
├── ast_analyzer.py                 # AST utilities
│
├── pipeline/                       # Pipeline Orchestration
│   ├── pipeline.py                 # Main pipeline orchestrator
│   └── container_detector.py      # Container detection logic
│
├── taint/                          # Static Taint Analysis
│   └── static_taint.py             # Taint flow analysis
│
├── runtime/                        # Dynamic Analysis
│   └── dynamic_analyzer.py         # Runtime execution & hooks
│
├── correlation/                    # Correlation Engine
│   ├── correlator.py               # Static ↔ Dynamic correlation
│   ├── cve_runtime_mapper.py      # CVE to runtime mapping
│   ├── event_matcher.py           # Event matching logic
│   └── package_resolver.py        # Package name resolution
│
├── rbom/                           # Runtime Bill of Materials
│   ├── __init__.py                 # Package exports
│   ├── schema.py                   # RBOM data models
│   ├── builder.py                  # RBOM construction
│   └── serializer.py               # JSON/Markdown output
│
├── security/                       # Security Utilities
│
├── agents/                         # AI Agent System
│
└── utils/                          # Utility Modules
    ├── multi_language_analyzer.py  # Language detection
    ├── reachability_engine.py      # Sink-to-handler reachability
    ├── exploitability_analyzer.py  # Exploit assessment
    ├── ai_analyzer.py              # AI/LLM integration
    ├── semgrep_runner.py           # SAST execution
    ├── route_extractor.py          # Web route extraction
    ├── dependency_tree_analyzer.py # Dependency tree analysis
    ├── html_reporter.py            # HTML report generation
    ├── python_call_graph.py        # Python call graph
    ├── python_reachability_analyzer.py
    ├── java_call_graph.py          # Java call graph
    ├── java_reachability_analyzer.py
    ├── javascript_call_graph.py    # JavaScript call graph
    ├── javascript_reachability_analyzer.py
    ├── go_reachability_analyzer.py
    ├── php_reachability_analyzer.py
    ├── csharp_reachability_analyzer.py
    ├── ast_grep_wrapper.py         # AST-grep integration
    └── get_metadata.py             # Metadata extraction
```

---

## Detailed Flow Analysis

### Flow 1: Full Pipeline Execution

**Trigger:** User runs `python run_vulnreach.py <project_path>`

**Steps:**

#### 1.1 Initialization
```
run_vulnreach.py::main()
    ↓
Parse CLI arguments
    ↓
Create PipelineConfig
    ↓
Instantiate VulnReachPipeline(project_root, config)
    ↓
Call pipeline.run_full_analysis()
```

#### 1.2 Static Analysis Phase
```
VulnReachPipeline._run_static_phase()
    ↓
┌─────────────────────────────────────────┐
│ 1. SBOM Generation                      │
├─────────────────────────────────────────┤
│ SyftSBOMGenerator.generate_sbom()       │
│   ↓                                     │
│ Execute: syft <project> -o sbom.json    │
│   ↓                                     │
│ _enhance_sbom_with_transitive_info()    │
│   ↓                                     │
│ ProjectLanguageDetector.detect_language()│
│   ↓                                     │
│ DependencyTreeAnalyzer.get_all_dependencies()│
│   ↓                                     │
│ Enrich SBOM with transitive markers     │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 2. SCA Scanning                         │
├─────────────────────────────────────────┤
│ TrivySCAScanner.scan_sbom()             │
│   ↓                                     │
│ Execute: trivy sbom sbom.json           │
│   ↓                                     │
│ _parse_trivy_output()                   │
│   ↓                                     │
│ Build Vulnerability[] list              │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 3. Exploitability Analysis              │
├─────────────────────────────────────────┤
│ ExploitabilityAnalyzer.analyze_vulnerability_batch()│
│   ↓                                     │
│ For each CVE:                           │
│   ├─ Query SearchSploit                │
│   ├─ Query ExploitDB API               │
│   ├─ Query GitHub exploits             │
│   └─ Calculate exploitability score    │
│   ↓                                     │
│ generate_exploitability_report()        │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 4. Static Taint Analysis                │
├─────────────────────────────────────────┤
│ analyze_project_taint()                 │
│   ↓                                     │
│ StaticTaintAnalyzer.analyze_project()   │
│   ↓                                     │
│ For each .py file:                      │
│   ├─ Parse AST                          │
│   ├─ SourceDetector.visit() → sources  │
│   ├─ SinkDetector.visit() → sinks      │
│   └─ _build_flows() → TaintFlow[]      │
│   ↓                                     │
│ _map_flows_to_packages()                │
│   ↓                                     │
│ Save static_taint_flows.json            │
└─────────────────────────────────────────┘
```

#### 1.3 Dynamic Analysis Phase (Conditional)
```
VulnReachPipeline._run_dynamic_phase()
    ↓
┌─────────────────────────────────────────┐
│ 1. Container Detection                  │
├─────────────────────────────────────────┤
│ ContainerDetector.detect()              │
│   ↓                                     │
│ Check for:                              │
│   ├─ Dockerfile                         │
│   ├─ docker-compose.yml                 │
│   └─ Run instructions in README         │
│   ↓                                     │
│ Determine entrypoint                    │
│   ↓                                     │
│ Return ContainerInfo                    │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ 2. Runtime Analysis                     │
├─────────────────────────────────────────┤
│ If use_container:                       │
│   ContainerDynamicAnalyzer.run_container_analysis()│
│ Else:                                   │
│   DynamicAnalyzer.run_dynamic_analysis()│
│     ↓                                   │
│ Execute: python runtime_hooks/runner.py <entrypoint>│
│     ↓                                   │
│ runtime_hooks system:                   │
│   ├─ hooks/imports.py → Track imports  │
│   ├─ hooks/sinks.py → Track sink calls │
│   ├─ hooks/audit.py → Track audit events│
│   └─ hooks/events.py → Collect events  │
│     ↓                                   │
│ _extract_json_from_stdout()             │
│     ↓                                   │
│ _process_events() → DynamicFinding[]    │
│     ↓                                   │
│ Save dynamic_findings.json              │
└─────────────────────────────────────────┘
```

#### 1.4 Correlation Phase
```
VulnReachPipeline._run_correlation_phase()
    ↓
┌─────────────────────────────────────────┐
│ FindingCorrelator.correlate_findings()  │
├─────────────────────────────────────────┤
│ Input:                                  │
│   ├─ vulnerabilities (from Trivy)      │
│   ├─ taint_flows (from static)         │
│   └─ dynamic_results (from hooks)      │
│     ↓                                   │
│ For each vulnerability:                 │
│   ├─ _check_runtime_loaded()           │
│   ├─ _check_sink_executed()            │
│   ├─ _determine_verdict()              │
│   │   • CONFIRMED (high confidence)    │
│   │   • LIKELY (medium confidence)     │
│   │   • POSSIBLE (static only)         │
│   │   • UNLIKELY (not observed)        │
│   └─ Build CorrelatedFinding            │
│     ↓                                   │
│ Save correlated_findings.json           │
└─────────────────────────────────────────┘
```

#### 1.5 Output Generation
```
VulnReachPipeline._generate_unified_output()
    ↓
┌─────────────────────────────────────────┐
│ Consolidate all findings                │
├─────────────────────────────────────────┤
│ Merge:                                  │
│   ├─ SBOM data                          │
│   ├─ Vulnerabilities                    │
│   ├─ Taint flows                        │
│   ├─ Dynamic findings                   │
│   ├─ Correlation results                │
│   └─ Exploitability data                │
│     ↓                                   │
│ Generate outputs:                       │
│   ├─ complete_findings.json             │
│   ├─ RBOM (JSON + Markdown)             │
│   ├─ HTML report                        │
│   └─ AI analysis (optional)             │
└─────────────────────────────────────────┘
```

---

### Flow 2: Multi-Language Analysis

**Trigger:** Non-Python project detected

**Steps:**

```
ProjectLanguageDetector.detect_language()
    ↓
Language = java | javascript | go | csharp | php
    ↓
run_multi_language_analysis()
    ↓
Switch by language:
    ├─ Python → run_python_reachability_analysis()
    │             ├─ Build call graph
    │             ├─ Extract routes
    │             └─ Calculate reachability
    ├─ Java → run_java_reachability_analysis()
    │           ├─ Use ast-grep for parsing
    │           └─ Analyze Maven/Gradle deps
    ├─ JavaScript → run_javascript_reachability_analysis()
    │                ├─ Parse npm package.json
    │                └─ Analyze node_modules
    ├─ Go → run_go_reachability_analysis()
    ├─ C# → run_csharp_reachability_analysis()
    └─ PHP → run_php_reachability_analyzer()
```

**Note:** Advanced features (taint analysis, dynamic hooks) only work for Python. Other languages get SBOM + SCA + basic reachability.

---

### Flow 3: Reachability Engine

**Purpose:** Link SAST findings to web handlers/routes

**Steps:**

```
run_reachability_engine()
    ↓
Load inputs:
    ├─ semgrep.json (SAST findings)
    └─ routes.json (extracted routes)
    ↓
For each SAST finding:
    ↓
    ├─ _enclosing_handler() → Find function containing sink
    ├─ _match_route() → Match handler to route
    ├─ _compute_reachability_score()
    │     Scoring:
    │     ├─ +0.4 if handler found
    │     ├─ +0.3 if route matched
    │     ├─ +0.2 if taint hint exists
    │     └─ +0.1 if severity is HIGH/CRITICAL
    └─ Filter score < 0.4
    ↓
Save sink_handler_reachability.json
```

---

### Flow 4: AI Analysis

**Trigger:** When AI providers configured

**Steps:**

```
AIVulnerabilityAnalyzer.analyze_integrated_results()
    ↓
_integrate_vulnerability_data()
    ├─ Merge vuln_data, reachability_data, exploit_data
    └─ Create unified vulnerability records
    ↓
For each vulnerability:
    ↓
    _analyze_single_vulnerability_with_ai()
        ├─ Build LLM prompt with context
        ├─ Call LLM API (OpenAI/Anthropic/local)
        ├─ Parse response
        └─ Extract:
            ├─ Priority score (0-10)
            ├─ Recommendation text
            ├─ Remediation steps
            ├─ Short-term actions
            ├─ Long-term actions
            └─ Risk assessment
    ↓
_generate_ai_summary()
    ├─ Calculate overall security score
    ├─ Identify top recommendations
    └─ Generate compliance considerations
    ↓
Save ai_analysis.json
```

---

### Flow 5: RBOM Generation

**Purpose:** Create Runtime Bill of Materials

**Steps:**

```
create_rbom_from_analysis()
    ↓
RBOMBuilder.build()
    ├─ Set target info
    ├─ Add components from SBOM
    ├─ Add vulnerabilities with reachability
    │     For each vuln:
    │     ├─ Map to component
    │     ├─ Add runtime evidence
    │     ├─ Add static evidence
    │     └─ Set verdict/confidence
    ├─ Add execution summary
    └─ Build RBOM object
    ↓
RBOMSerializer.serialize()
    ├─ to_json() → rbom.json
    └─ to_markdown() → rbom_report.md
```

---

## Module Dependencies

### Dependency Graph

```
┌──────────────────────────────────────────────────────────────────┐
│                         External Tools                           │
├──────────────────────────────────────────────────────────────────┤
│ • Syft (SBOM generation)                                         │
│ • Trivy (SCA scanning)                                           │
│ • Semgrep (SAST analysis)                                        │
│ • SearchSploit (Exploitability)                                  │
│ • Docker (Container analysis)                                    │
│ • ast-grep (Multi-language parsing)                              │
│ • pipdeptree (Python dependency tree)                            │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│                      Python Dependencies                         │
├──────────────────────────────────────────────────────────────────┤
│ • requests (HTTP calls)                                          │
│ • pathlib (File operations)                                      │
│ • ast (Python AST parsing)                                       │
│ • json (Data serialization)                                      │
│ • subprocess (External tool execution)                           │
│ • dataclasses (Data structures)                                  │
│ • typing (Type hints)                                            │
└──────────────────────────────────────────────────────────────────┘
```

### Internal Module Dependencies

```
tracer_.py (Legacy)
    ↓ uses
    ├─ utils/multi_language_analyzer.py
    ├─ utils/reachability_engine.py
    ├─ utils/exploitability_analyzer.py
    ├─ utils/ai_analyzer.py
    ├─ utils/html_reporter.py
    ├─ rbom/*
    ├─ runtime/dynamic_analyzer.py
    ├─ correlation/correlator.py
    └─ config.py

pipeline/pipeline.py (New)
    ↓ uses
    ├─ tracer_.py (SyftSBOMGenerator, TrivySCAScanner)
    ├─ taint/static_taint.py
    ├─ pipeline/container_detector.py
    ├─ runtime/dynamic_analyzer.py
    └─ correlation/correlator.py

correlation/correlator.py
    ↓ uses
    ├─ tracer_.py (Vulnerability dataclass)
    └─ No external dependencies

runtime/dynamic_analyzer.py
    ↓ uses
    └─ runtime_hooks/* (external to package)

taint/static_taint.py
    ↓ uses
    ├─ ast (Python stdlib)
    └─ No internal dependencies

utils/multi_language_analyzer.py
    ↓ uses
    ├─ utils/python_reachability_analyzer.py
    ├─ utils/java_reachability_analyzer.py
    ├─ utils/javascript_reachability_analyzer.py
    ├─ utils/go_reachability_analyzer.py
    ├─ utils/php_reachability_analyzer.py
    └─ utils/csharp_reachability_analyzer.py

utils/reachability_engine.py
    ↓ uses
    └─ None (standalone)

utils/exploitability_analyzer.py
    ↓ uses
    ├─ requests
    └─ subprocess (for searchsploit)

utils/ai_analyzer.py
    ↓ uses
    ├─ requests
    └─ config.py

rbom/builder.py
    ↓ uses
    ├─ rbom/schema.py
    └─ correlation/correlator.py (for CorrelatedFinding)

rbom/serializer.py
    ↓ uses
    └─ rbom/schema.py
```

---

## Data Flow Diagrams

### Data Structure Flow

```
Project Directory
    ↓
┌─────────────────────────────────────────┐
│ Language Detection                      │
│ Output: language_name (string)          │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ SBOM Generation                         │
│ Output: sbom.json                       │
│ Schema: SPDX/CycloneDX/Syft             │
│ Contains:                               │
│   - packages[]                          │
│   - is_direct_dependency (enhanced)     │
│   - dependency_depth (enhanced)         │
│   - required_by[] (enhanced)            │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ SCA Scanning                            │
│ Output: trivy_output.json               │
│ Schema: Trivy JSON                      │
│ Contains:                               │
│   - Results[]                           │
│     - Vulnerabilities[]                 │
│       - VulnerabilityID                 │
│       - PkgName                         │
│       - Severity                        │
│       - CVSS                            │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Vulnerability List                      │
│ Data: List[Vulnerability]               │
│ Fields:                                 │
│   - vulnerability_id                    │
│   - pkg_name                            │
│   - pkg_version                         │
│   - severity                            │
│   - cvss_score                          │
│   - fixed_version                       │
└─────────────────────────────────────────┘
    ↓
    ├──────────────────────────────────────┐
    │                                      │
    ↓ Static Branch                       ↓ Dynamic Branch
┌────────────────────────┐    ┌──────────────────────────┐
│ Taint Analysis         │    │ Runtime Hooks            │
│ Output:                │    │ Output:                  │
│   static_taint_flows   │    │   dynamic_findings.json  │
│   .json                │    │ Schema:                  │
│ Schema:                │    │   - findings[]           │
│   {pkg_name: [flows]}  │    │     - finding_type       │
│   TaintFlow:           │    │     - package_name       │
│     - source           │    │     - function_name      │
│     - sink             │    │     - sink_type          │
│     - confidence       │    │   - summary              │
└────────────────────────┘    └──────────────────────────┘
    │                                      │
    └──────────────┬───────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│ Correlation Engine                      │
│ Output: correlated_findings.json        │
│ Schema:                                 │
│   - findings[]                          │
│     - vulnerability_id                  │
│     - verdict (CONFIRMED/LIKELY/...)    │
│     - confidence (HIGH/MEDIUM/LOW)      │
│     - priority (CRITICAL/HIGH/...)      │
│     - static_evidence                   │
│     - dynamic_evidence                  │
│     - runtime_loaded                    │
│     - sink_executed                     │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ RBOM Generation                         │
│ Outputs:                                │
│   - rbom.json                           │
│   - rbom_report.md                      │
│ Schema:                                 │
│   - target                              │
│   - components[]                        │
│   - vulnerabilities[]                   │
│     - reachability                      │
│     - verdict                           │
│     - runtime_evidence                  │
│     - static_evidence                   │
│   - execution_summary                   │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│ Unified Output                          │
│ Output: complete_findings.json          │
│ Consolidates all data                   │
└─────────────────────────────────────────┘
```

---

## External Tool Dependencies

### Tool Dependency Matrix

| Tool | Purpose | Required | Fallback | Detection Method |
|------|---------|----------|----------|------------------|
| **Syft** | SBOM Generation | Yes | None (fails) | `shutil.which('syft')` |
| **Trivy** | SCA Scanning | Yes | None (fails) | `shutil.which('trivy')` |
| **Semgrep** | SAST Analysis | No | Skip SAST | `shutil.which('semgrep')` |
| **SearchSploit** | Exploit DB | No | Skip exploits | `shutil.which('searchsploit')` |
| **Docker** | Container Analysis | No | Local execution | `shutil.which('docker')` |
| **pipdeptree** | Dependency Tree | No | Basic analysis | `subprocess.run(['pipdeptree', '--version'])` |
| **ast-grep** | Multi-language Parse | No | Skip languages | `shutil.which('ast-grep')` |

### Tool Invocation Examples

**Syft:**
```bash
syft <target> -o spdx-json=sbom.json --quiet
```

**Trivy:**
```bash
trivy sbom sbom.json --format json --output trivy_output.json --quiet
```

**Semgrep:**
```bash
semgrep scan --json --quiet --timeout 120 --config p/security-audit \
  --exclude env --exclude tests <target>
```

**SearchSploit:**
```bash
searchsploit --json <CVE-ID>
```

**Docker:**
```bash
docker run --rm \
  -v <hooks_dir>:/tmp/vulnreach_hooks \
  -v <project_dir>:/app \
  -w /app \
  <image> python3 /tmp/vulnreach_hooks/runner.py <entrypoint>
```

---

## Configuration System

### Configuration Files

**Location:** `~/.vulnreach/config/creds.yaml`

**Schema:**
```yaml
providers:
  openai:
    api_key: "sk-..."
    model: "gpt-4"
  anthropic:
    api_key: "..."
    model: "claude-3-opus"
  local:
    endpoint: "http://localhost:11434"
    model: "llama2"

preferences:
  default_provider: "openai"
  enable_ai_analysis: true
  timeout_seconds: 60
```

**Loading:**
```python
from vulnreach.config import get_config_loader

config_loader = get_config_loader()
config = config_loader.get_config()
```

**Environment Variables:**
- `LLM_HOST` - LLM endpoint (default: http://localhost:11434)
- `LLM_GENERATE_PATH` - API path (default: /api/generate)
- `LLM_TIMEOUT` - Request timeout (default: 60)
- `LLM_RETRIES` - Retry count (default: 2)
- `VULNREACH_AI_MOCK` - Enable mock mode (default: 0)
- `VULNREACH_DEBUG_IMPORTS` - Debug import errors (default: 0)
- `SEMGREP_SEND_METRICS` - Disable Semgrep metrics (default: off)

---

## Output Artifacts

### File Structure

```
security_findings/<project_name>/
├── sbom.json                          # Software Bill of Materials
├── trivy_output.json                  # SCA scan results
├── exploitability_report.json         # Exploit analysis
├── static_taint_flows.json            # Static taint analysis
├── dynamic_findings.json              # Runtime execution data
├── semgrep.json                       # SAST findings (optional)
├── routes.json                        # Extracted routes (optional)
├── sink_handler_reachability.json     # Reachability scores
├── correlated_findings.json           # Correlated results
├── rbom.json                          # Runtime BOM (JSON)
├── rbom_report.md                     # Runtime BOM (Markdown)
├── complete_findings.json             # Unified output
├── report.html                        # HTML dashboard (optional)
├── ai_analysis.json                   # AI insights (optional)
└── python_vulnerability_reachability_report.json  # Language-specific
```

### Output Schema Reference

#### complete_findings.json
```json
{
  "metadata": {
    "project_name": "string",
    "analysis_timestamp": "ISO8601",
    "pipeline_version": "string",
    "phases_completed": ["sbom", "sca", "taint", "dynamic", "correlation"]
  },
  "summary": {
    "total_vulnerabilities": 0,
    "by_severity": {},
    "by_verdict": {},
    "by_priority": {}
  },
  "sbom": { },
  "vulnerabilities": [ ],
  "taint_flows": { },
  "dynamic_findings": { },
  "correlated_findings": [ ],
  "exploitability": { },
  "rbom": { }
}
```

#### correlated_findings.json
```json
{
  "metadata": {
    "timestamp": "ISO8601",
    "total_findings": 0,
    "verdicts": {
      "CONFIRMED": 0,
      "LIKELY": 0,
      "POSSIBLE": 0,
      "UNLIKELY": 0
    }
  },
  "findings": [
    {
      "vulnerability_id": "CVE-XXXX-XXXX",
      "package_name": "pyyaml",
      "package_version": "5.3.1",
      "severity": "CRITICAL",
      "verdict": "CONFIRMED",
      "confidence": "HIGH",
      "priority": "CRITICAL",
      "static_evidence": {
        "title": "string",
        "cvss_score": 9.8,
        "taint_flows": []
      },
      "dynamic_evidence": {
        "package_loaded": true,
        "sink_executed": true,
        "execution_count": 3
      },
      "correlation_reason": "string"
    }
  ]
}
```

---

## Inter-Module Communication

### Communication Patterns

#### 1. Pipeline → Modules (Command Pattern)

```python
# Pipeline orchestrates, modules execute
pipeline.run_full_analysis()
    → syft.generate_sbom()
    → trivy.scan_sbom()
    → analyzer.analyze_project_taint()
    → dynamic.run_dynamic_analysis()
    → correlator.correlate_findings()
```

#### 2. Data Passing (Shared State)

```python
# Pipeline maintains shared state
class VulnReachPipeline:
    self.sbom_path = None          # Set by phase 1.1
    self.components = []            # Set by phase 1.1
    self.vulnerabilities = []       # Set by phase 1.2
    self.exploitability_results = []  # Set by phase 1.3
    self.taint_flows = {}           # Set by phase 1.4
    self.dynamic_results = None     # Set by phase 2
    self.correlated_findings = []   # Set by phase 3
```

#### 3. File-Based Communication

```
Module A writes JSON
    ↓
File System
    ↓
Module B reads JSON
```

Example:
```python
# Dynamic Analyzer writes
dynamic_analyzer.run_dynamic_analysis(entrypoint, "dynamic_findings.json")

# Correlator reads
with open("dynamic_findings.json") as f:
    dynamic_findings = json.load(f)
```

#### 4. Return Value Propagation

```python
# Cascading returns
components = syft.parse_sbom_components(sbom_path)
    ↓
vulnerabilities = trivy.scan_sbom(sbom_path)
    ↓
taint_flows = analyze_project_taint(project_root, vulnerabilities)
    ↓
correlated = correlator.correlate_findings(
    vulnerabilities,
    dynamic_findings
)
```

---

## Refactoring Recommendations

### Critical Issues Identified

#### 1. **Monolithic tracer_.py (2146 lines)**

**Problem:** Single file contains multiple concerns:
- SBOM generation
- SCA scanning
- Report generation
- Main orchestration
- Utility functions

**Recommendation:**
- Already partially addressed with `pipeline/pipeline.py`
- Complete migration to pipeline architecture
- Keep only data classes in `tracer_.py`
- Move utilities to dedicated modules

#### 2. **Mixed Responsibilities**

**Problem:** Modules doing too much
- `tracer_.py` does orchestration + tool wrapping + reporting
- `pipeline.py` does orchestration + configuration + execution

**Recommendation:**
- Separate concerns:
  - **Orchestration** → `pipeline/orchestrator.py`
  - **Configuration** → `config/manager.py`
  - **Tool Wrappers** → `tools/syft_wrapper.py`, `tools/trivy_wrapper.py`
  - **Reporters** → `reports/generator.py`

#### 3. **Inconsistent Error Handling**

**Problem:** Mix of exceptions, print statements, and silent failures

**Recommendation:**
- Define custom exception hierarchy:
  ```python
  class VulnReachError(Exception): pass
  class ToolNotFoundError(VulnReachError): pass
  class AnalysisFailedError(VulnReachError): pass
  ```
- Use logging instead of print
- Propagate errors to top level

#### 4. **Tight Coupling**

**Problem:** Modules directly import each other
- `tracer_.py` imports from `utils/*`
- `pipeline.py` imports from `tracer_.py`
- Circular dependencies possible

**Recommendation:**
- Introduce interfaces/protocols:
  ```python
  class SBOMGenerator(Protocol):
      def generate_sbom(self, target: str, output: str) -> bool: ...
  
  class SCAScanner(Protocol):
      def scan_sbom(self, sbom_path: str) -> List[Vulnerability]: ...
  ```
- Use dependency injection in pipeline

#### 5. **Data Model Confusion**

**Problem:** Multiple representations of same data
- `Vulnerability` dataclass in `tracer_.py`
- `CorrelatedFinding` in `correlation/correlator.py`
- `AIAnalysisResult` in `utils/ai_analyzer.py`
- Dict representations in JSON

**Recommendation:**
- Define canonical models in `models/` directory:
  ```
  models/
  ├── vulnerability.py
  ├── component.py
  ├── finding.py
  └── analysis_result.py
  ```
- Use Pydantic for validation
- Single source of truth for schemas

#### 6. **Lack of Abstraction**

**Problem:** Direct subprocess calls scattered throughout
```python
subprocess.run(['syft', target, '-o', output])
subprocess.run(['trivy', 'sbom', sbom_path])
```

**Recommendation:**
- Abstract tool execution:
  ```python
  class ToolExecutor:
      def execute(self, cmd: List[str]) -> ToolResult:
          # Centralized execution, logging, error handling
  ```

#### 7. **Testing Challenges**

**Problem:** Hard to test due to:
- External tool dependencies
- File system operations
- Long-running processes

**Recommendation:**
- Mock external tools
- Use temporary directories for tests
- Break down long functions
- Add unit tests for core logic

#### 8. **Configuration Sprawl**

**Problem:** Config in multiple places:
- CLI arguments
- Environment variables
- YAML file
- Hardcoded defaults

**Recommendation:**
- Single configuration source with priority:
  1. CLI args (highest)
  2. Environment variables
  3. Config file
  4. Defaults (lowest)
- Use Pydantic Settings

#### 9. **Incomplete Type Hints**

**Problem:** Inconsistent typing
- Some functions fully typed
- Others using `Any` or no hints
- Runtime type errors possible

**Recommendation:**
- Add mypy to CI
- Enforce type checking
- Complete type annotations

#### 10. **Documentation Gaps**

**Problem:** Missing documentation for:
- Internal module contracts
- Data flow between modules
- Expected outputs
- Error conditions

**Recommendation:**
- Add docstrings to all public APIs
- Document data schemas
- Create architectural diagrams
- Maintain this functionality map

---

## Suggested Refactored Structure

```
vulnreach/
├── __init__.py
├── __main__.py                    # Entry point
│
├── cli/
│   ├── __init__.py
│   ├── commands.py                # CLI command definitions
│   └── arguments.py               # Argument parsing
│
├── config/
│   ├── __init__.py
│   ├── loader.py                  # Configuration loading
│   ├── schema.py                  # Configuration schema
│   └── defaults.py                # Default values
│
├── models/
│   ├── __init__.py
│   ├── vulnerability.py           # Vulnerability model
│   ├── component.py               # Component model
│   ├── finding.py                 # Finding models
│   └── schemas.py                 # JSON schemas
│
├── tools/
│   ├── __init__.py
│   ├── base.py                    # Abstract base for tools
│   ├── syft.py                    # Syft wrapper
│   ├── trivy.py                   # Trivy wrapper
│   ├── semgrep.py                 # Semgrep wrapper
│   └── executor.py                # Command execution
│
├── analyzers/
│   ├── __init__.py
│   ├── taint/
│   │   ├── __init__.py
│   │   ├── analyzer.py
│   │   ├── sources.py
│   │   └── sinks.py
│   ├── dynamic/
│   │   ├── __init__.py
│   │   ├── analyzer.py
│   │   ├── hooks.py
│   │   └── container.py
│   └── reachability/
│       ├── __init__.py
│       ├── engine.py
│       └── scorer.py
│
├── correlation/
│   ├── __init__.py
│   ├── engine.py
│   ├── strategies.py
│   └── verdicts.py
│
├── intelligence/
│   ├── __init__.py
│   ├── exploitability.py
│   ├── ai_analyzer.py
│   └── prioritizer.py
│
├── pipeline/
│   ├── __init__.py
│   ├── orchestrator.py            # Main orchestration
│   ├── phases.py                  # Phase definitions
│   └── context.py                 # Shared context
│
├── reports/
│   ├── __init__.py
│   ├── generator.py               # Report generation
│   ├── formatters/
│   │   ├── json.py
│   │   ├── html.py
│   │   └── markdown.py
│   └── templates/
│
├── rbom/
│   ├── __init__.py
│   ├── schema.py
│   ├── builder.py
│   └── serializer.py
│
└── utils/
    ├── __init__.py
    ├── file_system.py
    ├── language_detector.py
    └── dependency_tree.py
```

---

## Next Steps for Refactoring

### Phase 1: Foundation (Week 1-2)
1. ✅ Create this documentation
2. Create `models/` with canonical data models
3. Setup mypy + linting
4. Add comprehensive test fixtures

### Phase 2: Tool Abstraction (Week 3-4)
1. Create `tools/` with wrapper classes
2. Implement `ToolExecutor` for subprocess management
3. Add tool detection and validation
4. Mock interfaces for testing

### Phase 3: Module Separation (Week 5-6)
1. Extract analyzers from `tracer_.py`
2. Move utilities to proper locations
3. Separate concerns in pipeline
4. Update imports throughout

### Phase 4: Configuration Refactor (Week 7)
1. Consolidate configuration system
2. Implement priority-based config loading
3. Validate all configuration at startup
4. Document configuration options

### Phase 5: Testing & Documentation (Week 8)
1. Add unit tests for core modules
2. Add integration tests
3. Update all docstrings
4. Create API documentation
5. Update README with new structure

### Phase 6: Migration & Cleanup (Week 9-10)
1. Deprecate old entry points
2. Update CLI to use new structure
3. Remove redundant code
4. Performance optimization
5. Final validation

---

## Appendix: Function Call Chains

### Complete Analysis Chain

```
main() [run_vulnreach.py]
  → VulnReachPipeline.__init__()
    → VulnReachPipeline.run_full_analysis()
      → _run_static_phase()
        → SyftSBOMGenerator.__init__()
          → _find_syft()
        → SyftSBOMGenerator.generate_sbom()
          → subprocess.run(['syft', ...])
          → _enhance_sbom_with_transitive_info()
            → ProjectLanguageDetector.detect_language()
            → get_dependency_analyzer()
              → PythonDependencyTreeAnalyzer()
            → DependencyTreeAnalyzer.get_all_dependencies()
          → parse_sbom_components()
        → TrivySCAScanner.__init__()
          → _find_trivy()
        → TrivySCAScanner.scan_sbom()
          → subprocess.run(['trivy', ...])
          → _parse_trivy_output()
        → ExploitabilityAnalyzer.analyze_vulnerability_batch()
          → For each CVE:
            → _query_searchsploit()
            → _query_exploitdb_api()
            → _query_github_exploits()
            → _calculate_exploitability_score()
          → generate_exploitability_report()
        → analyze_project_taint()
          → StaticTaintAnalyzer.analyze_project()
            → _find_python_files()
            → For each file:
              → _analyze_file()
                → SourceDetector().visit(ast.parse(code))
                → SinkDetector().visit(ast.parse(code))
            → _build_flows()
            → _map_flows_to_packages()
      → _run_dynamic_phase()
        → ContainerDetector.detect()
          → _find_dockerfile()
          → _find_compose_file()
          → _parse_run_instructions()
        → DynamicAnalyzer.run_dynamic_analysis()
          → subprocess.run([sys.executable, 'runner.py', entrypoint])
          → _extract_json_from_stdout()
          → _process_events()
          → _generate_summary()
      → _run_correlation_phase()
        → FindingCorrelator.correlate_findings()
          → For each vulnerability:
            → _check_runtime_loaded()
            → _check_sink_executed()
            → _determine_verdict()
          → save_correlated_findings()
      → _generate_unified_output()
        → create_rbom_from_analysis()
          → RBOMBuilder.build()
        → save_rbom()
          → RBOMSerializer.to_json()
          → RBOMSerializer.to_markdown()
```

---

## Document Maintenance

**Owners:** Engineering Team  
**Review Frequency:** Before each major refactor  
**Update Triggers:**
- New module added
- Flow changed
- Architecture modified
- External tool changed

**Version History:**
- v1.0 (2026-02-14): Initial comprehensive documentation

---

**END OF DOCUMENT**


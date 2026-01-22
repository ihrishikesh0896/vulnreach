    # VulnReach Security Analysis - TPM-2 Evaluation
**Evaluator Role:** Principal Application Security Engineer + Security Architect  
**Focus:** Reachability Analysis → RBOM (Runtime Bill of Materials)  
**Philosophy:** Truth, not noise | Observation, not exploitation  
**Evaluation Date:** January 21, 2026

---

## TASK 1: DEEP CODE ANALYSIS

### Core Components Analysis

#### 1. **src/vulnreach/tracer_.py** (Main Entry Point)
**What it does:**
- CLI orchestrator for all security analysis workflows
- Manages SBOM generation (Syft) and vulnerability scanning (Trivy)
- Coordinates static + dynamic analysis pipelines
- Git repository cloning and cleanup
- Report consolidation and generation

**Key Functions:**
- `SyftSBOMGenerator.generate_sbom()` - Creates SBOM from target
- `TrivySCAScanner.scan_sbom()` - Maps CVEs to dependencies
- `consolidate_fixed_versions()` - Aggregates remediation advice
- `main()` - CLI argument parsing and workflow coordination

**Signals Produced:**
- SBOM (JSON): Component inventory
- Security report (JSON): CVE mappings with severity
- Consolidated fixes (JSON): Remediation recommendations

**Security Questions Answered:**
- "What components are in this application?"
- "Which components have known vulnerabilities?"
- "What versions fix these vulnerabilities?"

---

#### 2. **runtime_hooks/** (Dynamic Analysis - Phase 1 Complete)
**What it does:**
- Observes Python application runtime behavior without modification
- Captures imports, dangerous function calls (eval, exec, Popen), interpreter events
- Produces structured JSON events with stack traces

**Key Modules:**
- `runner.py` - Entry point that installs hooks before execution
- `hooks/events.py` - In-memory event buffer with emit()/flush()
- `hooks/audit.py` - sys.addaudithook for interpreter signals
- `hooks/imports.py` - builtins.__import__ wrapper
- `hooks/sinks.py` - eval/exec/subprocess.Popen wrappers

**Signals Produced:**
- Import events: `{"type": "import", "data": {"module": "...", "stack": [...]}}`
- Sink events: `{"type": "sink", "data": {"function": "eval", "source_preview": "..."}}`
- Audit events: `{"type": "audit", "data": {"event": "import", "args": [...]}}`

**Security Questions Answered:**
- "Which dependencies are actually loaded at runtime?"
- "Which dangerous functions are called?"
- "What is the call chain to sinks?"

---

#### 3. **src/vulnreach/agents/** (Agent-Based Analysis)
**What it does:**
- AST-based static analysis using ast-grep
- Multi-agent orchestration for vulnerability analysis
- Dependency tree analysis and CVE correlation

**Key Agents:**
- `ast_agent.py` - Code structure analysis via ast-grep
- `dependency_agent.py` - Dependency tree traversal (pip, npm)
- `vulnerability_agent.py` - OSV/CVE database queries
- `reachability_agent.py` - Orchestrates full analysis workflow
- `tainter_agent.py` - Taint analysis integration (NEW)

**Signals Produced:**
- agent_reachability_report.json - Call chains with confidence scores
- Package usage patterns
- Entry point → vulnerable function paths

**Security Questions Answered:**
- "Is this vulnerable function reachable from entry points?"
- "What is the confidence level of reachability?"
- "Which call paths lead to vulnerabilities?"

---

#### 4. **src/vulnreach/utils/** (Analysis Utilities)
**What it does:**
- Language-specific reachability analyzers (Python, JS, Java, Go, PHP, C#)
- Call graph generation
- Exploitability analysis (SearchSploit integration)
- HTML report generation
- Semgrep SAST integration

**Key Modules:**
- `multi_language_analyzer.py` - Language detection + analyzer dispatch
- `python_call_graph.py` - AST-based call graph for Python
- `exploitability_analyzer.py` - Public exploit matching
- `reachability_engine.py` - Sink→Handler correlation
- `dependency_tree_analyzer.py` - Transitive dependency mapping

**Signals Produced:**
- {language}_vulnerability_reachability_report.json
- exploitability_report.json
- Call graphs (Mermaid format)
- HTML dashboards

**Security Questions Answered:**
- "How does vulnerable code get called?"
- "Are there public exploits for these CVEs?"
- "What are the data flows to sinks?"

---

#### 5. **src/vulnreach/security/** (Security Analysis)
**What it does:**
- SAST findings normalization
- Route extraction (Flask/Django/FastAPI)
- Sink detection patterns

**Signals Produced:**
- semgrep.json - Normalized SAST findings
- routes.json - API endpoints and handlers
- sink_handler_reachability.json - Route→Sink mappings

**Security Questions Answered:**
- "Which endpoints expose vulnerable code?"
- "Can user input reach dangerous sinks?"

---

## TASK 2: CAPABILITY GAP TABLE

| Layer | Implemented? | Evidence | Gaps |
|-------|-------------|----------|------|
| **SBOM generation** | ✅ YES | `SyftSBOMGenerator.generate_sbom()` in tracer_.py | - No container image support beyond Syft defaults |
| **SCA / CVE mapping** | ✅ YES | `TrivySCAScanner.scan_sbom()` with full Trivy integration | - No custom CVE database support <br> - No CVSS filtering |
| **Static reachability (imports)** | ✅ PARTIAL | Agent-based: ast-grep queries <br> Traditional: import detection in reachability analyzers | - Import detection ≠ data flow <br> - No inter-procedural analysis <br> - No taint tracking (Phase 1) |
| **Static reachability (calls)** | ✅ PARTIAL | Call graph generation per language <br> Agent: call chain tracing | - Limited to single-file analysis in some languages <br> - No cross-module flow |
| **Static reachability (flows)** | ❌ NO | No control-flow or data-flow analysis | - Missing: CFG construction <br> - Missing: DFG construction <br> - Missing: Path sensitivity |
| **Runtime execution tracing** | ✅ YES (NEW) | runtime_hooks/runner.py with full hook system | - Python only <br> - No async/await capture yet <br> - Single-process only |
| **Runtime dependency activation** | ✅ YES (NEW) | runtime_hooks/hooks/imports.py captures actual imports | - No version tracking <br> - No lazy loading detection |
| **Stack trace collection** | ✅ YES (NEW) | All runtime_hooks events include stack traces (10 frames) | - Fixed depth limit <br> - No stack symbolication |
| **Sink visibility** | ✅ PARTIAL | runtime_hooks/hooks/sinks.py (eval, exec, Popen) <br> SAST: semgrep patterns | - Limited sink coverage (3 sinks) <br> - No custom sink definitions <br> - No SQL/XSS/SSRF sinks yet |
| **Taint propagation** | ❌ NO (Phase 2) | Tainter agent stub exists | - No source marking <br> - No propagation rules <br> - No sanitizer detection |
| **OS / process impact** | ❌ NO | No system call tracing | - No file I/O monitoring <br> - No network monitoring <br> - No process spawning beyond Popen |
| **Correlation logic** | ⚠️ MINIMAL | `reachability_engine.py` correlates routes→sinks <br> Agent mode: CVE→function mapping | - No Static ↔ Dynamic correlation <br> - No SBOM ↔ Runtime correlation <br> - No confidence scoring model |
| **RBOM generation** | ❌ NO | No RBOM output format | - No RBOM schema <br> - No runtime evidence storage <br> - No confidence metadata |

---

## TASK 3: PIPELINE ALIGNMENT TABLE

### Static Phase

| Step | Status | Implementation | Gaps |
|------|--------|----------------|------|
| **1. SBOM generation** | ✅ IMPLEMENTED | `SyftSBOMGenerator` (tracer_.py:66-277) <br> Supports: spdx-json, cyclonedx-json, syft-json | - No plugin extensibility |
| **2. SCA (CVE mapping)** | ✅ IMPLEMENTED | `TrivySCAScanner` (tracer_.py:326-580) <br> Full Trivy integration with JSON parsing | - No NVD API fallback <br> - No manual CVE addition |
| **3a. Static reachability: file imports** | ✅ IMPLEMENTED | Agent: `ast_agent.find_imports()` <br> Traditional: Language-specific analyzers | - No import aliasing resolution <br> - No wildcard imports tracking |
| **3b. Static reachability: function calls** | ⚠️ PARTIAL | Call graph generation per language <br> `python_call_graph.py`, etc. | - Single-file scope in most languages <br> - No inter-procedural analysis |
| **3c. Static reachability: return flows** | ❌ MISSING | No data-flow analysis | - No def-use chains <br> - No return value tracking |
| **4. Exploitability heuristics** | ✅ IMPLEMENTED | `ExploitabilityAnalyzer` (utils/exploitability_analyzer.py) <br> SearchSploit integration | - Binary presence/absence only <br> - No exploit code analysis <br> - No CVSS/EPSS scoring |

### Dynamic Phase

| Step | Status | Implementation | Gaps |
|------|--------|----------------|------|
| **5a. App execution: Docker** | ⚠️ PARTIAL | User must provide Docker setup <br> `labs/vuln_demo/Dockerfile` created | - No automatic containerization <br> - No runtime orchestration |
| **5b. App execution: Manual** | ✅ IMPLEMENTED | `runtime_hooks/runner.py` executes target directly | - No sandboxing <br> - No timeout enforcement |
| **6a. Runtime observation: libraries loaded** | ✅ IMPLEMENTED | runtime_hooks/hooks/imports.py <br> Captures every `__import__` call | - Python only <br> - No native library tracking |
| **6b. Runtime observation: packages activated** | ✅ IMPLEMENTED | Import events show module names | - No version capture <br> - No lazy loading detection |
| **6c. Runtime observation: sinks executed** | ⚠️ PARTIAL | runtime_hooks/hooks/sinks.py <br> Captures: eval, exec, subprocess.Popen | - Only 3 sinks covered <br> - No SQL/XSS/File sinks <br> - No custom sink definitions |
| **6d. Runtime observation: full stack traces** | ✅ IMPLEMENTED | All events include stack traces (10 frames) | - Fixed depth <br> - No symbolication <br> - No async context |

### Correlation Phase

| Step | Status | Implementation | Gaps |
|------|--------|----------------|------|
| **7. Static ↔ Dynamic correlation** | ❌ MISSING | No correlation logic | - No event matching <br> - No call chain alignment <br> - No confidence calculation |
| **8. CVE ↔ function ↔ runtime path mapping** | ⚠️ MINIMAL | Agent mode: CVE → function (AST-based) <br> No runtime correlation | - No runtime event → CVE mapping <br> - No path reconstruction |
| **9. Suppress unreachable CVEs** | ❌ MISSING | No suppression mechanism | - No reachability verdict <br> - No confidence thresholds <br> - No report filtering |
| **10. Generate RBOM** | ❌ MISSING | No RBOM format defined | - No schema <br> - No output generation <br> - No confidence metadata |

---

## TASK 4: NEXT 5 STEPS (ORDERED, MINIMAL)

### Step 1: Define RBOM Schema & Output Format
**Rationale:** Cannot build correlation without a target data model  
**Scope:** Design RBOM JSON schema only (no implementation)  
**What uncertainty this removes:** "What does success look like?"

**Deliverable:**
```json
{
  "rbom_version": "1.0",
  "generated_at": "ISO8601",
  "components": [{
    "name": "requests",
    "version": "2.25.1",
    "sbom_present": true,
    "runtime_loaded": true,
    "runtime_evidence": ["import event", "stack trace"],
    "vulnerabilities": [{
      "cve_id": "CVE-2023-12345",
      "static_reachable": true,
      "runtime_reachable": true,
      "confidence": "HIGH",
      "evidence": {
        "static": ["call_chain.json"],
        "dynamic": ["sink_event.json"]
      }
    }]
  }]
}
```

---

### Step 2: Implement Static-Dynamic Event Matcher
**Rationale:** Core correlation logic before confidence scoring  
**Scope:** Match runtime import events to SBOM components  
**What uncertainty this removes:** "Which SBOM components were actually used?"

**Implementation:**
- Create `src/vulnreach/correlation/event_matcher.py`
- Input: SBOM JSON + runtime_hooks events JSON
- Output: Matched pairs with metadata
- Algorithm:
  ```python
  def match_import_to_component(import_event, sbom_components):
      module_name = import_event['data']['module']
      # Match module → package (handle namespace packages)
      # Return component + confidence score
  ```

---

### Step 3: Extend Sink Coverage in runtime_hooks
**Rationale:** More sinks = better reachability detection  
**Scope:** Add 5 critical sinks: open(), SQL execute(), render_template(), urlopen(), pickle.load  
**What uncertainty this removes:** "Are we catching the right dangerous functions?"

**Implementation:**
- Update `runtime_hooks/hooks/sinks.py`
- Add wrappers for:
  - `builtins.open()` (File I/O)
  - `sqlite3.Cursor.execute()` (SQL injection)
  - `flask.render_template()` (SSTI)
  - `urllib.request.urlopen()` (SSRF)
  - Already have pickle.load audit event
- Each emits structured sink event with stack trace

---

### Step 4: Implement CVE→Runtime Path Correlation
**Rationale:** Connect vulnerabilities to actual runtime behavior  
**Scope:** Map CVE-affected packages to runtime sink events  
**What uncertainty this removes:** "Did this vulnerability get triggered?"

**Implementation:**
- Create `src/vulnreach/correlation/cve_runtime_mapper.py`
- Logic:
  ```python
  def correlate_cve_to_runtime(cve, sbom, runtime_events):
      # 1. Find package from CVE
      # 2. Check if package was imported (runtime evidence)
      # 3. Check if vulnerable function was called (sink events)
      # 4. Return reachability verdict + confidence
  ```
- Confidence levels:
  - HIGH: Package imported + vulnerable function called
  - MEDIUM: Package imported + similar function called
  - LOW: Package imported but no function calls
  - NONE: Package not imported

---

### Step 5: Generate RBOM with Confidence Scores
**Rationale:** Produce actionable output with uncertainty quantified  
**Scope:** Implement RBOM generator using correlation results  
**What uncertainty this removes:** "Which vulnerabilities should we fix first?"

**Implementation:**
- Create `src/vulnreach/rbom/generator.py`
- Input: SBOM + Trivy scan + Static analysis + Runtime events + Correlation results
- Output: RBOM JSON (schema from Step 1)
- CLI integration: `vulnreach . --generate-rbom`
- Include:
  - All SBOM components
  - Runtime activation status
  - CVE reachability verdicts
  - Confidence scores
  - Evidence links (static analysis + runtime events)

---

## TASK 5: RBOM DEFINITION & DATA MODEL

### RBOM (Runtime Bill of Materials) Definition

**Purpose:** An SBOM enhanced with runtime evidence and reachability analysis to distinguish between *present* and *active* vulnerabilities.

---

### What RBOM Contains

#### 1. **Core Metadata**
```json
{
  "rbom_version": "1.0",
  "generated_at": "2026-01-21T10:30:00Z",
  "tool": "vulnreach",
  "tool_version": "2.1.0",
  "target": {
    "path": "/path/to/project",
    "type": "directory|repository",
    "language": "python",
    "framework": "flask"
  },
  "analysis_duration_seconds": 45.3
}
```

#### 2. **Component Inventory** (SBOM Base)
```json
{
  "components": [
    {
      "name": "requests",
      "version": "2.25.1",
      "type": "library",
      "language": "python",
      "purl": "pkg:pypi/requests@2.25.1",
      "sbom_source": "syft",
      "locations": ["/path/to/site-packages/requests"],
      
      // RBOM Enhancement: Runtime Evidence
      "runtime_status": {
        "loaded": true,
        "load_timestamp": "2026-01-21T10:30:15Z",
        "load_evidence": [
          {
            "type": "import",
            "module": "requests",
            "stack_trace": ["..."],
            "file": "app.py",
            "line": 5
          }
        ]
      }
    }
  ]
}
```

#### 3. **Vulnerability Analysis** (Enhanced with Reachability)
```json
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-2023-12345",
      "package_name": "requests",
      "package_version": "2.25.1",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      
      // RBOM Enhancement: Reachability Analysis
      "reachability": {
        "verdict": "REACHABLE",  // REACHABLE | NOT_REACHABLE | UNKNOWN
        "confidence": "HIGH",     // HIGH | MEDIUM | LOW
        "analysis_methods": ["static", "dynamic"],
        
        // Static Evidence
        "static_evidence": {
          "call_chain_exists": true,
          "call_chain": [
            "app.py:main() → app.py:fetch_data() → requests.get()"
          ],
          "entry_points": ["app.main"],
          "vulnerable_function": "requests.api.request"
        },
        
        // Dynamic Evidence
        "dynamic_evidence": {
          "package_loaded": true,
          "function_called": true,
          "sink_events": [
            {
              "type": "sink",
              "function": "requests.get",
              "timestamp": "2026-01-21T10:30:20Z",
              "stack_trace": ["app.py:12 in fetch_data", "..."],
              "arguments_preview": "url='https://api.example.com'"
            }
          ]
        },
        
        // Exploit Context
        "exploit_analysis": {
          "public_exploits": true,
          "exploit_count": 3,
          "exploit_sources": ["exploit-db", "metasploit"]
        }
      },
      
      // Remediation
      "remediation": {
        "fixed_version": "2.28.0",
        "upgrade_recommended": true,
        "priority": "CRITICAL"  // Based on severity + reachability
      }
    }
  ]
}
```

#### 4. **Execution Summary**
```json
{
  "execution_summary": {
    "runtime_analysis_performed": true,
    "runtime_duration_seconds": 15.2,
    "events_captured": {
      "imports": 45,
      "sinks": 12,
      "audits": 23
    },
    "coverage": {
      "code_paths_exercised": ["app.py:main", "app.py:fetch_data"],
      "coverage_percentage": 65.0  // Optional
    }
  }
}
```

---

### How RBOM Differs from SBOM

| Aspect | SBOM | RBOM |
|--------|------|------|
| **Focus** | Inventory | Inventory + Active Use |
| **Vulnerabilities** | All CVEs for components | CVEs filtered by reachability |
| **Evidence** | Static (manifest files) | Static + Dynamic (runtime traces) |
| **Confidence** | Presence confirmed | Usage confirmed with confidence levels |
| **Actionability** | "You have this" | "You use this, fix now" |
| **False Positives** | High (unused dependencies) | Low (runtime-verified) |
| **Prioritization** | CVSS score only | CVSS × Reachability × Exploitability |

---

### How Dynamic Evidence Feeds RBOM

**Data Flow:**
```
1. Static Analysis (SBOM + SCA)
   ↓
   Components with CVEs identified

2. Runtime Hooks Execute
   ↓
   Import events, Sink events, Audit events collected

3. Correlation Engine
   ↓
   Match: SBOM components ↔ Runtime imports
   Match: CVE-affected functions ↔ Sink events

4. Confidence Calculation
   ↓
   HIGH:   Package loaded + Function called + Stack trace matches
   MEDIUM: Package loaded + Similar function called
   LOW:    Package loaded + No function calls
   NONE:   Package not loaded

5. RBOM Generation
   ↓
   Enhanced SBOM with runtime_status + reachability verdicts
```

---

### Confidence Levels Explained

| Confidence | Static Evidence | Dynamic Evidence | Meaning |
|------------|----------------|------------------|---------|
| **HIGH** | Call chain to vulnerable function | Package imported + Vulnerable function called | Vulnerability is definitely reachable and active |
| **MEDIUM** | Call chain exists | Package imported + No function call yet | Vulnerability is reachable but not observed in this run |
| **LOW** | Import exists | Package imported + No call chain | Package is used but vulnerable code path unlikely |
| **NONE** | No static evidence | Package not imported | Vulnerability not reachable |

**Priority Calculation:**
```python
priority = (
    severity_score * 0.4 +          # CVSS
    reachability_confidence * 0.4 +  # HIGH=1.0, MEDIUM=0.6, LOW=0.3, NONE=0
    exploit_availability * 0.2       # Public exploit = 1.0, None = 0
)
```

---

### RBOM Use Cases

1. **Triage:** Focus remediation on HIGH confidence vulnerabilities
2. **Compliance:** Prove unused dependencies don't affect security posture
3. **CI/CD:** Fail builds only on reachable vulnerabilities
4. **Audit:** Show evidence of vulnerability reachability to auditors
5. **Metrics:** Track "vulnerable code paths executed" over time

---

## CURRENT STATE SUMMARY (1 PAGE MAX)

**VulnReach Status:** Hybrid reachability analysis tool with solid foundation, missing final correlation layer.

**What Works:**
- ✅ **SBOM generation** (Syft) and **SCA** (Trivy) are production-ready
- ✅ **Agent-based static analysis** using ast-grep shows promising call chain detection
- ✅ **Runtime hooks** (Phase 1 complete) capture actual imports and dangerous function calls
- ✅ **Language support** for Python, JavaScript, Java, Go, PHP, C# (varying maturity)
- ✅ **Exploitability analysis** via SearchSploit integration

**Critical Gaps:**
- ❌ **No Static-Dynamic correlation** - SBOM and runtime events are separate
- ❌ **No RBOM generation** - No unified output format
- ❌ **No confidence scoring** - Cannot quantify reachability uncertainty
- ❌ **Limited sink coverage** - Only 3 sinks (eval, exec, Popen) in runtime hooks
- ❌ **No taint propagation** - Cannot track data flow from sources to sinks

**Architectural Strength:**
The tool has two parallel analysis modes:
1. **Traditional:** SBOM → Trivy → Static reachability → Exploitability
2. **Agent-based:** ast-grep → Call chains → Confidence scores

Both modes are independently valuable but **lack integration**.

**Technical Debt:**
- Runtime hooks are Python-only (by design for Phase 1)
- No async/await support in runtime observation
- Call graph generation is single-file in most languages
- No inter-procedural data-flow analysis

**Next Critical Step:**
Implement the **correlation layer** to bridge static (SBOM) and dynamic (runtime_hooks) evidence into a unified RBOM format. This is the "last mile" to achieve true reachability-based vulnerability management.

**Bottom Line:**
VulnReach has **all the pieces** to become a groundbreaking reachability-first tool. It needs the **glue logic** (Steps 1-5 above) to connect SBOM + Runtime + CVE into actionable RBOM reports with confidence scores.

---

*End of TPM-2 Evaluation*

**Recommendation:** Prioritize Steps 1-2 (RBOM schema + Static-Dynamic matcher) to unlock the tool's full potential.

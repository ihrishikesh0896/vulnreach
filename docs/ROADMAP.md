# VulnReach: Implementation Roadmap

Based on analysis of the codebase (`src/`, `runtime_hooks/`), here's what exists and what needs to be built:

---

## ✅ What Already Works (90% Complete!)

### 1. SBOM → SCA → Exploit Pipeline ✅
**Location:** `src/vulnreach/tracer_.py`

- `SyftSBOMGenerator` → Generates SBOM
- `TrivySCAScanner` → Scans for vulnerabilities  
- `ExploitabilityAnalyzer` (`utils/exploitability_analyzer.py`) → Searches exploits

### 2. Dynamic Analysis (Runtime Hooks) ✅
**Location:** `runtime_hooks/`

Complete taint tracking system:
- `hooks/sources.py` - HTTP inputs, file reads (Flask, Django, FastAPI)
- `hooks/sinks.py` - SQL, command exec, eval, deserialization
- `hooks/taint.py` - `TaintedValue` wrapper, propagation
- `hooks/dataflow.py` - Builds dataflow graphs
- `runner.py` - Executes app with hooks

### 3. Basic Correlation ✅
**Location:** `src/vulnreach/correlation/correlator.py`

- Matches packages (static ↔ runtime imports)
- Matches sinks (static ↔ runtime events)
- Assigns verdicts: CONFIRMED, LIKELY, POSSIBLE, UNLIKELY
- Already integrated in `tracer_.py` (line 1867)

### 4. Existing Integrations ✅
- Semgrep (`utils/semgrep_runner.py`)
- Call graph generation (`utils/python_call_graph.py`)
- Route extraction (`utils/route_extractor.py`)
- HTML reporting (`utils/html_reporter.py`)

---

## ❌ What's Missing (3 Components)

### 1. Static Taint Analysis 🔥 (CRITICAL)
**Need:** `src/vulnreach/taint/static_taint.py`

**Purpose:** Map taint flows to vulnerable packages

**Requirements:**
```python
class StaticTaintAnalyzer:
    def analyze_project(project_root: str, vulnerabilities: List) -> Dict[str, List[TaintFlow]]
    
    # For each vulnerable package, find:
    # - Where user input enters (source)
    # - Where it reaches vulnerable code (sink)
    # - The path between them
    
    # Output:
    # {
    #   "flask": [
    #     {
    #       "source": "request.args['user']",
    #       "sink": "db.execute(sql)",
    #       "source_file": "app.py",
    #       "sink_file": "db.py",
    #       # ... more metadata
    #     }
    #   ]
    # }
```

**Integration points:**
- Use existing `utils/semgrep_runner.py` to find sinks
- Use existing `utils/python_call_graph.py` for dataflow
- Combine with SCA results to link vulns → packages → taint flows

### 2. Container Detection 🔥 (CRITICAL for dynamic)
**Need:** `src/vulnreach/pipeline/container_detector.py`

**Purpose:** Detect if app can be run in container

```python
class ContainerDetector:
    def is_containerized(project_root: str) -> bool:
        # Check for Dockerfile, docker-compose.yml
    
    def can_run(project_root: str) -> bool:
        # Check for run instructions
        # Parse README, look for CMD in Dockerfile
    
    def get_run_command(project_root: str) -> Optional[str]:
        # Extract docker-compose up, etc.
```

**Flow you requested:**
```
1. Is containerized? (Dockerfile check)
   ├─ YES → Continue
   └─ NO  → Exit (skip dynamic)

2. Has run instructions?
   ├─ YES → Continue
   └─ NO  → Exit

3. Try running app
   ├─ SUCCESS → Collect hooks
   └─ FAIL    → Exit

4. Map to static findings ← [✅ Already exists in correlator.py]
```

### 3. Unified Pipeline Orchestrator 🟡 (MEDIUM)
**Need:** `src/vulnreach/pipeline/pipeline.py`

**Purpose:** Wire everything together + generate single output file

```python
class VulnReachPipeline:
    def run_full_scan(project_root: str) -> str:
        # Phase 1: Static
        sbom = generate_sbom()
        vulns = scan_with_trivy(sbom)
        exploits = find_exploits(vulns)
        taint_flows = static_taint_analysis(project_root, vulns)  # ← NEW
        
        # Phase 2: Dynamic (conditional)
        if is_containerized(project_root):  # ← NEW
            if can_run(project_root):       # ← NEW
                dynamic_results = run_with_hooks(project_root)
        
        # Phase 3: Correlate (already exists!)
        findings = correlate(vulns, taint_flows, dynamic_results)
        
        # Phase 4: Single output file
        save_unified_findings(findings, "complete_findings.json")
```

---

## Your Required Finding Structure

```json
{
  "filename": "app.py",
  "vulnerable_package": "flask",
  "fixed_version": ["2.0.3"],
  "public_external_exploits": [
    {"exploit_db_id": "50123", "title": "..."}
  ],
  "taint_flow": {
    "flask": [
      {
        "source": "request.args['user']",
        "sink": "db.execute()"
      }
    ]
  }
}
```

**Status:** ✅ Can generate this with:
- existing SCA (package + fixed_version)
- existing exploits (public_external_exploits)
- **NEW static taint** (taint_flow)
- existing correlator (mapping)

---

## Implementation Plan

### Step 1: Static Taint Analysis (2-3 days)
**File:** `src/vulnreach/taint/static_taint.py`

1. Use Semgrep to find sinks (already have `semgrep_runner.py`)
2. Parse AST to find sources (HTTP inputs, file reads)
3. Build call graph (already have `python_call_graph.py`)
4. Trace source → sink paths
5. Map flows to vulnerable packages from SCA

**Test:** Run on `labs/vuln_demo` and verify taint flows detected

### Step 2: Container Detection (1 day)
**File:** `src/vulnreach/pipeline/container_detector.py`

1. Check for `Dockerfile`, `docker-compose.yml`
2. Parse `README.md` for run commands
3. Parse Dockerfile `CMD`/`ENTRYPOINT`
4. Return run instructions

**Test:** Run on various repos, verify detection

### Step 3: Pipeline Integration (1-2 days)
**File:** `src/vulnreach/pipeline/pipeline.py`

1. Wire: SBOM → SCA → Exploits → Static Taint → Container Check → Dynamic → Correlate
2. Generate single `complete_findings.json` with your schema
3. Add to CLI in `tracer_.py`

**Test:** End-to-end scan on vulnerable app

---

## Existing Code to Reuse

### For Static Taint:
```python
# Already have:
from vulnreach.utils.semgrep_runner import SemgrepRunner  # Find sinks
from vulnreach.utils.python_call_graph import PythonCallGraphBuilder  # Dataflow
from vulnreach.ast_analyzer import ASTAnalyzer  # AST parsing

# Combine into static taint analyzer
```

### For Dynamic (already complete):
```python
# runtime_hooks/runner.py - Run with hooks
# runtime_hooks/hooks/dataflow.py - Build graph
# src/vulnreach/runtime/dynamic_analyzer.py - Wrapper
```

### For Correlation (already complete):
```python
from vulnreach.correlation.correlator import FindingCorrelator

correlator = FindingCorrelator(findings_dir)
findings = correlator.correlate_findings(static, dynamic)
# Outputs: CONFIRMED, LIKELY, POSSIBLE, UNLIKELY
```

---

## Quick Start (Copy-Paste)

### To implement your exact flow:

1. **Create static taint analyzer:**
```bash
mkdir -p src/vulnreach/taint
touch src/vulnreach/taint/__init__.py
touch src/vulnreach/taint/static_taint.py
```

2. **Create container detector:**
```bash
mkdir -p src/vulnreach/pipeline
touch src/vulnreach/pipeline/__init__.py
touch src/vulnreach/pipeline/container_detector.py
```

3. **Create pipeline orchestrator:**
```bash
touch src/vulnreach/pipeline/pipeline.py
```

4. **Test on sample app:**
```bash
cd labs/vuln_demo
python -m vulnreach.pipeline.pipeline . --output complete_findings.json
```

---

## Code That Exists for Mapping

**Looking for:** Code that maps static findings to dynamic

**Found:** In `src/vulnreach/tracer_.py`, lines 1846-1878:

```python
# Run correlation analysis (static + dynamic)
correlated_findings = None
if vulnerabilities and not args.no_correlation:
    # Convert vulnerabilities to dict
    static_findings_dict = [...]
    
    # Run correlation
    correlated_findings = run_correlation_pipeline(
        project_findings_dir=project_findings_dir,
        static_findings=static_findings_dict,
        dynamic_results=dynamic_results,  # ← From runtime hooks
        skip_correlation=args.no_correlation
    )
```

**This calls:** `src/vulnreach/correlation/correlator.py::FindingCorrelator`

Which matches:
- Packages: `static vuln.pkg_name` ↔ `dynamic import events`
- Sinks: `static vulnerable functions` ↔ `dynamic sink events`

**Enhancement needed:** Also match taint flows (source/sink pairs)

---

## Summary

| Component | Status | Priority | File Location |
|-----------|--------|----------|---------------|
| SBOM Generation | ✅ Done | - | `tracer_.py::SyftSBOMGenerator` |
| SCA Scanning | ✅ Done | - | `tracer_.py::TrivySCAScanner` |
| Exploit Search | ✅ Done | - | `utils/exploitability_analyzer.py` |
| Runtime Hooks | ✅ Done | - | `runtime_hooks/hooks/` |
| Basic Correlation | ✅ Done | - | `correlation/correlator.py` |
| **Static Taint** | ❌ Missing | 🔥 High | `taint/static_taint.py` (NEW) |
| **Container Detect** | ❌ Missing | 🔥 High | `pipeline/container_detector.py` (NEW) |
| **Pipeline** | ❌ Missing | 🟡 Med | `pipeline/pipeline.py` (NEW) |

**Bottom line:** You're 3 files away from the complete flow

---

## Next Actions

1. **Review:** Does this match your vision?
2. **Decide:** Start with static taint or container detection?
3. **Implement:** I can help build any of the missing components
4. **Test:** Run on `labs/vuln_demo` or your target repo

Ready to start implementation? Let me know which component to build first! 🚀

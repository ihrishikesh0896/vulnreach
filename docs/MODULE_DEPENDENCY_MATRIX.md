# VulnReach Module Dependency Matrix

**Document Version:** 1.0  
**Date:** February 14, 2026  
**Purpose:** Detailed dependency mapping for refactoring reference

---

## Table of Contents

1. [Module Dependency Matrix](#module-dependency-matrix)
2. [Function Call Dependencies](#function-call-dependencies)
3. [Data Flow Dependencies](#data-flow-dependencies)
4. [External Tool Dependencies](#external-tool-dependencies)
5. [Circular Dependency Analysis](#circular-dependency-analysis)
6. [Refactoring Impact Analysis](#refactoring-impact-analysis)

---

## Module Dependency Matrix

### Legend
- ✅ **Direct Dependency** - Module explicitly imports another
- 🔄 **Circular** - Two-way dependency
- 📊 **Data** - Depends via shared data structures
- 🗂️ **File** - Depends via file I/O
- ⚠️ **Problematic** - Should be removed during refactoring

| Module | Depends On | Type | Reason | Refactor Priority |
|--------|-----------|------|--------|-------------------|
| **cli.py** | tracer_.py | ✅ | Calls main() | HIGH |
| **cli.py** | config.py | ✅ | Configuration loading | LOW |
| **core.py** | tracer_.py | ✅ | Re-exports classes | ⚠️ HIGH |
| **tracer_.py** | utils/multi_language_analyzer.py | ✅ | Language detection | MEDIUM |
| **tracer_.py** | utils/reachability_engine.py | ✅ | Reachability scoring | MEDIUM |
| **tracer_.py** | utils/exploitability_analyzer.py | ✅ | Exploit analysis | MEDIUM |
| **tracer_.py** | utils/ai_analyzer.py | ✅ | AI insights | MEDIUM |
| **tracer_.py** | utils/html_reporter.py | ✅ | Report generation | MEDIUM |
| **tracer_.py** | rbom/* | ✅ | RBOM generation | MEDIUM |
| **tracer_.py** | runtime/dynamic_analyzer.py | ✅ | Dynamic analysis | MEDIUM |
| **tracer_.py** | correlation/correlator.py | ✅ | Finding correlation | MEDIUM |
| **tracer_.py** | config.py | ✅ | Configuration | LOW |
| **pipeline/pipeline.py** | tracer_.py | ✅⚠️ | Tool wrappers (SBOM/SCA) | ⚠️ HIGH |
| **pipeline/pipeline.py** | taint/static_taint.py | ✅ | Taint analysis | LOW |
| **pipeline/pipeline.py** | pipeline/container_detector.py | ✅ | Container detection | LOW |
| **pipeline/pipeline.py** | runtime/dynamic_analyzer.py | ✅ | Dynamic execution | LOW |
| **pipeline/pipeline.py** | correlation/correlator.py | ✅ | Correlation | LOW |
| **pipeline/container_detector.py** | None | - | Standalone | LOW |
| **taint/static_taint.py** | ast (stdlib) | ✅ | AST parsing | LOW |
| **runtime/dynamic_analyzer.py** | None (subprocess) | - | Process execution | LOW |
| **correlation/correlator.py** | tracer_.py | 📊⚠️ | Vulnerability dataclass | HIGH |
| **correlation/cve_runtime_mapper.py** | correlation/correlator.py | ✅ | Finding types | LOW |
| **correlation/event_matcher.py** | correlation/correlator.py | ✅ | Correlation logic | LOW |
| **correlation/package_resolver.py** | None | - | Name resolution | LOW |
| **rbom/__init__.py** | rbom/schema.py | ✅ | Data models | LOW |
| **rbom/__init__.py** | rbom/builder.py | ✅ | RBOM construction | LOW |
| **rbom/__init__.py** | rbom/serializer.py | ✅ | Output generation | LOW |
| **rbom/builder.py** | rbom/schema.py | ✅ | Data models | LOW |
| **rbom/builder.py** | correlation/correlator.py | 📊 | CorrelatedFinding | MEDIUM |
| **rbom/serializer.py** | rbom/schema.py | ✅ | Data models | LOW |
| **utils/multi_language_analyzer.py** | utils/python_reachability_analyzer.py | ✅ | Python analysis | LOW |
| **utils/multi_language_analyzer.py** | utils/java_reachability_analyzer.py | ✅ | Java analysis | LOW |
| **utils/multi_language_analyzer.py** | utils/javascript_reachability_analyzer.py | ✅ | JS analysis | LOW |
| **utils/multi_language_analyzer.py** | utils/go_reachability_analyzer.py | ✅ | Go analysis | LOW |
| **utils/multi_language_analyzer.py** | utils/php_reachability_analyzer.py | ✅ | PHP analysis | LOW |
| **utils/multi_language_analyzer.py** | utils/csharp_reachability_analyzer.py | ✅ | C# analysis | LOW |
| **utils/reachability_engine.py** | None | - | Standalone | LOW |
| **utils/exploitability_analyzer.py** | requests | ✅ | HTTP API calls | LOW |
| **utils/exploitability_analyzer.py** | subprocess | ✅ | SearchSploit | LOW |
| **utils/ai_analyzer.py** | requests | ✅ | LLM API calls | LOW |
| **utils/ai_analyzer.py** | config.py | ✅ | Provider config | LOW |
| **utils/semgrep_runner.py** | subprocess | ✅ | Semgrep execution | LOW |
| **utils/dependency_tree_analyzer.py** | subprocess | ✅ | pipdeptree | LOW |
| **utils/python_call_graph.py** | ast (stdlib) | ✅ | Call graph | LOW |
| **utils/route_extractor.py** | ast (stdlib) | ✅ | Route parsing | LOW |
| **utils/html_reporter.py** | None | - | Template rendering | LOW |

---

## Function Call Dependencies

### Critical Function Call Paths

#### Path 1: Full Analysis Execution
```
run_vulnreach.py::main()
  ├─> VulnReachPipeline.__init__()
  └─> VulnReachPipeline.run_full_analysis()
      ├─> VulnReachPipeline._run_static_phase()
      │   ├─> SyftSBOMGenerator.generate_sbom()
      │   ├─> TrivySCAScanner.scan_sbom()
      │   ├─> ExploitabilityAnalyzer.analyze_vulnerability_batch()
      │   └─> analyze_project_taint()
      ├─> VulnReachPipeline._run_dynamic_phase()
      │   ├─> ContainerDetector.detect()
      │   └─> DynamicAnalyzer.run_dynamic_analysis()
      ├─> VulnReachPipeline._run_correlation_phase()
      │   └─> FindingCorrelator.correlate_findings()
      └─> VulnReachPipeline._generate_unified_output()
          ├─> create_rbom_from_analysis()
          └─> save_rbom()
```

#### Path 2: Legacy Entry Point
```
cli.py::main()
  ├─> _initialize_config()
  │   └─> get_config_loader()
  └─> tracer_main()  [LEGACY - NEEDS DEPRECATION]
      └─> [Monolithic logic in tracer_.py]
```

#### Path 3: SBOM Generation
```
SyftSBOMGenerator.generate_sbom()
  ├─> subprocess.run(['syft', ...])
  └─> _enhance_sbom_with_transitive_info()
      ├─> ProjectLanguageDetector.detect_language()
      └─> get_dependency_analyzer()
          ├─> PythonDependencyTreeAnalyzer.get_all_dependencies()
          ├─> JavaDependencyTreeAnalyzer.get_all_dependencies()
          └─> [other language analyzers]
```

#### Path 4: Dynamic Analysis
```
DynamicAnalyzer.run_dynamic_analysis()
  ├─> subprocess.run([sys.executable, 'runner.py', entrypoint])
  │   └─> runtime_hooks/runner.py::main()
  │       ├─> hooks/audit.install()
  │       ├─> hooks/imports.install()
  │       ├─> hooks/sinks.install()
  │       └─> exec(compiled_code)
  ├─> _extract_json_from_stdout()
  ├─> _process_events()
  └─> _generate_summary()
```

#### Path 5: Correlation
```
FindingCorrelator.correlate_findings()
  ├─> _check_runtime_loaded()
  ├─> _check_sink_executed()
  └─> _determine_verdict()
      ├─> _severity_to_priority()
      └─> [verdict calculation logic]
```

---

## Data Flow Dependencies

### Data Structure Flow Map

| Data Structure | Created By | Consumed By | Format | Persistence |
|----------------|-----------|-------------|--------|-------------|
| **Component** | SyftSBOMGenerator.parse_sbom_components() | VulnReachPipeline, RBOMBuilder | Dataclass | In-memory |
| **Vulnerability** | TrivySCAScanner._parse_trivy_output() | Pipeline, Correlator, RBOM | Dataclass | In-memory |
| **TaintSource** | SourceDetector.visit() | StaticTaintAnalyzer | Dataclass | In-memory |
| **TaintSink** | SinkDetector.visit() | StaticTaintAnalyzer | Dataclass | In-memory |
| **TaintFlow** | StaticTaintAnalyzer._build_flows() | Correlator, RBOM | Dataclass | static_taint_flows.json |
| **DynamicFinding** | DynamicAnalyzer._process_events() | Correlator | Dataclass | dynamic_findings.json |
| **CorrelatedFinding** | FindingCorrelator.correlate_findings() | RBOM, Reports | Dataclass | correlated_findings.json |
| **ContainerInfo** | ContainerDetector.detect() | Pipeline | Dataclass | In-memory |
| **RBOM** | RBOMBuilder.build() | Serializer | Dataclass | rbom.json |
| **AIAnalysisResult** | AIVulnerabilityAnalyzer.analyze_integrated_results() | Reports | Dataclass | ai_analysis.json |
| **ReachabilityFinding** | run_reachability_engine() | Reports | Dataclass | sink_handler_reachability.json |
| **SemgrepFinding** | SemgrepRunner._normalize_results() | Reachability Engine | Dataclass | semgrep.json |

### JSON File Dependencies

```
sbom.json
  ├─> Used by: trivy (SCA scanning)
  ├─> Used by: pipeline (component extraction)
  └─> Enhanced with: dependency tree info

trivy_output.json
  ├─> Parsed by: TrivySCAScanner._parse_trivy_output()
  ├─> Used by: Pipeline (vulnerability list)
  └─> Used by: Correlator

static_taint_flows.json
  ├─> Created by: StaticTaintAnalyzer
  ├─> Read by: Correlator
  └─> Format: {package_name: [TaintFlow]}

dynamic_findings.json
  ├─> Created by: DynamicAnalyzer
  ├─> Read by: Correlator
  └─> Format: {findings: [DynamicFinding], summary: {...}}

semgrep.json
  ├─> Created by: SemgrepRunner
  ├─> Read by: ReachabilityEngine
  └─> Format: {results: [...], normalized_findings: [...]}

routes.json
  ├─> Created by: RouteExtractor
  ├─> Read by: ReachabilityEngine
  └─> Format: [{file, handler, route, method}]

correlated_findings.json
  ├─> Created by: FindingCorrelator
  ├─> Read by: RBOMBuilder, Reporters
  └─> Format: {metadata: {...}, findings: [CorrelatedFinding]}

rbom.json
  ├─> Created by: RBOMSerializer
  ├─> Final output
  └─> Format: RBOM schema

complete_findings.json
  ├─> Created by: Pipeline._generate_unified_output()
  ├─> Final consolidated output
  └─> Format: All findings merged
```

---

## External Tool Dependencies

### Tool Execution Matrix

| Tool | Executed By | Command Pattern | Output Format | Failure Handling |
|------|-------------|----------------|---------------|------------------|
| **syft** | SyftSBOMGenerator.generate_sbom() | `syft <target> -o <format>=<output>` | SPDX/CycloneDX/Syft JSON | RuntimeError - CRITICAL |
| **trivy** | TrivySCAScanner.scan_sbom() | `trivy sbom <sbom> --format json --output <output>` | Trivy JSON | RuntimeError - CRITICAL |
| **semgrep** | SemgrepRunner.run_scan() | `semgrep scan --json --config <config> <target>` | Semgrep JSON | Skip SAST analysis |
| **searchsploit** | ExploitabilityAnalyzer._query_searchsploit() | `searchsploit --json <cve>` | JSON | Skip exploit for CVE |
| **docker** | ContainerDynamicAnalyzer.run_container_analysis() | `docker run --rm -v ... <image> python runner.py` | stdout | Fall back to local |
| **pipdeptree** | PythonDependencyTreeAnalyzer.get_dependency_tree_from_pip() | `pipdeptree --json` | JSON | Basic dependency analysis |
| **ast-grep** | Language analyzers | `ast-grep --pattern <pattern> <file>` | JSON | Skip language analysis |
| **python** | DynamicAnalyzer.run_dynamic_analysis() | `python runtime_hooks/runner.py <entrypoint>` | stdout (JSON) | Return empty findings |

### Tool Detection Logic

```python
# Pattern used throughout codebase
tool_path = shutil.which('tool_name')
if not tool_path:
    if tool_is_critical:
        raise RuntimeError(f"{tool_name} not found")
    else:
        print(f"⚠️  {tool_name} not found, skipping feature")
        return default_value
```

---

## Circular Dependency Analysis

### Identified Circular Dependencies

#### 🔄 Circular 1: core.py ↔ tracer_.py

**Problem:**
```
core.py imports from tracer_.py
tracer_.py could import from core.py (if refactored)
```

**Status:** Not currently circular, but fragile

**Resolution:**
- Remove `core.py` entirely
- Export classes directly from their modules
- Update imports in consuming code

---

#### 🔄 Circular 2: pipeline.py → tracer_.py → pipeline.py (potential)

**Problem:**
```
pipeline.py imports SyftSBOMGenerator, TrivySCAScanner from tracer_.py
If tracer_.py needs PipelineConfig, circular dependency forms
```

**Status:** Avoided by keeping tracer_.py dependency-free

**Resolution:**
- Extract SyftSBOMGenerator → tools/syft.py
- Extract TrivySCAScanner → tools/trivy.py
- Break dependency

---

#### 🔄 Circular 3: rbom/builder.py ↔ correlation/correlator.py

**Problem:**
```
rbom/builder.py uses CorrelatedFinding from correlator.py
correlator.py might need RBOM types (future feature)
```

**Status:** One-way currently, low risk

**Resolution:**
- Define shared types in models/finding.py
- Both modules import from models

---

### Dependency Depth Analysis

```
Level 0 (No dependencies):
  - pipeline/container_detector.py
  - utils/reachability_engine.py
  - correlation/package_resolver.py
  - rbom/schema.py

Level 1 (Depends on Level 0 or stdlib):
  - taint/static_taint.py (uses ast)
  - runtime/dynamic_analyzer.py (uses subprocess)
  - utils/semgrep_runner.py (uses subprocess)
  - utils/route_extractor.py (uses ast)
  - rbom/serializer.py (uses rbom/schema.py)

Level 2 (Depends on Level 1):
  - rbom/builder.py (uses schema.py, correlator.py)
  - correlation/correlator.py (uses tracer_.py for Vulnerability)
  - utils/ai_analyzer.py (uses config.py)

Level 3 (Depends on Level 2):
  - pipeline/pipeline.py (uses tools, analyzers, correlator)
  - rbom/__init__.py (uses builder.py, serializer.py)

Level 4 (Top level):
  - tracer_.py (uses most modules)
  - cli.py (uses config, tracer_)
  - run_vulnreach.py (uses pipeline)
```

---

## Refactoring Impact Analysis

### High-Priority Refactoring Tasks

#### 1. Extract Tool Wrappers from tracer_.py

**Impact:**
- **Affected Modules:** pipeline.py, any direct tracer_ imports
- **Files to Create:** 
  - `tools/syft_wrapper.py`
  - `tools/trivy_wrapper.py`
- **Breaking Changes:** Import paths change
- **Estimated Effort:** 4 hours
- **Risk:** LOW (well-isolated functionality)

**Before:**
```python
from vulnreach.tracer_ import SyftSBOMGenerator, TrivySCAScanner
```

**After:**
```python
from vulnreach.tools.syft import SyftWrapper
from vulnreach.tools.trivy import TrivyWrapper
```

---

#### 2. Create Canonical Data Models

**Impact:**
- **Affected Modules:** ALL
- **Files to Create:**
  - `models/vulnerability.py`
  - `models/component.py`
  - `models/finding.py`
  - `models/analysis_result.py`
- **Breaking Changes:** Import paths, data structure access
- **Estimated Effort:** 8 hours
- **Risk:** MEDIUM (touches many files)

**Migration Strategy:**
```python
# Phase 1: Create new models (parallel to existing)
# Phase 2: Update one module at a time
# Phase 3: Deprecate old dataclasses
# Phase 4: Remove from tracer_.py
```

---

#### 3. Separate Pipeline Orchestration

**Impact:**
- **Affected Modules:** cli.py, run_vulnreach.py
- **Files to Create:**
  - `pipeline/orchestrator.py` (from pipeline.py)
  - `pipeline/phases.py` (phase definitions)
  - `pipeline/context.py` (shared state)
- **Breaking Changes:** None if API preserved
- **Estimated Effort:** 6 hours
- **Risk:** LOW (internal refactor)

---

#### 4. Remove core.py

**Impact:**
- **Affected Modules:** Any module importing from core.py
- **Files to Delete:** `core.py`
- **Breaking Changes:** Import paths
- **Estimated Effort:** 2 hours
- **Risk:** LOW (simple re-export removal)

**Migration:**
```python
# Find all imports
grep -r "from vulnreach.core import" src/

# Update to direct imports
from vulnreach.tracer_ import Component, Vulnerability
# OR (after tool extraction)
from vulnreach.models import Component, Vulnerability
```

---

#### 5. Abstract Subprocess Execution

**Impact:**
- **Affected Modules:** All tool wrappers, analyzers
- **Files to Create:**
  - `tools/executor.py`
- **Breaking Changes:** Internal only
- **Estimated Effort:** 4 hours
- **Risk:** LOW

**Example:**
```python
class ToolExecutor:
    def execute(self, cmd: List[str], timeout: int = 60) -> ToolResult:
        """Centralized execution with logging and error handling"""
        logger.info(f"Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ToolResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            command=cmd
        )
```

---

### Refactoring Dependency Order

**Recommended Order (minimizes disruption):**

1. ✅ **Create Documentation** (DONE)
2. **Create models/** (no dependencies)
3. **Create tools/executor.py** (no dependencies)
4. **Extract tools/syft.py, tools/trivy.py** (depends on executor)
5. **Create utils/logger.py** (no dependencies)
6. **Refactor correlation/** to use models
7. **Refactor rbom/** to use models
8. **Refactor pipeline/** to use tools
9. **Update CLI to use new structure**
10. **Deprecate tracer_.py functions**
11. **Remove core.py**
12. **Add comprehensive tests**
13. **Update documentation**

---

## Module Coupling Metrics

### Coupling Score (0-10, lower is better)

| Module | Coupling Score | Incoming Deps | Outgoing Deps | Assessment |
|--------|---------------|---------------|---------------|------------|
| **tracer_.py** | 9 | 6 | 12 | ⚠️ CRITICAL - Monolithic |
| **pipeline/pipeline.py** | 7 | 2 | 8 | ⚠️ HIGH - Needs splitting |
| **correlation/correlator.py** | 5 | 4 | 2 | ⚠️ MEDIUM |
| **rbom/builder.py** | 5 | 2 | 4 | ⚠️ MEDIUM |
| **utils/ai_analyzer.py** | 4 | 1 | 3 | ✅ OK |
| **taint/static_taint.py** | 2 | 1 | 1 | ✅ GOOD |
| **runtime/dynamic_analyzer.py** | 2 | 2 | 0 | ✅ GOOD |
| **pipeline/container_detector.py** | 1 | 1 | 0 | ✅ EXCELLENT |
| **utils/reachability_engine.py** | 1 | 1 | 0 | ✅ EXCELLENT |

### Instability Metric (I = Outgoing / (Incoming + Outgoing))

- **Stable** (I < 0.3): container_detector, reachability_engine, dynamic_analyzer
- **Balanced** (0.3 ≤ I ≤ 0.7): ai_analyzer, correlator
- **Unstable** (I > 0.7): tracer_.py, pipeline.py, rbom/builder.py

**Goal:** Move more modules to Stable or Balanced categories

---

## Testing Dependencies

### Test Coverage Gaps

| Module | Current Tests | Coverage | Priority | Blockers |
|--------|--------------|----------|----------|----------|
| tracer_.py | None | 0% | CRITICAL | Too complex to test |
| pipeline/pipeline.py | None | 0% | HIGH | External tool deps |
| taint/static_taint.py | None | 0% | HIGH | None |
| runtime/dynamic_analyzer.py | Manual only | 0% | HIGH | Requires app execution |
| correlation/correlator.py | None | 0% | MEDIUM | None |
| rbom/* | None | 0% | MEDIUM | None |
| utils/reachability_engine.py | None | 0% | MEDIUM | None |

### Testing Strategy After Refactor

```python
# Unit tests (no external dependencies)
tests/unit/
  test_models.py
  test_taint_analyzer.py
  test_correlator.py
  test_reachability_engine.py

# Integration tests (mocked external tools)
tests/integration/
  test_pipeline.py
  test_sbom_generation.py
  test_dynamic_analysis.py

# End-to-end tests (real tools)
tests/e2e/
  test_full_analysis.py
  test_container_analysis.py
```

---

## Import Graph Visualization

### Module Import Tree

```
vulnreach/
│
├─ cli.py
│  ├─ tracer_ [⚠️ LEGACY]
│  └─ config
│
├─ tracer_.py [⚠️ MONOLITHIC]
│  ├─ utils/multi_language_analyzer
│  ├─ utils/reachability_engine
│  ├─ utils/exploitability_analyzer
│  ├─ utils/ai_analyzer
│  ├─ utils/html_reporter
│  ├─ rbom/*
│  ├─ runtime/dynamic_analyzer
│  ├─ correlation/correlator
│  └─ config
│
├─ pipeline/pipeline.py
│  ├─ tracer_ [⚠️ BAD - Use tool wrappers]
│  ├─ taint/static_taint
│  ├─ pipeline/container_detector
│  ├─ runtime/dynamic_analyzer
│  └─ correlation/correlator
│
├─ taint/static_taint.py
│  └─ ast (stdlib)
│
├─ runtime/dynamic_analyzer.py
│  └─ subprocess (stdlib)
│
├─ correlation/correlator.py
│  └─ tracer_ [⚠️ BAD - Use models]
│
├─ rbom/builder.py
│  ├─ rbom/schema
│  └─ correlation/correlator [⚠️ Consider models]
│
└─ utils/multi_language_analyzer.py
   ├─ utils/python_reachability_analyzer
   ├─ utils/java_reachability_analyzer
   ├─ utils/javascript_reachability_analyzer
   ├─ utils/go_reachability_analyzer
   ├─ utils/php_reachability_analyzer
   └─ utils/csharp_reachability_analyzer
```

---

## Recommended Import Structure After Refactor

```
vulnreach/
│
├─ cli/
│  └─ commands.py
│     └─ pipeline/orchestrator
│
├─ models/
│  ├─ vulnerability.py [NO DEPS]
│  ├─ component.py [NO DEPS]
│  └─ finding.py [NO DEPS]
│
├─ tools/
│  ├─ executor.py [NO DEPS]
│  ├─ syft.py
│  │  └─ tools/executor
│  └─ trivy.py
│     └─ tools/executor
│
├─ analyzers/
│  ├─ taint/analyzer.py
│  │  └─ models/*
│  ├─ dynamic/analyzer.py
│  │  └─ models/*
│  └─ reachability/engine.py
│     └─ models/*
│
├─ correlation/
│  └─ engine.py
│     └─ models/*
│
├─ pipeline/
│  └─ orchestrator.py
│     ├─ tools/*
│     ├─ analyzers/*
│     └─ correlation/*
│
└─ reports/
   └─ generator.py
      └─ models/*
```

**Key Improvements:**
- ✅ No circular dependencies
- ✅ Clear dependency direction (top-down)
- ✅ Testable modules (low coupling)
- ✅ Reusable components
- ✅ Single responsibility

---

## Appendix: Dependency Commands

### Find All Imports in Module
```bash
# Find all imports from a specific module
grep -r "from vulnreach.tracer_ import" src/

# Find all imports of a specific class
grep -r "import.*Vulnerability" src/

# Show import tree
pipdeptree -p vulnreach
```

### Analyze Circular Dependencies
```bash
# Install pydeps
pip install pydeps

# Generate dependency graph
pydeps src/vulnreach --only vulnreach -o deps.svg

# Find cycles
pydeps src/vulnreach --show-cycles
```

### Count Lines of Code
```bash
# Count by module
find src/vulnreach -name "*.py" -exec wc -l {} + | sort -n

# Identify large files (>500 lines)
find src/vulnreach -name "*.py" -exec wc -l {} + | awk '$1 > 500'
```

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-02-14 | Initial comprehensive dependency map | Engineering Team |

---

**END OF DOCUMENT**


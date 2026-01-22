# VulnReach - 30% Implementation Roadmap to RBOM
**Date:** January 22, 2026  
**Goal:** Complete correlation layer and RBOM generation  
**Timeline:** 2 weeks (10 working days)

---

## Current Status: 70% Complete

### ✅ What We Have (Phase 1 Complete)
- SBOM generation (Syft)
- SCA/CVE scanning (Trivy)
- Agent-based static analysis (ast-grep)
- Language-specific reachability analyzers
- **Runtime hooks system** (imports, sinks, stack traces)
- Exploitability analysis (SearchSploit)

### ❌ What's Missing (The 30%)
- Static ↔ Dynamic correlation
- RBOM schema and generation
- Confidence scoring model
- Extended sink coverage
- CVE → Runtime event mapping

---

## Implementation Plan: 5 Phases

### **Phase 1: RBOM Schema & Foundation** (Days 1-2)
**Goal:** Define data model and create output format

**Tasks:**
1. Create `src/vulnreach/rbom/` package
2. Define RBOM JSON schema (dataclasses)
3. Create RBOM builder/serializer
4. Add CLI flag: `--generate-rbom`

**Deliverables:**
- `src/vulnreach/rbom/schema.py` - Data models
- `src/vulnreach/rbom/builder.py` - RBOM construction logic
- `src/vulnreach/rbom/serializer.py` - JSON output
- Unit tests for schema validation

---

### **Phase 2: Static-Dynamic Event Matcher** (Days 3-4)
**Goal:** Correlate runtime_hooks events with SBOM components

**Tasks:**
1. Create `src/vulnreach/correlation/` package
2. Parse runtime_hooks JSON output
3. Match import events to SBOM components
4. Handle namespace packages (e.g., `flask` → `Flask==2.0.1`)
5. Generate correlation report

**Deliverables:**
- `src/vulnreach/correlation/event_matcher.py` - Core matching logic
- `src/vulnreach/correlation/package_resolver.py` - Name normalization
- Integration with SBOM parser
- Correlation confidence scores

**Algorithm:**
```python
def match_import_to_component(import_event, sbom_components):
    module_name = import_event['data']['module']
    
    # Direct match
    if module_name in sbom_packages:
        return ("HIGH", component)
    
    # Namespace match (e.g., flask → Flask)
    normalized = normalize_package_name(module_name)
    if normalized in sbom_packages:
        return ("HIGH", component)
    
    # Submodule match (e.g., flask.app → Flask)
    parent = get_parent_package(module_name)
    if parent in sbom_packages:
        return ("MEDIUM", component)
    
    return ("NONE", None)
```

---

### **Phase 3: Extended Sink Coverage** (Days 5-6)
**Goal:** Expand dangerous function tracking from 3 to 10+ sinks

**Tasks:**
1. Extend `runtime_hooks/hooks/sinks.py`
2. Add file I/O sinks: `open()`, `pathlib.Path.read_text()`
3. Add SQL sinks: `sqlite3.Cursor.execute()`, `psycopg2.execute()`
4. Add template sinks: `flask.render_template()`, `jinja2.Template.render()`
5. Add network sinks: `urllib.request.urlopen()`, `socket.connect()`
6. Add serialization sinks: Already have pickle audit event
7. Update sink classification (XSS, SQLi, RCE, Path Traversal, etc.)

**Deliverables:**
- Updated `runtime_hooks/hooks/sinks.py` with 7+ new sinks
- Sink categorization by vulnerability type
- Enhanced event data (e.g., SQL query preview, URL for SSRF)
- Tests for all new sinks

**New Sink Structure:**
```json
{
  "type": "sink",
  "data": {
    "function": "sqlite3.Cursor.execute",
    "category": "SQL_INJECTION",
    "source_preview": "SELECT * FROM users WHERE id = ?",
    "arguments": {"query": "...", "params": [...]},
    "stack": ["..."]
  }
}
```

---

### **Phase 4: CVE → Runtime Correlation** (Days 7-8)
**Goal:** Map CVEs to actual runtime behavior

**Tasks:**
1. Create `src/vulnreach/correlation/cve_runtime_mapper.py`
2. Extract affected functions from CVE descriptions (heuristics)
3. Match CVE packages to runtime import events
4. Match CVE functions to runtime sink events
5. Calculate reachability confidence scores
6. Generate reachability verdicts

**Deliverables:**
- CVE → Runtime correlation engine
- Confidence calculation logic
- Reachability verdict (REACHABLE/NOT_REACHABLE/UNKNOWN)
- Evidence collection (static + dynamic)

**Confidence Algorithm:**
```python
def calculate_confidence(cve, sbom, static_analysis, runtime_events):
    score = 0.0
    evidence = {"static": [], "dynamic": []}
    
    # Check if package was imported at runtime
    if package_imported(cve.package, runtime_events):
        score += 0.3
        evidence["dynamic"].append("package_imported")
    
    # Check if static call chain exists
    if call_chain_exists(cve.package, static_analysis):
        score += 0.3
        evidence["static"].append("call_chain")
    
    # Check if vulnerable function was called at runtime
    if function_called(cve.function, runtime_events):
        score += 0.4
        evidence["dynamic"].append("function_called")
    
    # Convert to confidence level
    if score >= 0.7:
        return "HIGH", evidence
    elif score >= 0.4:
        return "MEDIUM", evidence
    elif score > 0:
        return "LOW", evidence
    else:
        return "NONE", evidence
```

---

### **Phase 5: RBOM Generation & Integration** (Days 9-10)
**Goal:** Produce complete RBOM output with all evidence

**Tasks:**
1. Integrate all correlation results
2. Build complete RBOM structure
3. Add to CLI workflow: `vulnreach . --generate-rbom`
4. Generate JSON + Markdown reports
5. Add HTML dashboard with RBOM visualization
6. Performance optimization
7. End-to-end testing

**Deliverables:**
- Complete RBOM generator
- CLI integration
- Multiple output formats (JSON, Markdown, HTML)
- User documentation
- Example RBOM outputs

**CLI Integration:**
```bash
# Generate RBOM with runtime analysis
vulnreach /path/to/project --generate-rbom

# Full pipeline: SBOM → Runtime → RBOM
vulnreach /path/to/project --generate-rbom --run-runtime-analysis

# Output location
security_findings/project_name/rbom.json
security_findings/project_name/rbom_report.md
security_findings/project_name/rbom_dashboard.html
```

---

## File Structure (New Components)

```
src/vulnreach/
├── rbom/
│   ├── __init__.py
│   ├── schema.py              # RBOM data models (Phase 1)
│   ├── builder.py             # RBOM construction (Phase 1)
│   ├── serializer.py          # JSON/Markdown output (Phase 1)
│   └── visualizer.py          # HTML dashboard (Phase 5)
│
├── correlation/
│   ├── __init__.py
│   ├── event_matcher.py       # Import → SBOM matching (Phase 2)
│   ├── package_resolver.py    # Name normalization (Phase 2)
│   ├── cve_runtime_mapper.py  # CVE → Runtime mapping (Phase 4)
│   └── confidence.py          # Confidence scoring (Phase 4)
│
└── runtime/
    ├── __init__.py
    ├── executor.py            # Runtime hooks orchestration
    ├── parser.py              # Parse runtime_hooks output
    └── analyzer.py            # Runtime event analysis

runtime_hooks/hooks/
├── sinks.py                   # Extended sink coverage (Phase 3)
└── ...existing files...
```

---

## Integration Points

### 1. **CLI Flow with RBOM**
```python
# In tracer_.py main()
if args.generate_rbom:
    # 1. Generate SBOM
    sbom = generate_sbom(target)
    
    # 2. Run Trivy scan
    vulnerabilities = scan_with_trivy(sbom)
    
    # 3. Run static reachability
    static_results = run_static_analysis(target)
    
    # 4. Run runtime hooks
    runtime_events = run_runtime_analysis(target)
    
    # 5. Correlate
    correlation = correlate_all(sbom, vulnerabilities, static_results, runtime_events)
    
    # 6. Generate RBOM
    rbom = generate_rbom(correlation)
    
    # 7. Output
    save_rbom(rbom, output_path)
```

### 2. **Data Flow**
```
SBOM (Syft)
    ↓
CVE Scan (Trivy)
    ↓
Static Analysis (ast-grep/agents)
    ↓
Runtime Analysis (runtime_hooks)
    ↓
Correlation Engine
    ├─ Import Matcher
    ├─ CVE Mapper
    └─ Confidence Calculator
    ↓
RBOM Builder
    ↓
RBOM Output (JSON/MD/HTML)
```

---

## Success Metrics

### Phase Completion Criteria

**Phase 1:** ✅ RBOM schema defined, can serialize empty RBOM  
**Phase 2:** ✅ Can match 80%+ of runtime imports to SBOM components  
**Phase 3:** ✅ 10+ sinks captured with categorization  
**Phase 4:** ✅ Confidence scores calculated for all CVEs  
**Phase 5:** ✅ Complete RBOM generated with all evidence  

### Final Success Criteria

- [ ] RBOM JSON schema validated
- [ ] CLI flag `--generate-rbom` works end-to-end
- [ ] Confidence levels match expectations:
  - HIGH: Package imported + Function called + Stack trace
  - MEDIUM: Package imported + Call chain exists
  - LOW: Package imported only
  - NONE: Package not imported
- [ ] False positive reduction: 50%+ fewer alerts vs SBOM-only
- [ ] Performance: RBOM generation < 60 seconds for medium project
- [ ] Documentation complete with examples

---

## Risk Mitigation

### Risk 1: Import Name Mismatch
**Problem:** `import flask` vs package `Flask==2.0.1`  
**Solution:** Maintain canonical name mapping (PyPI name normalization)

### Risk 2: Incomplete Runtime Coverage
**Problem:** Not all code paths exercised  
**Solution:** Document coverage limitations, recommend multiple test runs

### Risk 3: Performance Overhead
**Problem:** Runtime analysis + correlation is slow  
**Solution:** 
- Cache intermediate results
- Parallelize correlation when possible
- Optimize event matching with indexes

### Risk 4: False Negatives
**Problem:** Lazy loading or dynamic imports missed  
**Solution:** 
- Document limitations
- Support multiple runtime trace files
- Add "confidence: LOW" for edge cases

---

## Testing Strategy

### Unit Tests
- RBOM schema validation
- Import matching algorithms
- Confidence calculation logic
- Each new sink wrapper

### Integration Tests
- End-to-end: Source code → RBOM
- Multiple languages (Python, JS, Java)
- Different project structures
- Edge cases (no runtime events, all unreachable, etc.)

### Validation Tests
- Compare RBOM vs SBOM (should have fewer CVEs)
- Manual verification of confidence scores
- Real-world projects: Flask apps, Django apps, Express.js

---

## Timeline (10 Working Days)

| Day | Phase | Deliverables |
|-----|-------|--------------|
| 1 | Phase 1 | RBOM schema, builder foundation |
| 2 | Phase 1 | Serializer, CLI integration stub |
| 3 | Phase 2 | Event matcher core logic |
| 4 | Phase 2 | Package resolver, integration tests |
| 5 | Phase 3 | Extended sinks (file I/O, SQL) |
| 6 | Phase 3 | Network sinks, template sinks, categorization |
| 7 | Phase 4 | CVE → Runtime mapper |
| 8 | Phase 4 | Confidence calculation, reachability verdicts |
| 9 | Phase 5 | RBOM generator, full integration |
| 10 | Phase 5 | Testing, documentation, polish |

---

## Post-Implementation

### Immediate Next Steps (After 30% complete)
1. Deploy to production
2. Gather feedback from real-world usage
3. Measure false positive reduction
4. Iterate on confidence algorithm

### Future Enhancements (Beyond 30%)
1. **Taint propagation** (Phase 2 of runtime_hooks)
   - Track data flow from sources to sinks
   - Build dataflow graphs
   - Detect exploit paths

2. **Multi-language runtime support**
   - JavaScript runtime hooks
   - Java agent (JVM bytecode instrumentation)
   - Go runtime tracing

3. **ML-based confidence scoring**
   - Train on historical data
   - Learn patterns of reachability
   - Auto-tune confidence thresholds

4. **CI/CD integration**
   - GitHub Actions workflow
   - GitLab CI pipeline
   - Jenkins plugin

---

## Getting Started (Day 1)

### Immediate Actions
1. Create directory structure:
   ```bash
   mkdir -p src/vulnreach/{rbom,correlation,runtime}
   ```

2. Start with RBOM schema:
   ```python
   # src/vulnreach/rbom/schema.py
   from dataclasses import dataclass
   from typing import List, Optional, Dict, Any
   from enum import Enum
   
   class Confidence(Enum):
       HIGH = "HIGH"
       MEDIUM = "MEDIUM"
       LOW = "LOW"
       NONE = "NONE"
   
   @dataclass
   class RuntimeEvidence:
       package_loaded: bool
       function_called: bool
       load_events: List[Dict[str, Any]]
       sink_events: List[Dict[str, Any]]
   
   @dataclass
   class VulnerabilityReachability:
       cve_id: str
       verdict: str  # REACHABLE, NOT_REACHABLE, UNKNOWN
       confidence: Confidence
       static_evidence: Dict[str, Any]
       dynamic_evidence: RuntimeEvidence
       exploit_available: bool
   
   @dataclass
   class RBOMComponent:
       name: str
       version: str
       sbom_present: bool
       runtime_loaded: bool
       runtime_evidence: List[Dict[str, Any]]
       vulnerabilities: List[VulnerabilityReachability]
   
   @dataclass
   class RBOM:
       version: str
       generated_at: str
       target: Dict[str, Any]
       components: List[RBOMComponent]
       execution_summary: Dict[str, Any]
   ```

3. Begin implementation...

---

**Status:** Ready to execute  
**Owner:** Implementation Team  
**Review Date:** End of Day 5 (mid-point check)  
**Completion Date:** End of Day 10

---

## Questions to Answer Along the Way

1. **Schema:** Is the RBOM structure complete for all use cases?
2. **Matching:** What's the false positive rate on import matching?
3. **Sinks:** Are we capturing the most critical dangerous functions?
4. **Confidence:** Does the scoring algorithm match intuition?
5. **Performance:** Is it fast enough for CI/CD pipelines?
6. **Usability:** Is the output actionable for developers?

---

**Next Action:** Begin Phase 1 - RBOM Schema & Foundation


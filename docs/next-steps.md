# Next Steps for V1 (Reachability-Aware AppSec Scanner)

## Current Coverage (repo status)
- SCA pipeline (Syft+Trivy) with SBOM enhancement and parsing in `src/vulnreach/tracer_.py` and CLI wiring in `src/vulnreach/cli.py`.
- Package-level reachability (import/use) via `src/vulnreach/utils/multi_language_analyzer.py` and dependency tree analyzers.
- Exploitability addon (`src/vulnreach/utils/exploitability_analyzer.py`) and AI analysis (`src/vulnreach/utils/ai_analyzer.py`).
- Reports currently focused on SCA/reachability/exploitability under `security_findings/<project>/`.

## Decisions Confirmed
- V1 scope: Python (Flask/FastAPI); Spring Boot is deferred.
- Reports stay under `security_findings/<project>/` (can add subfolders/files there).
- Reporting format: JSON + CLI summary; HTML not required for V1.

## Gaps vs TODO.md
- Semgrep wired (runner + CLI flags) but curated ruleset pinning and tests are pending (TODO 2).
- No HTTP route extraction for Flask/FastAPI (TODO 3).
- No sink→handler reachability scoring or confidence logic per TODO 4–5.
- No validation strategy builder or safe probe executor (TODO 6–7).
- No risk scoring formula (Impact×Exploitability×Reachability×Confidence) or gating (TODO 8).
- Reporting lacks reachability/confidence/risk/"not tested" fields and HTML export (TODO 9).
- Safety controls (rate limits, kill switch, secret scrubbing, payload hardening) missing (TODO 0/10).

## Proposed Next Actions (ordered)
1) **Semgrep SAST ingestion**: finalize curated rules (SQLi, cmd inj, SSTI, path traversal, deserialization, unsafe eval/exec) and tests; emit `semgrep.json` in `security_findings/<project>/` with rule_id/file/line/sink/taint.
2) **Entrypoint discovery**: build Flask/FastAPI route extractor (method, path, handler, file) → `routes.json`; unit fixtures in `examples/` or `tests/`.
3) **Reachability engine (sink→handler)**: map Semgrep findings to enclosing function, join with routes, detect user-input flow; compute reachability score (0–1) per TODO weights; drop <0.4.
4) **Confidence scoring**: apply Semgrep-only 0.6, +dep context 0.8, heuristic 0.4; drop <0.5; store alongside reachability.
5) **Validation strategy (safe probes)**: per vuln type select harmless probe templates (boolean SQLi, math SSTI, marker XSS, timing cmd inj, traversal detection). Enforce ≤3 requests, expected signal, abort conditions; no RCE/file read/exfil.
6) **Risk scoring + reporting**: implement Impact×Exploitability×Reachability×Confidence; map CWE→impact; gate levels (<20 info / 20–50 later / >50 now). Extend JSON + lightweight HTML to include reachability, confidence, validation result, risk, and "not tested" rationale.
7) **Safety controls**: add rate limiting, kill switch flag, request logging with secret scrubbing, payload hardening, and probe timeouts.
8) **Optional sandbox hook**: containerized replay of validated endpoints with static auth token injection; capture timing/response deltas.

## Action 1 Details — Semgrep SAST Ingestion (V1)
- Implemented: new module `src/vulnreach/utils/semgrep_runner.py`; CLI flags `--run-sast` and `--semgrep-rules`; output saved to `security_findings/<project>/semgrep.json`; Semgrep optional (warns if missing).
- Remaining: pin curated ruleset; fixture-based test can be added later (deferred for now); consider optional/dev dependency entry for Semgrep.
- Execution safety: runtime cap (timeout), repo-only scope, excludes for env/tests/build/git/security_findings; quiet JSON mode.
- Output schema per finding: `rule_id`, `file`, `line`, `sink_function`, `taint_hint`, `message`, `severity` (raw), `metadata` passthrough.

## Action 2 Details — Entrypoint Discovery (Static)
- Scope: Python Flask/FastAPI (V1), plus initial patterns for Node.js Express and Spring Boot.
- Output: `security_findings/<project>/routes.json` with entries: `{method, path, handler, file, framework}`.
- Flask/FastAPI: parse decorators (`app.route`, `Blueprint.route`, `APIRouter.*`, `FastAPI.*`) and basic router/blueprint prefixes.
- Node.js (Express): parse `app.METHOD(path, handler)` and `router.METHOD(path, handler)`, with optional `app.use(prefix, router)` prefix stitching.
- Spring Boot: parse annotations `@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`, `@RequestMapping` on classes/methods; include class-level path prefixes.
- Safety: static parsing only (AST/regex), no code execution; skip env/.venv/tests/security_findings/build/.git.
- CLI: new flag `--run-routes` to emit `routes.json`; can be run alongside reachability to feed sink→handler mapping later.

## Community Feedback & Advanced Enhancements

### Feedback Received (2026-01-03)
A reviewer noted:
> "What's your approach to code parsing across all languages you support? And also i see you're using ai for auto remediate. It might be worthwhile to use agents with something like ast-grep to quickly scan codebases."

### Current State vs. Suggestions

#### Code Parsing Approach (Current Implementation)
- **Python**: Uses Python's built-in `ast` module for AST-based parsing (in `python_reachability_analyzer.py`)
  - Handles imports, function calls, method calls, attribute access
  - Full AST traversal for accurate detection
- **Java**: Regex-based pattern matching (in `java_reachability_analyzer.py`)
  - Matches import statements, method calls, instantiations
  - No formal parser/AST used
- **JavaScript/Node.js**: Regex-based pattern matching (in `javascript_reachability_analyzer.py`)
  - Basic require/import detection
  - No formal parser/AST used
- **Other Languages** (Go, PHP, C#): Similar regex-based approaches

**Limitation**: Regex patterns can miss complex code structures (nested calls, dynamic imports, multi-line statements)

#### AI Auto-Remediation (Current Implementation)
- **LLM Integration**: Active AI analysis via `ai_analyzer.py`
  - Uses LLM providers (Ollama, OpenAI, Anthropic, etc.)
  - Generates remediation recommendations, risk assessments, priority scores
  - Provides short-term and long-term action plans
- **Approach**: Single-pass LLM calls with structured prompts
- **Not Agent-Based**: No iterative reasoning, tool usage, or multi-step workflows

### Proposed Enhancement: Agent-Based AST Scanning

#### Why ast-grep or Similar Tools?
1. **Language-Agnostic Parsing**: ast-grep supports multiple languages via tree-sitter
   - Python, JavaScript, Java, Go, Rust, PHP, C#, etc.
   - Consistent query syntax across all languages
   
2. **Faster & More Accurate**: 
   - Native parsers (tree-sitter) are more reliable than regex
   - Pattern-based queries are faster for large codebases
   - Can handle complex nested structures

3. **Agent-Based Scanning**:
   - Instead of single LLM call → use agentic workflow
   - Agent can iteratively:
     1. Query codebase with ast-grep
     2. Analyze findings
     3. Request more context
     4. Propose targeted fixes
     5. Validate changes

#### Implementation Plan (Future Enhancement)

**Phase 1: Replace Regex with ast-grep** (Medium Priority)
- ✅ Install ast-grep as optional dependency
- ✅ Create unified `ast_based_analyzer.py` module (ast_analyzer.py)
- ✅ Support pattern queries for function calls, imports, class usage
- Migrate language-specific analyzers to use ast-grep
- Fallback to current regex approach if ast-grep unavailable

**Phase 2: Agent-Based Workflow** ✅ COMPLETED
- ✅ Create specialized agents:
  - ✅ **AST Agent** (ast_agent.py): Uses ast-grep to find vulnerable patterns
  - ✅ **Dependency Agent** (dependency_agent.py): Analyzes dependency trees (pip, npm)
  - ✅ **Vulnerability Agent** (vulnerability_agent.py): Queries OSV/CVE databases
  - ✅ **Reachability Agent** (reachability_agent.py): Orchestrates reachability analysis
  - **Remediation Agent**: Proposes fixes, validates them via ast-grep queries (FUTURE)
- ✅ Implement coordinator/orchestrator for agent communication (coordinator.py)
- ✅ Add demo script (examples/agent_demo.py)
- Add agent reasoning logs to reports (TODO)

**Phase 3: Performance & Scale** (Future)
- Cache ast-grep parse trees for large repos
- Parallel agent execution for independent vulnerabilities
- Incremental scanning (only changed files)

#### Benefits
- **Accuracy**: Eliminate regex false positives/negatives
- **Speed**: ast-grep is faster than full AST traversal in Python
- **Multi-Language**: Single parsing approach for all languages
- **Smarter AI**: Agents can iteratively refine analysis vs. single-shot prompts
- **Maintainability**: Reduce language-specific code duplication

#### Effort Estimate
- **ast-grep Integration**: 2-3 weeks (one language at a time)
- **Agent Framework**: 3-4 weeks (design, implement, test)
- **Full Migration**: 8-12 weeks (all languages + testing)

#### Decision Point
- **Keep Current**: Good enough for V1 (Python AST + regex for others)
- **Add ast-grep**: Significant accuracy/speed improvement, worth investment
- **Add Agents**: Advanced feature, best after core functionality is stable

### Recommendation
1. **V1 (Current)**: Ship with current approach (AST for Python, regex for others)
2. **V1.5 (Next 3 months)**: Add ast-grep support for Java/JavaScript
3. **V2.0 (6-12 months)**: Implement agent-based scanning with ast-grep as foundation

---

## Questions to Confirm
- Is V1 limited to Python Flask/FastAPI (Spring Boot later)?
- Preferred location for new reports (extend `security_findings/<project>/` or subfolders)?
- Is HTML output required in V1 or is JSON + CLI summary sufficient?


## Agent-Based Implementation Status (2026-01-03)

### ✅ COMPLETED

1. **AST Foundation** (ast_analyzer.py)
   - ASTAnalyzer class using ast-grep
   - VulnerabilityTracer for reachability checks
   - Pattern search, import detection, call chain tracing

2. **Agent System** (4 agents)
   - AST Agent: Code structure analysis
   - Dependency Agent: Dependency tree (pip, npm)
   - Vulnerability Agent: OSV/CVE queries
   - Reachability Agent: Orchestrator

3. **Agent Coordinator** (coordinator.py)
   - Central hub managing all agents
   - Unified API: analyze_project(), analyze_package(), analyze_cve()
   - Report export (JSON, Markdown)

4. **CLI Integration**
   - --agent-mode for full project analysis
   - --analyze-package for single package
   - --analyze-cve for CVE-specific analysis
   - Color-coded output, auto-reports

### 🎯 WORKING EXAMPLES

```bash
# Full project analysis
vulnreach . --agent-mode

# Analyze specific package
vulnreach . --analyze-package requests

# Analyze CVE with custom entry points
vulnreach . --analyze-cve CVE-2023-12345 --package-name requests --entry-points 'app.route,main'
```

### 📊 WHAT IT DOES

1. Scans all dependencies (pipdeptree)
2. Queries OSV for vulnerabilities
3. Uses ast-grep to find imports/function calls
4. Traces reachability from entry points
5. Scores confidence (high/medium/low)
6. Generates JSON + Markdown reports

### 🚀 NEXT PRIORITIES

1. Entry Point Auto-Detection (Flask routes, FastAPI, etc)
2. Integration Tests
3. Enhanced CVE→function mapping
4. Multi-language expansion (JavaScript, Java)


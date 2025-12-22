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

## Questions to Confirm
- Is V1 limited to Python Flask/FastAPI (Spring Boot later)?
- Preferred location for new reports (extend `security_findings/<project>/` or subfolders)?
- Is HTML output required in V1 or is JSON + CLI summary sufficient?

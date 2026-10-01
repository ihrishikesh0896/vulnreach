# Changelog

## [Unreleased] — 2026-10-01

### Changed

#### BREAKING: CLI is now lifecycle-only — scanning via UI or `curl`
- Removed `vulnreach scan`, `fix-plan`, `replay`, `explain`, and the standalone
  local-pipeline mode (`vulnreach/local.py`, `vulnreach/client.py` — 635 lines).
  The web UI (`dashboard/`) already covered every one of these end-to-end
  (starting/cancelling/deleting scans, fix plans, CVE explanations, call-graph
  replay, RBOM/CycloneDX export), so this removes a second, harder-to-maintain
  surface without losing capability — it also closes a real gap: `correlation/
  rbom.py`'s docstring claimed "package/local mode" RBOM support that the CLI
  never actually had.
- **New**: `vulnreach start` / `stop` / `reload` / `status` (`vulnreach/lifecycle.py`,
  `vulnreach/cli/lifecycle.py`) — auto-detects Docker vs. bare-process mode
  (`docker compose` wrapper, or a pidfile-based `uvicorn` supervisor for
  `pip install vulnreach[server]`), overridable via `--mode`. That's the entire
  CLI surface now.
- **CI/CD gating** — `policy.block_if` gating is unaffected; it was always
  evaluated server-side (`core/orchestrator.py`), independent of how a scan was
  triggered. The CLI's `--fail-on` flag was just a polling convenience around
  it. New doc: [docs/ci-cd-gating.md](docs/ci-cd-gating.md) — the `curl`-based
  replacement recipe.
- `USAGE_PACKAGE.md` rewritten around the new install → lifecycle → UI/curl-scan
  flow. `tests/test_package_parity.py` and `tests/test_cli_scan_warning.py`
  removed (tested the now-gone surfaces); `tests/test_lifecycle.py` added (22
  tests covering mode detection, Docker wrapper commands, and process-mode
  pidfile start/stop/reload).

---

## [Unreleased] — 2026-05-19

### Added

#### AI Next-Steps Endpoint (`POST /findings/{id}/next-steps`)
- **`agents/agent_next_steps.py`** — `NextStepsReasoner` calls Anthropic Claude with the locked `VulnReach AI NextStepsReasoner` system prompt and a normalised EvidenceGraph. **The deterministic verdict is read-only** — the LLM never re-derives it. Returns strict JSON: `summary`, `risk_context`, `immediate_actions`, `investigation_steps`, `recommended_validation`, `remediation { upgrade_path, code_changes, workarounds }`, `monitoring_recommendations`, `false_positive_signals`, `missing_evidence`, `analyst_notes`, `attack_surface_summary`. Temperature 0.1, 30s timeout, `PROMPT_VERSION="1.0.0"`. Token usage + latency logged per call.
- **`correlation/evidence_graph.py`** — `EvidenceGraphBuilder.build(finding_id)` normalises CVE / dependency / framework / routes / imports / call paths / taint paths / runtime events / snippets / per-tier evidence strengths into a fixed shape. The LLM consumes only this — never raw scanner JSON. `EVIDENCE_GRAPH_VERSION="1.0.0"`. Provides `evidence_hash()` for cache keying and `parse_finding_id()` for `<scan_id>:<cve_id>[:<package>]` decoding.
- **`api/next_steps.py`** — `NextStepsService` wires builder → cache → reasoner. Bounded in-memory LRU (512 entries) keyed by `finding_id + evidence_hash + prompt_version` so prompt or graph-schema bumps invalidate correctly. Failures are **not cached** (retryable). All exceptions caught → response stays well-formed with `status="degraded"`, `result=null`, and the EvidenceGraph still attached.
- **`api/server.py`** — `POST /findings/{finding_id}/next-steps` mounted with `NextStepsRequest { bypass_cache, model }`. Lazy reasoner construction so missing `ANTHROPIC_API_KEY` cannot crash startup. Reuses `_fetch_scan_owned` for auth (404 on miss to avoid scan-id enumeration).
- **Scan pipeline untouched** — the endpoint is on-demand and optional. Scans remain fast, cheap, reproducible, and fault-tolerant. LLM failures cannot fail scans.
- Response envelope includes `evidence_graph_version`, `prompt_version`, `evidence_hash`, `cache: "hit" | "miss"`, and full `telemetry { model, latency_ms, input_tokens, output_tokens }` on success.
- New env var: `VULNREACH_NEXTSTEPS_MODEL` (defaults to `claude-sonnet-4-5-20241022`).

#### Java eBPF E2E Lab
- **`labs/ebpf-e2e-java/`** — New Java E2E lab for full pipeline testing. Target app is a plain-JDK HTTP server with three intentionally vulnerable dependencies: `log4j-core 2.14.1` (CVE-2021-44228), `commons-text 1.9` (CVE-2022-42889), `snakeyaml 1.30` (CVE-2022-1471). Exposes five routes: `/health` (negative baseline), `/log` (exercises log4j), `/substitute` (exercises commons-text), `/yaml` (exercises snakeyaml), `/nolog` (imports all three but calls none — negative control).
- **`labs/ebpf-e2e-java/openapi.json`** — OpenAPI 3.0.3 spec describing all five routes with query parameters and response schemas. Used by Schemathesis to drive traffic during dynamic scans.
- **`labs/ebpf-e2e-java/vulnreach.yaml`** — Scan config for the Java lab: `container_port: 5002`, `ebpf.enabled: true`, `ebpf.sidecar_mode: true`, `ebpf.mode: usdt`.
- **`labs/ebpf-e2e-java/target/Dockerfile`** — Eclipse Temurin 17 JDK image; builds a fat JAR via Maven Shade Plugin; starts with `-XX:+ExtendedDTraceProbes` to enable `hotspot:method__entry` USDT probes.
- **`labs/ebpf-e2e-java/target/pom.xml`** — Maven fat-jar build with the three intentionally vulnerable dependencies. Do not upgrade versions in this lab.

#### Java eBPF Sidecar Support (`agents/ebpf/sidecar/sidecar_entrypoint.py`)
- **`_find_libjvm(pid)`** — Reads `/proc/{pid}/maps` to locate `libjvm.so` for a running JVM process.
- **`_has_java_hotspot(libjvm_path)`** — Runs `readelf -n` on `libjvm.so` to confirm `hotspot:method__entry` USDT probes are present.
- **Java branch in `build_probe_script()`** — When `runtime` is `"java"` or `"auto"`, checks for `libjvm.so` and USDT probes; emits a `usdt:{libjvm}:hotspot:method__entry` bpftrace script that prints `method:{class_slash}:{method_name}` per call. Falls back to `openat` with a diagnostic message when USDT is unavailable (e.g. JVM started without `-XX:+ExtendedDTraceProbes`).
- **`java_method` parser in `parse_output()`** — Parses `method:com/example/Foo:bar` lines into `NormalisedCoverage` format (`executed_functions` keyed by `class/Foo.java`). Executed lines left empty; function presence is sufficient for correlation.

#### Maven Coordinate Correlation Fix (`agents/agent_dynamic_reachability.py`)
- **`_maven_alt_names` in `_correlate()`** — When a package name contains `:` (Maven coordinate), extracts the group-path (`org.apache.logging.log4j` → `org/apache/logging/log4j`) and significant artifact keywords (`log4j-core` → `log4j`, `core`) as alternative match tokens. Strategy 1 (direct library path match) now correctly links Maven coordinates to coverage paths like `org/apache/logging/log4j/core/Logger.java`.

#### Tests
- **`tests/test_java_docker.py`** — 34 tests across four classes: `TestJavaDockerEndpoints` (6, Docker) HTTP smoke tests for all five routes; `TestJavaStaticReachability` (8, no deps) verifies `JavaReachabilityAnalyzer` detects all three packages with usage context; `TestJavaDynamicCoverage` (8, no deps) verifies `parse_output` → `NormalisedCoverage` → coverage.py conversion for both all-routes and nolog-only eBPF output; `TestJavaFullPipeline` (12, Docker) exercises the complete static + simulated-dynamic + correlation pipeline, asserting `DYNAMICALLY_REACHABLE` for called packages and `STATICALLY_REACHABLE` for the negative control.
- **`tests/test_ebpf_e2e.py` — Java additions** — `TestEbpfSidecarUnit` (5 tests, no platform requirement): unit tests for `parse_output` with `java_method` parser and `build_probe_script` openat fallback when no libjvm is present; `TestJavaEbpfE2E` (4 tests, Linux + bpftrace + Docker): full eBPF sidecar E2E for the Java lab; `TestEbpfProbeSelection.test_java_probe_selection_does_not_raise` (Linux-only): verifies probe router does not raise for Java PIDs.

### Fixed

#### Java E2E Lab — App.java Bugs (found by Schemathesis)
- **Non-GET methods returned 200** — Added `allowOnly()` helper that sends `405 Method Not Allowed` with an `Allow: GET` header (RFC 9110 compliant) for any non-GET request. Previously TRACE/POST/etc. returned 200.
- **`jsonEscape()` incomplete** — Only escaped `"` and `\`; control characters below `0x20` (except `\n`, `\r`, `\t`) were emitted raw, producing invalid JSON. Fixed to escape all `< 0x20` characters as `\uXXXX`.
- **`/yaml` crashed on binary input** — `yaml.load()` was not wrapped; malformed or binary query strings caused the JVM handler to drop the TCP connection silently. Wrapped in try-catch; on exception returns `{"parsed":"error: ExceptionClassName"}` with HTTP 200 so eBPF probe still fires and Schemathesis does not flag schema-compliant inputs as rejected.
- **`queryParam()` double-decode crash** — `URI.getQuery()` pre-decodes percent-encoded characters (e.g. `%25` → `%`), then `URLDecoder.decode("%", UTF_8)` threw `IllegalArgumentException` on the incomplete escape sequence. Fixed by switching to `URI.getRawQuery()` so decoding happens exactly once.

---

## [Unreleased] — 2026-04-16

### Added

#### CI / CD
- **All workflows now run on every PR** — `ci.yml`, `build-test.yml`, `docker-publish.yml`, and `python-publish.yml` trigger on any pull request regardless of source branch. `ebpf-e2e.yml` triggers on PRs touching eBPF-related paths.
- **Docker publish workflow** — `.github/workflows/docker-publish.yml` builds and pushes to both `ghcr.io` and `docker.io` on `v*.*.*` tag push or GitHub Release. On PRs, image is built but not pushed (login steps skipped via `github.event_name != 'pull_request'`).
- **eBPF E2E workflow** — `.github/workflows/ebpf-e2e.yml` runs the full eBPF pipeline test on `ubuntu-latest` (kernel 5.15+) with `bpftrace` installed. Path-filtered to only trigger when eBPF-related files change.
- **`CI.md`** — Complete CI/CD reference: per-workflow breakdown, local reproduction commands, PR checklist, secrets reference, and environment variable table.

#### eBPF E2E Testing
- **`labs/ebpf-e2e/`** — New lab for full pipeline E2E testing via eBPF sidecar. Target app (`ubuntu:22.04` + USDT Python) exposes a controlled vulnerable route (`/parse` calls `yaml.safe_load`) and a negative-control function (`unused_pickle`) never called at runtime.
- **`tests/test_ebpf_e2e.py`** — End-to-end pytest suite with two test classes: `TestEbpfSidecarE2E` (full pipeline — eBPF sidecar → correlator → `DYNAMICALLY_REACHABLE` verdict, guarded by Linux + bpftrace + Docker) and `TestEbpfProbeSelection` (probe_router logic — USDT selection, openat fallback, guarded by Linux only).

#### Correlation Engine
- **`uncertainty_reason` field on UNCERTAIN findings** — Every `UNCERTAIN` finding now includes a machine-readable `uncertainty_reason` code and a human-readable `reason` string explaining why the finding could not be confirmed:
  - `taint_no_dynamic` — taint flow detected but runtime scan was not run; action: enable `scan.runtime.enabled: true`
  - `taint_dynamic_miss` — taint flow detected and runtime scan ran but package was not observed in coverage; action: exercise the affected endpoint with representative traffic
  Both the `uncertain` bucket and the full `evidence` blob carry the code so API consumers and the dashboard both surface it.

#### Multi-language Reachability
- **`analysis_notes` in agent bridge metadata** — When Java, JavaScript, or other non-Python languages are analyzed, `AgentResult.metadata.analysis_notes` now includes a per-language note explaining that call graph and import detection are functional but taint-flow (user-input-to-sink tracing) is not yet supported. Helps API consumers distinguish Python confidence levels from non-Python ones.

#### Packaging & Distribution
- **`tainter` now installed from PyPI** — `tainter` is now a public PyPI package. `Dockerfile`, `requirements.txt`, and `pyproject.toml` updated to install via `pip install tainter`. Local wheel in `libs/` no longer required.
- **`taint` optional extra in `pyproject.toml`** — `pip install vulnreach[taint]` installs tainter. `pip install vulnreach[full]` includes it alongside `server` and `llm`.
- **`ROADMAP.md`** — New file documenting language support status, near-term / medium-term / longer-term roadmap, and known limitations.

### Changed

#### Documentation
- **`README.md`** — Language support banner updated: Java and JavaScript described as "functional call graph analysis (experimental)" rather than "agent exists but not suitable for production use". Scan cancellation and Java/JS reachability added to Project Status. OWASP submission status updated to submitted.
- **`docs/TODO.md`** — 12 P2 items reclassified as done after codebase audit: async Docker operations (fully async via `asyncio.create_subprocess_exec`), scan cancellation (`POST /scan/{id}/cancel`), orphaned container cleanup (`_cleanup_port_conflicts`), `VULNREACH_WORK_DIR` configurability, coverage flush retry logic, CI pipeline, dependency pinning, Docker image publishing, version tagging, Java reachability, JavaScript reachability, OWASP application submission. Summary: **52/53 items done**. Only remaining item: SBOM ingestion.
- **`ROADMAP.md`** — Language table corrected: Java has real call graph (Maven/Gradle dependency parsing, method scope tracking); JavaScript has real call graph (BFS path tracing, route entry point detection). Both were incorrectly described as stubs. Roadmap reframed around actual gaps: taint-flow for Java/JS, SBOM ingestion.
- **`config/generic_scan.yml`** — eBPF section expanded with all config keys (`mode`, `sidecar_mode`, `language`) and inline documentation explaining requirements and fallback behavior.
- **`docs/development.md`** — Tainter install instructions updated: local wheel and git source removed, `pip install tainter` only.

#### CI
- **`ci.yml` tainter in test job** — `pip install tainter` added to the test job so taint-related code paths are exercised during CI rather than silently skipped.
- **`python-publish.yml` restructured** — Split into `build` job (runs on all triggers) and `publish-to-pypi` job (runs only on `release` events). Build artifact uploaded as a GitHub Actions artifact for inspection on non-release runs.

### Fixed

#### Dockerfile
- **`pyproject.toml` version out of sync with git tag** — `pyproject.toml` declared version `2.0.0` while git tag `v2.0.1` already existed. Bumped to `2.0.1`.
- **`pyproject.toml` description used "exploitable"** — Description said "proves which CVEs are actually exploitable"; corrected to "reachable" (the tool measures reachability, not exploitability).

---

## [Unreleased] — 2026-03-27

### Added

#### Testing & CI
- **Integration test suite** — `tests/test_integration.py` (6 tests) exercises the full pipeline end-to-end: `Orchestrator` + `CorrelationService` + `InMemoryRepository`. Covers static-only findings, dynamic reachability tier promotion, policy block (`CRITICAL+CONFIRMED → blocked`), partial scan on agent failure, clean repo (no vulns), and raw output storage.
- **API endpoint tests** — `tests/test_api_server.py` (22 tests) covers every public endpoint: `/health`, `/tools`, `/login` (success, wrong password, unknown user), `POST /scan` (auth required, missing repo, unknown tool, 413 body size limit, success with auto-injected `git`), `GET /scan/{id}` (ownership enforcement returning 404-not-403 to prevent ID enumeration, admin bypass), `GET /scans` (analyst sees own only, admin sees all), `GET /scan/{id}/raw` (list tools, missing tool 404, success). psycopg2 stubbed via `sys.modules` before import so no real database required.
- **PostgresRepository tests** — `tests/test_repository.py` (11 tests) validates the full storage contract against a real Postgres instance. Auto-skipped locally when `DATABASE_URL` is not set or psycopg2 is mocked; runs in CI against a postgres service container. Covers scan lifecycle, vulnerability storage, raw output CRUD, correlation storage, and user management.
- **`agent_dynamic_reachability` unit tests** — `tests/test_dynamic_reachability.py` (27 tests) covers all pure-Python logic: `_patch_dockerfile` (single-stage, multi-stage, WORKDIR detection, already-patched guard), `_parse_cmd_line` (JSON-array and shell forms), `_parse_file_imports` (AST alias resolution, dotted imports, syntax errors), `_target_host` (native vs Docker), and `_correlate` (strategy 1 direct library hit, 2a call-site and import-line, 3 taint stack, no-evidence skip, multiple CVEs per package, import-map fallback, custom container WORKDIR, short package name guard).
- **CI pipeline** — `.github/workflows/ci.yml` with three jobs: `lint` (ruff), `test` (pytest with postgres service, `--cov-fail-under=60` coverage gate, coverage artifact upload), `docker-build` (smoke-test image build on every push/PR to main).
- **`InMemoryRepository`** — Added to `tests/conftest.py`: a full in-memory implementation of the `StorageRepository` interface used across integration tests without a real database.

### Bug Fixes

#### Tests
- **`test_correlation.py` stale assertion** — `reachability_verdict(True, True, True)` was asserted to return `"LIKELY"` but the engine correctly returns `"CONFIRMED"` (import + call_chain + sink_reachable = full static trace to sink). Updated assertion and clarified comments.
- **`test_repository.py` psycopg2 mock contamination** — When `test_api_server.py` ran before `test_repository.py`, it replaced `psycopg2` in `sys.modules` with a `MagicMock`. The skip guard checked the URL string but not the module type, so `pytest.importorskip` passed and DB calls returned mocks. Fixed by checking `isinstance(sys.modules.get("psycopg2"), MagicMock)` at both the module-level skip mark and inside the `repo` fixture.

---

## [Unreleased] — 2026-03-26

### Bug Fixes

#### Docker / Infrastructure
- **Git clone not on bind mount** — `GitAgent` was cloning repos into the system temp dir (`/tmp/vulnreach-<repo>-<random>`) instead of `_WORK_BASE` (`/tmp/vulnreach/`). The host Docker daemon couldn't resolve the build context path for sibling containers. Fixed by passing `dir=_WORK_BASE` to `tempfile.mkdtemp`.
- **`docker compose` plugin missing** — Dockerfile only installed `docker-ce-cli`; `docker compose` subcommand was unavailable inside the container. Fixed by adding `docker-compose-plugin` to the apt install step.
- **`localhost` unreachable from inside Docker** — Health checks and Schemathesis were targeting `http://localhost:<port>` which resolves to the vulnreach container's own loopback, not the host. Added `_target_host()` helper that returns `host.docker.internal` when running inside Docker (detected via `/.dockerenv`), falling back to `localhost` for native runs. Applied to all three scan modes (Dockerfile, compose, eBPF).
- **`host.docker.internal` not resolvable on Linux** — Added `extra_hosts: host.docker.internal:host-gateway` to `docker-compose.yml` so the hostname resolves on Linux Docker hosts (it works automatically on Docker Desktop for macOS/Windows).
- **Tainter hardcoded macOS binary path** — `_run_scan` ignored its `tainter_bin` argument and had `/Library/Frameworks/Python.framework/Versions/3.11/bin/tainter` hardcoded, causing `[Errno 2] No such file or directory` inside the container. Fixed by calling `"tainter"` directly and catching `FileNotFoundError` for a clean skip.
- **`shutil.which` resolving host PATH into container** — Removed `shutil.which("tainter")` pre-flight check; availability is now determined at execution time via `FileNotFoundError`.
- **Tainter installed from local wheel** — Added `COPY libs/tainter-0.1.0-py3-none-any.whl` + `pip install` step to Dockerfile so `tainter` is available on PATH inside the container.

#### Dynamic Reachability — Coverage
- **Coverage restricted to app code only** — `.coveragerc` was generated with `source = .`, excluding site-packages entirely. Strategy 1 (direct library path match) never fired. Fixed by removing the `source` restriction and adding `omit` patterns for packaging noise (`pip`, `setuptools`, `pkg_resources`, `coverage`, `distutils`, `ensurepip`, internal `_*` modules). Coverage now traces site-packages so library execution is directly observable.
- **Strategy 1 only matched filenames, not full paths** — `import_name in hit_files` checked basename only (e.g. `adapters.py`), missing site-packages paths like `/usr/local/lib/python3.11/site-packages/requests/adapters.py`. Added full-path check: `f"/site-packages/{import_name}"` against `hit_files_full`.
- **Container paths not resolving to host files** — Coverage JSON produced inside Docker containers uses paths like `/app/api/views.py`. On the host, `Path("/app/api/views.py")` doesn't exist, and `repo_path / "/app/..."` discards the prefix (Python absolute path join). Fixed by stripping known container WORKDIR prefixes (`/app/`, `/code/`, `/srv/`, `/usr/src/app/`, `/home/app/`) before joining with `repo_path`.
- **Coverage flush unreliable** — `_extract_coverage_via_compose` ran once with a 30s timeout and no success validation. Fixed with retry logic (3 attempts, 5s apart), also copies `.coverage*` from `/app/` in addition to `/tmp/`, and validates `coverage.json` exists with >50 bytes before declaring success. Returns a bool indicating success.

#### Dynamic Reachability — Correlation
- **Aliased imports invisible to call-site matching** — Regex scanning for call sites matched raw token names (e.g. `sa`, `np`) instead of the real package names (`sqlalchemy`, `numpy`). `from flask import render_template` → `render_template(` was not linked back to `flask`. Replaced regex import scanning with AST-based `_parse_file_imports()` that builds two maps per file:
  - `alias_to_pkg`: `import sqlalchemy as sa` → `{sa: sqlalchemy}`
  - `imported_names`: `from flask import render_template` → `{render_template: flask}`
  Call-site matching now resolves through both maps before recording a hit.
- **Flat 0.40 confidence for all import-level evidence** — Strategy 2a assigned the same confidence regardless of how strong the evidence was. Replaced with three sub-levels:
  - Call-site line executed → **0.80** confidence, `sink_reachable=True`
  - Import line itself executed → **0.65** confidence, `sink_reachable=False`
  - File-level fallback (file ran, imports pkg, line unconfirmed) → **0.40** confidence
- **PyPI → import name mapping too small** — `_PYPI_TO_IMPORT` had only 7 entries, causing silent misses for common packages with mismatched names. Expanded to ~50 entries covering: crypto (`pyjwt→jwt`, `pyopenssl→OpenSSL`, `pycryptodome→Crypto`, `argon2-cffi→argon2`), DB drivers (`psycopg2-binary→psycopg2`, `cx-oracle→cx_Oracle`, `pymysql→pymysql`), web extensions (`djangorestframework→rest_framework`, `flask-login→flask_login`, `flask-cors→flask_cors`), media (`opencv-python→cv2`), messaging (`kafka-python→kafka`, `grpcio→grpc`), and others.

#### API
- **`/scan` returning 400 with no log context** — Added `logger.info` and `logger.warning` to the scan endpoint so config load failures and request parameters are visible in container logs, making it easier to diagnose path mismatches.

### Notes
- When running vulnreach via docker-compose, `repo_path` fields must use container-internal paths (e.g. `/app/scans/myrepo`) or use `repo_url` for git clone. Host filesystem paths are not accessible inside the container unless explicitly mounted.
- The `VULNREACH_TARGET_HOST` environment variable can be set to override the auto-detected target host used for health checks and Schemathesis.

# Changelog

## [Unreleased] — 2026-08-09

### Added

#### Transitive reachability from container metadata (runtime back-stop, Node)
- Added a second transitive source: the target app's *installed* dependency graph, read from the
  container the runtime path already has (`/proc/<pid>/root`). This complements the lockfile source
  — it exists even for a repo that ships no lockfile — and back-stops the eBPF observer: a vulnerable
  package that never loaded during the traffic window but is reachable through the dependency graph
  from a package that *did* load is structurally reachable, so it becomes **POSSIBLE** (with a
  `reachable_via` chain) instead of NOT_OBSERVED. This is additive, not redundant — the observer
  reports what *ran* (empirical, LIKELY/CONFIRMED); this reports what is *present and structurally
  reachable* but unobserved (POSSIBLE), which matters most when traffic coverage is partial or
  dependencies load lazily.
- `requires_graph_from_container` reads npm `node_modules/*/package.json` (scoped + nested handled);
  wired through `to_reachability_findings` (new `requires_graph` arg — the loaded packages are the
  closure roots) and built in `observer_runner`. **Node only for now:** npm's package name is
  consistent across the install dir, manifest, and vuln feed, so the graph and the observer's reached
  set share a namespace. Python (dist-vs-import name) and Java (pom parsing) need name reconciliation
  and are deferred.

#### Transitive reachability for Node (npm package-lock.json)
- Extended transitive reachability — a vulnerable dependency reached through a used package →
  POSSIBLE with a parent chain — to JavaScript. `requires_graph_from_lockfile` is now
  ecosystem-aware and parses `package-lock.json` (npm lockfileVersion 1/2/3): v2/v3 keys packages by
  install path (`node_modules/<name>`, nested for version conflicts), v1 nests a tree with
  `requires`; scoped (`@scope/pkg`) and nested packages are handled. Wired into the multi-language
  bridge, which builds the graph per detected language and applies the upgrade to that language's
  findings.
- Validated against a real, large lockfile (npm CLI's 437 KB / 870-package `package-lock.json`):
  correct closures such as `chalk → ansi-styles → color-convert → color-name` and
  `glob → minimatch → brace-expansion → concat-map`.
- **Java is intentionally not covered here.** Maven resolves the transitive tree at build time, so a
  source-only checkout has no dependency graph (`pom.xml` lists direct deps only). The edges exist
  only in the built jars (each carries its own `pom`), which is the container/runtime path — a
  separate future source, not a static-time one. Node without a committed `package-lock.json`
  degrades to no transitive upgrades, same honest limitation as a lockfile-less Python app.

### Fixed

#### Transitive reachability was a silent no-op in production — now sourced from lockfiles
- Transitive reachability (a vulnerable dep reached through a used package → POSSIBLE, added
  2026-08-06) never fired in a real scan. The agent read the dependency graph from
  `context.container_root` / `context.target_root`, but **`ScanContext` has no such fields**, so it
  always fell through to `requires_graph_from_env()` — the *scanner's* installed packages (289 of
  vulnreach's own deps), which never contain the target app's edges. Verified by tracing the scan:
  no step installs the target's requirements, and `MetadataAgent` likewise reads the scanner's
  `importlib.metadata`, not the app's. The feature validated in Tier 3 only because the harness fed
  it a container-derived graph explicitly.
- Fixed by sourcing the graph from a **lockfile in the repo** — the one place the resolved
  dependency graph exists at static time without the app's installed environment.
  `requires_graph_from_lockfile` parses `poetry.lock` and `uv.lock` (both carry explicit
  inter-package edges); `_requires_graph` now prefers it and drops the dead container-root gattrs.
  Honest limitation, documented: an app with only a pinned `requirements.txt` (no lockfile, e.g.
  `labs/python_vuln_app`) still gets no transitive upgrades at static time — a lockfile-less project
  has no edge source until the runtime/container path can supply one (a future enhancement).
  `Pipfile.lock` is intentionally unsupported: it records versions but not edges.
- Tests: `test_transitive_reachability.py` gains poetry.lock / uv.lock parsing, the no-lockfile
  no-op, and an agent-level test asserting the graph comes from the repo lockfile rather than the
  scanner env (the exact bug).

## [Unreleased] — 2026-08-06

### Added

#### Tier 3 — static reachability scored against runtime (eBPF) ground truth
- **`agents/ebpf/observer/e2e/static_vs_runtime.py`** — an oracle that runs the real static
  reachability path over an app's source and compares its per-package verdicts against the eBPF
  observer's runtime inventory (which packages actually loaded/executed). Turns "static recall
  improved" from an assertion into a measurement, and surfaces static **false negatives** — a
  package that ran but static called unreachable — the PyYAML-class error that tells a user to
  ignore a live CVE. Scoped to declared deps that are actually installed (the fair universe;
  aligned on import name so `PyYAML`↔`yaml`). Splits false negatives into *direct-detection bugs*
  (imported in source yet missed — a real regression) vs *indirect/transitive* (pulled in by
  another dep, invisible to source-scanning static by design).
- **First result — `labs/python_vuln_app` vs eBPF ground truth (16 packages loaded):**
  **precision 1.00, recall 0.33**, and critically **zero direct-detection bugs**. The three
  packages the app imports directly (`flask`, `requests`, `PyYAML`) are all caught and CONFIRMED
  with no over-claiming; all six misses are indirect — `jinja2`/`werkzeug`/`markupsafe` (via Flask),
  `certifi`/`urllib3` (via requests), and `coverage` (via the coverage-injection `sitecustomize`).
  This reframes the earlier "recall 33%→100%" honestly: the 100% was on *directly-imported* deps;
  overall recall against everything that loads is 0.33, and the entire gap is **transitive
  reachability** — where a large share of real CVEs live (urllib3, werkzeug) — not detection bugs.
  Motivates the transitive/framework-mediated reachability work next.

### Fixed

#### Static Java & JavaScript reachability over-claimed CONFIRMED
- **`agent_java_reachability.py`, `agents/reachability/agent_bridge.py`** — both set
  `sink_reachable = call_chain_exists`, so every used Java/JS/Go/PHP/C# package with a call chain
  became CONFIRMED 0.95 with no proof the vulnerable sink was reached — the mirror image of the
  Python false-negative below (over-claiming rather than under-claiming). Both now require a taint
  path into the package's namespace, via a shared matcher.
- **`agents/reachability/taint_match.py` (new)** — one conservative taint→package matcher for all
  languages. Distribution names are not sink namespaces, and each language resolves its own: Python
  via `import_resolver` (`PyYAML`→`yaml`), npm by bare/scoped name (`@a/b`→`b`), Maven by group
  namespace **and** artifact token as a dotted segment of the sink (so `org.freemarker:freemarker`
  matches sink `freemarker.template` and `com.google.code.gson:gson` matches `com.google.gson`,
  where group ≠ package). Generic Maven tokens (`core`, `client`, …) never match alone. When it
  cannot confidently associate a sink with a package it returns False, so the finding stays LIKELY.
- **Tainter is not Python-only** — tainter 1.0.2 ships Java, JavaScript, and Go flow finders
  (verified: `java.lang Runtime.exec`, JS `eval`, and library sinks `axios`/`sequelize`/
  `com.google.gson`/`org.apache.velocity`). The runner previously skipped tainter for every
  non-Python-only repo, so the Java and multi-language verdicts had no taint evidence at all. It now
  runs whenever a supported language is present (`_TAINTER_LANGUAGES`), sequenced before the static
  stage so its flows are available. The ROADMAP's "taint-flow is Python-only" is stale.
- **Taint is stronger than the analyzer's call graph, not gated behind it** — a taint flow is itself
  a proven source→sink path, so it establishes CONFIRMED on its own. The earlier grounding
  (`sink_reachable = call_chain_exists AND taint`) would have produced **zero** CONFIRMEDs for
  Java/JS, because those analyzers frequently emit no call graph — verified live: a real tainter
  SSRF flow into `axios` reached CONFIRMED only once taint stopped being gated behind the (absent)
  JS call graph. Applied consistently to Python too.

Live end-to-end (real tainter + real multi-language bridge, JS SSRF fixture): `axios` (tainted) →
CONFIRMED 0.95, `lodash` (used, not tainted) → POSSIBLE. Caveat: tainter's Java *library*-sink
detection is uneven (its `Gson().fromJson` pattern did not fire), though builtin sinks and the
matcher against its declared sink namespaces are validated.

#### Static Python reachability — the call graph had been dead for seven months
- **`agents/reachability/python_call_graph.py`, `dependency_tree_analyzer.py`** — moved into the
  package from `agents/utils/`. When `agents/reachability/` was created (2026-01-02, `667e355`) the
  Java and JavaScript call graphs moved with it but the Python ones did not, so
  `from .python_call_graph import PythonCallGraphBuilder` resolved to nothing. Both imports sat
  behind a bare `except ImportError`, so instead of failing they silently set `HAS_CALL_GRAPH=False`
  and `HAS_DEP_TREE_ANALYZER=False`. **Consequence: `call_chain_exists` and `sink_reachable` were
  always False for Python, no static finding could reach CONFIRMED, and transitive dependency
  detection never ran.** Verified against `labs/python_vuln_app`: static recall was 2 of 6 packages
  that eBPF observed loading.
- **PyPI name → import name resolution** — `find_package_usage` matched source imports against the
  raw distribution name, so `PyYAML` never matched `import yaml`, `Pillow` never matched
  `from PIL import Image`, `beautifulsoup4` never matched `import bs4`. The resolver
  (`agents/utils/import_resolver.py`) already existed and was already used by TainterAgent and
  DynamicReachabilityAgent — static reachability simply never called it. On the project's own demo
  app this scored **PyYAML as NOT_OBSERVED at confidence 0.1**, advising users to ignore a reachable
  `yaml.load` on request data; it now scores CONFIRMED 0.95. New
  `PythonReachabilityAnalyzer.candidate_module_names()`; the analyzer also accepts `import_map` so
  MetadataAgent's per-app discoveries layer over the curated table.
- **Findings no longer contradict themselves** — the verdict and the reported evidence were computed
  from different values, so a finding could report `verdict=LIKELY` (which `correlation.engine`
  defines as import + call chain) beside `call_chain_exists=False`. Both now derive from one set of
  booleans. Import-only correctly reports **POSSIBLE** rather than LIKELY.
- **CONFIRMED now requires taint evidence** — `sink_reachable` was set to `bool(call_chain_graph)`,
  conflating "a call chain reaches this package" with "the vulnerable sink is reachable", which made
  every used package CONFIRMED 0.95 and could not distinguish `yaml.safe_load` from `yaml.load`. It
  now requires a static taint path into the package's module, mirroring Rule R4 on the eBPF side.
  `TainterAgent` is sequenced before the parallel static stage in `agents/runner.py` — run
  concurrently it was a race that would have left `context.taint_flows` empty.
- **Unbounded subprocesses in `dependency_tree_analyzer`** — all six package-manager calls
  (`pipdeptree`, `npm ls --all`, `composer show`, `go mod graph`, `dotnet list`) ran with **no
  timeout** against untrusted repository content, several of which reach the network. All are now
  bounded. The `_has_pipdeptree()` probe shelled out to `pipdeptree --version`, measured at **over
  180 seconds** against a large global site-packages — the probe, not the query, was the hang; it now
  uses `shutil.which`. The pip dependency tree is cached per analyzer instance instead of being
  rebuilt once per vulnerable package. Re-enabling transitive analysis without these hung a scan of a
  3-file app; the same scan now completes in **0.7s**.
- **macOS temp directories were refused** — the system-directory guard rejected any path under
  `/var`, but `tempfile.gettempdir()` resolves to `/private/var/folders/...` on macOS, so the
  analyzer refused to scan any temporary workdir there. The OS temp root is now exempted.

### Added

- **`tests/test_static_reachability.py`** — 14 unit tests (no Docker, no root, so they run in normal
  CI). Covers the regression directly: `test_optional_analysis_modules_are_actually_importable`
  asserts `HAS_CALL_GRAPH`/`HAS_DEP_TREE_ANALYZER` are True, which is the check that would have
  caught the seven-month outage. Also covers distribution→import name bridging, the full verdict
  gradation (CONFIRMED / LIKELY / POSSIBLE / NOT_OBSERVED), and that reported evidence always agrees
  with the verdict. This path previously had no test coverage at all.

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

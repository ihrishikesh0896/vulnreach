# OSS / OWASP Incubator Readiness

This checklist tracks minimum readiness for an OWASP Incubator-quality OSS security tool.

Status legend:
- `[x]` complete
- `[~]` in progress
- `[ ]` not started

## P0 Security and Trust

- [x] Secure-by-default runtime boundary:
  - Dynamic daemon mode requires `VULNREACH_ALLOW_DOCKER_DAEMON=true`.
  - Base compose excludes Docker socket by default.
  - Runtime override file isolates high-privilege mode.
- [x] eBPF explicit opt-in (`VULNREACH_ALLOW_EBPF=true`).
- [~] Command execution hardening audit for all subprocess paths.
- [x] Docker socket proxy profile (`docker-compose.runtime.yml`) for dynamic mode isolation.

## P0 Correctness and Determinism

- [x] Correlation keyed by `(package, CVE)` not CVE-only.
- [x] Route gate enforced for dynamic reachability.
- [x] Multi-language reachability path wired into runner.
- [x] `GET /scan/{id}` contract returns summary + classified buckets.
- [x] Deterministic Java/JavaScript/Go fixture tests in CI.
- [x] Java runtime confirmation via `hotspot:method__entry` eBPF USDT probes (Log4Shell / Text4Shell / SnakeYAML E2E lab in `labs/ebpf-e2e-java/`).
- [x] AI augmentation layer is architecturally separated from the deterministic engine: the LLM never re-derives, overrides, or contradicts a verdict; consumes a versioned `EvidenceGraph` rather than raw scanner JSON; failures cannot fail scans.

## P0 AI / LLM Safety

The AI layer is deliberately scoped to analyst augmentation only. Reviewers may verify these properties directly:

- [x] **Read-only over the verdict** — `agents/agent_next_steps.py` raises `ValueError` if a finding has no deterministic verdict; the system prompt explicitly forbids re-derivation.
- [x] **No raw scanner JSON in prompts** — only the normalised `EvidenceGraph` (`correlation/evidence_graph.py`) is sent to the LLM. The graph schema is versioned (`EVIDENCE_GRAPH_VERSION`).
- [x] **No scan-time LLM dependency** — `POST /findings/{id}/next-steps` is on-demand. Scans complete without ever invoking an LLM; absence or failure of `ANTHROPIC_API_KEY` cannot fail a scan.
- [x] **Graceful degradation** — LLM errors return `status="degraded"` with the EvidenceGraph still attached; analysts retain value when the AI is down.
- [x] **Versioned, cached, auditable** — every response carries `prompt_version`, `evidence_graph_version`, and `evidence_hash`. Cache key composes all three, so prompt or schema bumps invalidate stale entries deterministically.
- [~] Pinned-fixture eval set for `/next-steps` output quality (planned; gates the lazy → eager promotion).

## P0 Threat Modeling and Documentation

- [x] Threat model document with trust boundaries and STRIDE analysis.
- [x] Deployment guidance distinguishes low-privilege vs high-privilege modes.
- [~] Data retention/redaction policy for raw findings.
- [ ] Architecture decision records (ADRs) for major security tradeoffs.

## OSS Governance

- [x] Apache 2.0 license, contribution guide, security policy.
- [x] Governance model documented (`GOVERNANCE.md`) — currently BDFL, single maintainer.
- [~] Maintainer rotation/on-call + response SLA documented — targets set in `GOVERNANCE.md`,
      not yet backed by a funded rotation (one maintainer today).
- [ ] Versioned support policy and deprecation windows.
- [ ] Signed release artifacts and provenance (SLSA-style).

## CI/CD Quality Gates

- [x] Lint + unit tests + coverage gate.
- [x] Deterministic multi-language fixture checks.
- [x] Dependency vulnerability scan (`pip-audit`) + CycloneDX SBOM generation, ratchet-gated
      (`dependency-audit` job in `.github/workflows/ci.yml`); weekly `dependabot.yml` updates.
- [x] Cross-platform unit coverage for `agents/ebpf/` (`package_index.py`, `observer_client.py`)
      runs without Linux/root/Docker; only the real kernel cgroup-isolation proof
      (`test_ebpf_observer_p0.py`) is gated, and that gate is correct, not a gap.
- [ ] End-to-end nightly scan suite with pinned vulnerable fixtures.
- [ ] Performance regression baseline (large monorepo fixture).

## Recommended Next 2 Weeks

1. Add artifact attestation/signing for scan outputs.
2. Add end-to-end nightly fixture scans with time budgets and flake tracking.
3. ~~Publish maintainer/SLA policy in `CONTRIBUTING.md`.~~ Done — see `GOVERNANCE.md`.
4. Add ADRs for dynamic runtime trust-boundary decisions.
5. Work down the `dependency-audit` ratchet baseline (93 unique known vulnerabilities across 17
   packages as of 2026-09-30) via Dependabot PRs.

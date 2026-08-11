# VulnReach

**Runtime-aware SCA — proves which CVEs are actually reachable, not just installed.**

[![OWASP Project](https://img.shields.io/badge/OWASP-Project-blue.svg)](https://www.owasp.community/projects/vulnreach)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

> **VulnReach is now an official [OWASP Project](https://www.owasp.community/projects/vulnreach).** 🎉

## Demo

[![VulnReach Demo](https://img.youtube.com/vi/d0lCo1nJzVM/maxresdefault.jpg)](https://youtu.be/d0lCo1nJzVM?si=ZDzG6kxvuCosQ7ts)

### Step 1 — SCA surfaces 74 CVEs across dependencies
![Trivy SCA output — 74 vulnerabilities detected](docs/screenshots/only_trivy_SCA.png)

### Step 2 — VulnReach proves which ones are actually reachable
![Fix Plan — 7 packages, 50 confirmed reachable CVEs with upgrade targets](docs/screenshots/package_to_upgrade_vs_CVE_count.png)

---

### Findings — evidence chain per CVE
![Dynamically reachable findings with full evidence chain](docs/screenshots/dynamic_reachability_landing.png)

### Dashboard — 42 confirmed reachable across 9 repos
![VulnReach Dashboard](docs/screenshots/scan_page.png)

> **Language support:** Python is fully production-ready (taint, AST, route, runtime). Java and JavaScript have functional call graph analysis and are experimental. Go, C#, and PHP are on the roadmap. See [ROADMAP.md](ROADMAP.md) for details.

VulnReach builds on standard SCA output by adding reachability context — proving through static analysis, taint tracking, and live runtime coverage which of the detected CVEs can actually be reached in your application.

---

## Project Status

### Latest Development (shipped)

- Dependency-aware **parallel runner pipeline** for faster scans
- **Python reachability** — production-ready (taint, AST, route, runtime layers all functional)
- **Java reachability** — functional call graph with Maven/Gradle dependency parsing (experimental)
- **JavaScript reachability** — functional call graph with route entry point detection (experimental)
- **Scan cancellation** — `POST /scan/{id}/cancel` stops in-progress scans
- Stable scan response contract: `summary` + classified buckets on `GET /scan/{id}`
- Shared scan response normalization across API and package local mode (parity)
- Secure-by-default runtime boundary:
  - base compose runs without Docker socket mount
  - dynamic scans require explicit opt-in via `VULNREACH_ALLOW_DOCKER_DAEMON=true`
  - runtime profile uses restricted `docker-socket-proxy`
- Deterministic fixture quality gates for Java/JavaScript/Go in CI
- **Accepted as an official OWASP Project** — [owasp.community/projects/vulnreach](https://www.owasp.community/projects/vulnreach)
- **AI next-steps endpoint** — `POST /findings/{id}/next-steps` produces analyst-facing remediation guidance (immediate actions, validation probes, upgrade paths, monitoring) for a deterministic finding. Lazy / on-demand: scans never call the LLM, and LLM failures degrade gracefully. The deterministic verdict is read-only. See [docs/api.md](docs/api.md#post-findingsfinding_idnext-steps).

### Experimental

- `scan.runtime.ebpf` tracing mode (Linux-focused, explicit opt-in)
- AI-assisted OpenAPI generation and Intelligent DAST flows

See:
- [docs/incubator-readiness.md](docs/incubator-readiness.md)
- [docs/threat-model.md](docs/threat-model.md)

---

## How it works

Each CVE is classified through a five-layer evidence chain:

```
1. SCA (Trivy)              → is the package installed and vulnerable?
2. Taint analysis (tainter) → does user input flow to the vulnerable sink?
3. AST analysis             → is the vulnerable function in your call graph?
4. Route exposure           → is the call path reachable from an HTTP endpoint?
5. Runtime coverage         → was the vulnerable code actually executed?
```

The result is a prioritised finding list with four tiers:

| Tier | Meaning |
|------|---------|
| `DYNAMICALLY_REACHABLE` | Runtime coverage confirmed execution — fix immediately |
| `STATICALLY_REACHABLE` | Code path proven via AST/taint — high priority |
| `UNCERTAIN` | Weak signal only — investigate |
| `NOT_REACHABLE` | No evidence — suppress from alert queue |

---

## Quick Start

### With Docker Compose (recommended)

> **Security notice** — before starting, copy `.env.example` to `.env.local` and
> replace every `CHANGE_ME` value with a strong random secret.  
> Do **not** expose VulnReach on a public network without setting real credentials
> and configuring `CORS_ORIGINS`.

```bash
git clone https://github.com/ihrishikesh0896/vulnreach.git
cd vulnreach

# 1. Create your local config
cp .env.example .env.local

# 2. Fill in every CHANGE_ME — generate secrets with: openssl rand -hex 32
$EDITOR .env.local

# 3. Start the stack
docker compose up --build

# Optional: enable dynamic runtime scans (Docker daemon access via restricted socket proxy)
# docker compose -f docker-compose.yml -f docker-compose.runtime.yml up --build
```

### Run a scan

Auth options:
- Short-lived JWT: `POST /login`
- Long-lived API token (API key): create in UI `Settings -> API Keys`, then use it as `Authorization: Bearer <API_KEY>`

```bash
# Get a token (replace with the credentials you set in .env.local)
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<your-admin-user>","password":"<your-admin-password>"}' | jq -r .access_token)

# Start scan from a GitHub repo
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/yourorg/yourapp"}'

# Poll for results
curl http://localhost:8000/scan/<scan_id> \
  -H "Authorization: Bearer $TOKEN" | jq .summary
```

---

## Features

- **Reachability-filtered SCA** — classifies each CVE by evidence strength, not just CVSS score
- **Runtime confirmation** — Docker-based coverage collection via `coverage.py`
- **Taint tracking** — traces user input → vulnerable sinks (SQL, subprocess, YAML, pickle)
- **LLM-steered DAST** — Claude/OpenAI/Ollama generates and validates exploit payloads (optional)
- **CI/CD gates** — `policy.block_if` fails builds on confirmed critical findings
- **JWT auth** — multi-user, role-based access (admin / analyst)
- **API tokens (API keys)** — long-lived machine auth for curl/CI (`Authorization: Bearer <API_KEY>`)
- **PDF export** — `GET /scan/{id}/export/pdf`
- **No vendor lock-in** — LLM features default to `provider: none`; Ollama supported for offline use

---

## In Practice

Scan target: [multi-tier-dvpa](https://github.com/ihrishikesh0896/multi-tier-dvpa) — an intentionally vulnerable Python/Django application with 72 raw CVEs across 11 packages.

| Layer | Result |
|---|---|
| Raw CVEs (Trivy) | 72 |
| Classified findings (VulnReach) | 90 |
| DYNAMICALLY_REACHABLE — fix now | **49** |
| STATICALLY_REACHABLE — fix this sprint | **23** |
| UNCERTAIN — investigate | **18** |
| NOT_REACHABLE — suppress | 0 |
| CI pipeline gate | **BLOCKED** |

46% of findings were moved out of the undifferentiated "fix everything" queue into a prioritised action list. In a typical production service (where many transitive dependencies are never called), this figure rises to 70–90%.

Full methodology, evidence chain detail, and package-level breakdown: [docs/benchmark.md](docs/benchmark.md)

---

## Documentation

### Usage

- [POC.md](POC.md) — **first project in ~10 min** — UI-only PoC against a bundled vulnerable app
- [USAGE_PACKAGE.md](USAGE_PACKAGE.md) — package/CLI installation, dependencies, startup, usage
- [USAGE_UI.md](USAGE_UI.md) — UI/server installation, dependencies, startup, usage

### Operators / Deployers

- [docs/deployment.md](docs/deployment.md) — Docker Compose setup, env vars, production notes
- [docs/configuration.md](docs/configuration.md) — full `scan.yml` config reference
- [docs/api.md](docs/api.md) — REST endpoints and schemas

### Architecture / Security

- [docs/architecture.md](docs/architecture.md) — pipeline design and execution model
- [docs/threat-model.md](docs/threat-model.md) — trust boundaries, STRIDE, abuse cases
- [docs/incubator-readiness.md](docs/incubator-readiness.md) — OSS/OWASP readiness status
- [docs/DAST.md](docs/DAST.md) — DAST concepts and flow

### Contributors

- [ROADMAP.md](ROADMAP.md) — planned features, known limitations, language support status
- [docs/development.md](docs/development.md) — internals, agents, storage, extension points
- [OWASP.md](OWASP.md) — OWASP project notes
- [SECURITY.md](SECURITY.md) — vulnerability disclosure and key rotation
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution process
- [CHANGELOG.md](CHANGELOG.md) — release history

---

## Requirements

- Python 3.11+
- PostgreSQL 13+
- Docker + Docker Compose v2 (for dynamic analysis)
- `trivy` on PATH ([install](https://aquasecurity.github.io/trivy/latest/getting-started/installation/))
- `jq` (used in quick start examples — [install](https://jqlang.github.io/jq/download/))

Optional (all skip gracefully if absent):
- `semgrep` — `pip install semgrep`
- `tainter` — `pip install tainter` (taint-flow analysis; see [development guide](docs/development.md#tainter--optional-taint-analysis))

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

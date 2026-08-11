# VulnReach UI Usage

This guide is for running and using the **web UI** (the `dashboard`) served by the
VulnReach API server. Everything here is done in the browser unless a step is
explicitly marked otherwise.

> One feature — the **RBOM / CycloneDX export** — is API-only today (there is no
> button for it in the UI yet). It is called out in [§11](#11-rbom--cyclonedx-api-only).

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Configure environment](#2-configure-environment)
3. [Start the stack](#3-start-the-stack)
4. [Verify services](#4-verify-services)
5. [Open the UI & sign in](#5-open-the-ui--sign-in)
6. [The dashboard at a glance](#6-the-dashboard-at-a-glance)
7. [Scan a project](#7-scan-a-project)
8. [Track scans (Scan History)](#8-track-scans-scan-history)
9. [Inspect a scan & check findings](#9-inspect-a-scan--check-findings)
10. [Explain & call-graph](#10-explain--call-graph)
11. [RBOM / CycloneDX (API-only)](#11-rbom--cyclonedx-api-only)
12. [Inventory](#12-inventory)
13. [Export (CSV / PDF)](#13-export-csv--pdf)
14. [Supporting pages: Tools, Config, API Access, Settings](#14-supporting-pages)
15. [Add more users](#15-add-more-users)
16. [Common issues](#16-common-issues)

---

## 1. Prerequisites

- Docker `24+`
- Docker Compose v2 (`docker compose`)
- A `.env.local` based on `.env.example`

---

## 2. Configure environment

```bash
cp .env.example .env.local
```

Set at minimum:

| Variable | Purpose |
|---|---|
| `POSTGRES_PASSWORD` | Database password |
| `DATABASE_URL` | Must match the password above |
| `JWT_SECRET` | Signs session tokens |
| `SEED_ADMIN_USERNAME` | Your first login username |
| `SEED_ADMIN_PASSWORD` | Your first login password |

---

## 3. Start the stack

**Default (recommended):**

```bash
docker compose up --build
```

**With the dynamic runtime profile** (only when you need Docker-based runtime
coverage — higher privilege path):

```bash
docker compose -f docker-compose.yml -f docker-compose.runtime.yml up --build
```

The runtime profile also requires explicit opt-in env:
`VULNREACH_ALLOW_DOCKER_DAEMON=true` and `DOCKER_HOST=tcp://docker-socket-proxy:2375`.

---

## 4. Verify services

```bash
docker compose ps                       # db healthy, vulnreach running
curl -s http://localhost:8000/health    # {"status":"ok","boot_id":"..."}
```

---

## 5. Open the UI & sign in

1. Open **`http://localhost:8000`** in a browser.
2. Click **Sign in** (top bar) and enter your `SEED_ADMIN_USERNAME` /
   `SEED_ADMIN_PASSWORD`.
3. On success the sidebar and topbar appear. The token is held **in memory for
   the session only** — closing the tab signs you out.

The top bar shows an **API connected** status dot, a **theme toggle**, and a
**profile menu** (username, Settings, Sign Out).

---

## 6. The dashboard at a glance

The left **sidebar** is your map:

**Analysis**
| Item | What it does |
|---|---|
| **Scans** | Scan history + headline stats (default landing page) |
| **Inventory** | One card per onboarded repository |
| **New Scan** | Configure and launch a reachability scan |
| **Findings** | Jump-off to per-scan findings (pick a scan first) |

**Platform**
| Item | What it does |
|---|---|
| **Tools** | The security tools registered with VulnReach |
| **API Access** | How to authenticate for programmatic access |
| **Config** | The default scan configuration |
| **Settings** | Profile, theme, and **API Keys** |

---

## 7. Scan a project

1. Sidebar → **New Scan**.
2. Provide **one** of:
   - **Repository Path (local)** — a path the server container can see, e.g.
     `/home/user/myapp`, **or**
   - **Repository URL (remote)** — e.g. `https://github.com/org/repo`.
3. *(Optional)* **Config Path** — a `vulnreach.yaml`. When you use a URL this is
   auto-discovered, and a sensible default is used if none is found.
4. **Tools** — toggle the tool chips. Defaults: `trivy`, `tainter`,
   `python_reachability`. All tools **degrade gracefully** — anything missing or
   not applicable is skipped, not fatal.
5. Click **▶ Launch Scan**. A progress bar appears and the scan runs in the
   background; you can navigate away and come back.

> **Reachability tools worth knowing**
> - `trivy` — SCA / CVE inventory (the vulnerabilities)
> - `tainter` — source→sink taint paths
> - `python_reachability` — AST call-chain reachability
> - `dynamic_reachability` — runtime coverage (needs the runtime profile from §3)

---

## 8. Track scans (Scan History)

Sidebar → **Scans**.

- **Stat cards** at the top: **Repositories** tracked, **Confirmed** (reachable
  vulns), **Likely** (probable risk), and **Running** (active scans).
- The **Recent Scans** table lists one row per repository with latest status and
  last-scan time. Use **↺ Refresh** to poll, or **+ New Scan** to launch another.
- **Click a repository row** to drill into every scan for that repo (Scan ID,
  status, started time, findings count, tools).
- **Click a scan** to open its detail panel (next section).

---

## 9. Inspect a scan & check findings

Clicking a scan opens the **detail panel** with four tabs:

| Tab | Contents |
|---|---|
| **Overview** | Scan ID, status, repository, start time, tools, package counts + severity breakdown. A banner warns if any tools were skipped. |
| **Findings** | The reachability results (detailed below). |
| **Fix Plan** | Prioritised remediation guidance for the actionable findings. |
| **Raw JSON** | The full underlying scan payload. |

### Reading the Findings tab

A **summary bar** counts findings by 4-tier reachability class:

| Class | Meaning |
|---|---|
| 🔴 **Dynamically Reachable** | Vulnerable code was actually executed at runtime |
| 🟠 **Statically Reachable** | Reached by import + call-chain (and, when taint-grounded to the sink, promoted) |
| 🔵 **Uncertain** | Weak signal only — imported but no proven call path |
| ⚪ **Not Reachable** | No path found; typically dead-dependency CVEs |

Each finding row carries a **verdict badge** — `CONFIRMED`, `LIKELY`, `POSSIBLE`,
or `NOT_OBSERVED` — alongside package, CVE IDs, severity, priority, risk score,
fix version, and the implicated files/functions. **DAST findings** (if the DAST
tools ran) are shown in their own section.

> **Verdict ↔ reachability:** `CONFIRMED` means the full evidence chain held —
> for static findings that's import + call-chain + a taint-grounded sink; for
> dynamic findings it's taint flow **and** runtime coverage. `LIKELY` is import +
> call-chain without sink proof; `POSSIBLE` is import-only / uncertain;
> `NOT_OBSERVED` means no reachability was established.

The **Findings** sidebar item is a shortcut: it prompts you to pick a scan from
Scan History, then shows the same findings view.

---

## 10. Explain & call-graph

Inside the **Findings** tab, each CVE row has two quick actions:

- **⚡ Explain** — opens the Explain modal. Choose a provider:
  - **Offline** (default, no LLM),
  - **Claude** (needs an Anthropic key configured on the server), or
  - **Ollama** (set a model name; the Ollama URL comes from `VULNREACH_OLLAMA_URL`
    on the server).

  Click **Generate** for a plain-language explanation of the finding.
- **⋯ Call graph** — opens the **Call Chain** modal, rendering the reachability
  path from entry point to the vulnerable sink (when a call chain exists).

---

## 11. RBOM / CycloneDX (API-only)

VulnReach produces a **Reachability Bill of Materials (RBOM)** — the full
component inventory annotated with a reachability verdict and layered evidence
per package — and can emit it as **CycloneDX 1.5 with VEX** (reachability encoded
as the VEX analysis state: `CONFIRMED`/`LIKELY` → `exploitable`, `POSSIBLE` →
`in_triage`, `NOT_OBSERVED` → `not_affected` + `code_not_reachable`).

**There is no button for this in the dashboard yet** — it is served by the API.
Fetch it for any completed scan (grab the `scan_id` from the detail panel's
Overview tab or the URL):

```bash
# native RBOM (JSON)
curl -s http://localhost:8000/scan/<scan_id>/rbom \
  -H "Authorization: Bearer <TOKEN>"

# CycloneDX 1.5 + VEX
curl -s "http://localhost:8000/scan/<scan_id>/rbom?format=cyclonedx" \
  -H "Authorization: Bearer <TOKEN>"
```

See [§14 → API Access](#14-supporting-pages) for how to obtain `<TOKEN>`.

---

## 12. Inventory

Sidebar → **Inventory** shows one card per onboarded repository (the SBOM-style
rollup across its scans). Use **Export CSV** to download the inventory, or
**+ New Scan** to onboard another repo.

---

## 13. Export (CSV / PDF)

From an open **scan detail panel**, the header buttons let you download the
results:

- **CSV** (`fa-file-csv`) — a flat table: package, CVE IDs, severity,
  reachability, verdict, priority, risk score, fix version, files, functions.
- **PDF** (`fa-file-pdf`) — a formatted report for the scan.

The **Inventory** page has its own **Export CSV** for the repository rollup.

---

## 14. Supporting pages

| Page | Use |
|---|---|
| **Tools** | Browse the analysis tools registered with VulnReach and what each does. |
| **Config** | View the default scan configuration; customise by editing `config/scan.sample.yml`. |
| **API Access** | Auth options for programmatic access — **JWT** via `POST /login` (short-lived) or an **API key** (long-lived, for CI/CD). Both are sent as `Authorization: Bearer <TOKEN>`. |
| **Settings** | Profile, theme, and **API Keys** — create long-lived keys here (roles: `admin`, `analyst`). Copy a new key at creation time; it is shown once. |

**Getting a token (for API-only features like RBOM):**

```bash
# JWT (short-lived) — or create an API key under Settings → API Keys
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
```

---

## 15. Add more users

VulnReach seeds only the initial admin from `.env.local`. There is no public
user-create endpoint yet, so add users via the repository (run against the
`vulnreach` container):

```bash
# analyst
docker compose exec vulnreach python -c "import uuid; from storage import get_repository; from api.auth import hash_password; r=get_repository(); r.create_user(str(uuid.uuid4()), 'analyst1', hash_password('CHANGE_ME_STRONG_PASSWORD'), 'analyst'); print('created analyst1')"

# admin
docker compose exec vulnreach python -c "import uuid; from storage import get_repository; from api.auth import hash_password; r=get_repository(); r.create_user(str(uuid.uuid4()), 'admin2', hash_password('CHANGE_ME_STRONG_PASSWORD'), 'admin'); print('created admin2')"
```

Then sign in with the new credentials from the UI login.

---

## 16. Common issues

| Symptom | Likely cause / fix |
|---|---|
| UI loads but login fails | Verify seeded credentials in `.env.local`. |
| Signed out after refresh | Expected — the session token is in-memory only. |
| A tool shows as "skipped" (amber banner) | Expected when a tool isn't installed/applicable; results are still produced from the tools that ran. |
| Dynamic reachability never appears | Start with the runtime profile and opt-in env (see §3). |
| `401` on an API/RBOM call | Token missing, expired, or revoked — get a fresh one (§14). |
| Browser CORS errors (separate frontend origin) | Set `CORS_ORIGINS` to your UI origin. |

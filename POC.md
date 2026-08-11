# VulnReach PoC — Onboard Your First Project (~10 minutes)

Prove VulnReach end-to-end **entirely in the UI**, against a vulnerable app that
ships **inside** the image — no external repo, no cloning. You'll start the
stack, run a scan, and see reachability separate the CVEs that actually matter
from the noise.

> **The target:** `labs/python_vuln_app`, an intentionally-vulnerable Flask app
> bundled in this repo (Flask + `yaml.load` + `requests`). It is copied into the
> server image at **`/app/labs/python_vuln_app`**, so you can scan it by local
> path with zero setup.

**What you'll prove:** Trivy alone flags CVEs across ~20 packages; VulnReach adds
*reachability* on top, so `Flask` and `requests` come back **CONFIRMED**
(user input → vulnerable sink, taint-grounded), while packages that are declared
but not exercised drop to the bottom.

Then you'll graduate to **crAPI** — a real multi-language target — and see where
[`vulnreach.yaml`](#understanding-vulnreachyaml) config comes in.

---

## Before you start

- **Docker 24+** and **Docker Compose v2** (`docker compose`)
- ~10 minutes

You do **not** need Python, Trivy, or any repo of your own for this PoC.

---

## Step 1 — Configure secrets

```bash
cp .env.example .env.local
```

Edit `.env.local` and set (generate secrets with `openssl rand -hex 32`):

| Variable | Notes |
|---|---|
| `POSTGRES_PASSWORD` | any strong value |
| `DATABASE_URL` | must contain the same password |
| `JWT_SECRET` | random 32+ bytes |
| `SEED_ADMIN_USERNAME` | your login, e.g. `admin` |
| `SEED_ADMIN_PASSWORD` | your login password |

---

## Step 2 — Start the stack

```bash
docker compose up --build
```

Wait until the API answers:

```bash
curl -s http://localhost:8000/health     # {"status":"ok","boot_id":"..."}
```

---

## Step 3 — Sign in

1. Open **`http://localhost:8000`**.
2. Click **Sign in** (top bar), enter your `SEED_ADMIN_USERNAME` /
   `SEED_ADMIN_PASSWORD`.
3. The sidebar appears — you're in.

---

## Step 4 — Launch the scan

1. Sidebar → **New Scan**.
2. In **Repository Path (local)**, enter exactly:

   ```
   /app/labs/python_vuln_app
   ```

   *(This is the path **inside the server container**, where the bundled app
   lives. Leave Repository URL empty.)*
3. In **Config Path**, enter:

   ```
   /app/config/poc.yml
   ```

   *(A config path is **required for local-path scans**. `config/poc.yml` ships
   with the repo — a minimal static config; see
   [Understanding vulnreach.yaml](#understanding-vulnreachyaml) for what's in it.)*
4. **Tools** — the config already selects `trivy`, `tainter`,
   `python_reachability`; make sure those chips are on.
5. Click **▶ Launch Scan**. A progress bar appears; the scan runs in the
   background.

> **Why these three:** `trivy` finds the CVEs, `python_reachability` builds the
> call graph, and `tainter` traces user input → sink. Together they're what
> promotes a finding from "a CVE exists" to **CONFIRMED reachable**.

---

## Step 5 — Watch it finish

- Sidebar → **Scans**. Your repo appears in **Recent Scans**; the **Running**
  stat card drops to 0 when it completes (use **↺ Refresh** if needed).
- The **Confirmed** stat card should tick up — that's the headline: reachable,
  vulnerable, actionable.
- **Click the scan row** to open the detail panel.

> **Terminal statuses:** `completed` (done, no gate), `blocked` (done — a
> `policy.block_if` gate matched; **not an error**, results are complete),
> `partial` (some optional tools were skipped), `failed` (a required tool errored).
> `blocked`/`partial`/`completed` all have full findings to read.

---

## Step 6 — Read the findings

In the detail panel open the **Findings** tab. You should see something like:

| What you'll see | Why |
|---|---|
| A **reachability summary bar** splitting findings into Dynamically / Statically Reachable / Uncertain / Not Reachable | VulnReach classifies by *evidence*, not CVSS |
| **`Flask` → CONFIRMED** and **`requests` → CONFIRMED** | import + call chain + a **taint-grounded sink** (the strongest static verdict) |
| **`Jinja2`, `Werkzeug` → reachable, lower verdict** (POSSIBLE) | reached, but no proven source→sink flow |
| Packages with **no applicable CVE → NOT_OBSERVED** (e.g. the pinned `PyYAML`) | nothing to be reachable *to* — correctly deprioritised |

Roughly: **~20 components, ~12 reachable-and-vulnerable**, with **Flask and
requests CONFIRMED**. (Exact CVE counts drift as Trivy's DB updates; the
*reachability story* is what's stable and what matters.)

Other tabs in the same panel:

- **Overview** — scan metadata, tools run, package/severity counts.
- **Fix Plan** — prioritised remediation for the actionable set.
- **Raw JSON** — the full payload.
- **⚡ Explain** / **⋯ Call graph** (per-CVE, in the Findings tab) — plain-language
  explanation and the entry-point → sink path.

Export the result with the **CSV** / **PDF** buttons in the panel header.

---

## Step 7 (optional) — Pull the RBOM

The **Reachability Bill of Materials** (full inventory + verdict + evidence,
exportable as CycloneDX 1.5 + VEX) is **API-only today** — there's no UI button
yet. Grab the `scan_id` from the panel's Overview tab, then:

```bash
# get a token
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<your-admin-user>","password":"<your-admin-password>"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# native RBOM
curl -s http://localhost:8000/scan/<scan_id>/rbom \
  -H "Authorization: Bearer $TOKEN"

# CycloneDX 1.5 + VEX (reachability encoded as VEX analysis state)
curl -s "http://localhost:8000/scan/<scan_id>/rbom?format=cyclonedx" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Scan crAPI — a real multi-language target

`python_vuln_app` proves the mechanics on one small Python app. **crAPI**
([OWASP crAPI](https://github.com/OWASP/crAPI) — "completely ridiculous API") is
the realistic next step: a deliberately-vulnerable **multi-service** app spanning
**Java (Spring Boot), Python (Flask), Go and Node**. It's the case where a custom
`vulnreach.yaml` earns its keep.

Because crAPI lives in an external repo, you scan it **by URL** and point at a
config tailored for a polyglot codebase. `config/crapi.yml` ships with this repo
for exactly this.

1. Sidebar → **New Scan**.
2. **Repository URL (remote):**

   ```
   https://github.com/OWASP/crAPI
   ```

   Leave **Repository Path** empty.
3. **Config Path:**

   ```
   /app/config/crapi.yml
   ```

4. **Tools** — `config/crapi.yml` selects the polyglot set: `trivy`, `tainter`,
   `multi_language_reachability`, `route_extractor`, `metadata` (`git` is
   auto-added for URL scans). Confirm those chips.
5. **▶ Launch Scan**, then follow the same **Scans → open panel → Findings** flow
   as before.

**What to expect:** Trivy inventories CVEs across every ecosystem;
`multi_language_reachability` + `tainter` then separate the packages actually
reached by crAPI's services from the long tail of transitive/dev dependencies.
crAPI is large, so this scan takes a few minutes (clone + polyglot analysis).

> **Verified run** (against `github.com/OWASP/crAPI`): **1,450 components** across
> **3 ecosystems** (node 1,380 · python 46 · go 24); 65 vulnerable, **61 reachable**,
> and **1,389 `NOT_OBSERVED`** — the unreached tail reachability strips out. Only
> **5 land as `CONFIRMED`** (`djangorestframework`, `requests`, `fastmcp`, `uuid`,
> `ws`) — that's your fix-first list out of 1,450. Exact counts drift with the
> Trivy DB; the ratio is the point.

> **This scan ends with status `blocked` — that's success, not an error.**
> `config/crapi.yml` sets a `policy.block_if` gate, and crAPI has reachable
> confirmed HIGH/CRITICAL findings, so the pipeline status is `BLOCK` (a CI gate
> would fail the build here). Open the scan and read its Findings exactly as
> normal. Remove the `block_if` rules if you don't want the gate.

> **Runtime note:** crAPI's live behaviour is a multi-container `docker compose`
> stack, which VulnReach's single-container runtime mode does not stand up — so
> `config/crapi.yml` keeps `runtime.enabled: false` and relies on static
> reachability. That's the right default here.

> **Alternative — auto-discovered config:** for a repo you control, commit a
> `vulnreach.yaml` at the **repo root** and leave Config Path empty. For `repo_url`
> scans VulnReach auto-uses that file; if none exists it falls back to a built-in
> default. (Local **path** scans always require an explicit Config Path.)

---

## Understanding `vulnreach.yaml`

`vulnreach.yaml` (any name works when you pass it as Config Path; the special
name `vulnreach.yaml` at a repo root is what URL scans auto-discover) controls
which tools run and how findings are scored. It has four top-level blocks. Here's
a fully-annotated reference — everything not shown has a sensible default, and
**every tool degrades gracefully** if unavailable.

```yaml
scan:
  static_reachability: true      # master switch for static reachability analysis
  tools:                          # which agents run (order-independent)
    - git                         #   clones repo_url scans (auto-injected for URLs)
    - trivy                       #   SCA — the CVE inventory (the only required tool)
    - tainter                     #   taint analysis: user input -> vulnerable sink
    - python_reachability         #   Python AST call-chain reachability (single-language)
    - multi_language_reachability #   polyglot call-chain reachability (Java/Python/Go/Node)
    - route_extractor             #   HTTP route map (Flask / FastAPI / Django)
    - metadata                    #   resolves PyPI dist name -> importable module name
    # - semgrep                   #   optional SAST (uncomment to enable)
    # - pytest_coverage           #   optional: run the target's own test suite
    # - dynamic_reachability      #   runtime coverage (auto-added when runtime.enabled)

  runtime:                        # dynamic (runtime) reachability — OFF by default
    enabled: false                #   true requires VULNREACH_ALLOW_DOCKER_DAEMON=true
    timeout: 120                  #   max seconds for container start + traffic
    coverage_wait: 10             #   seconds to wait before flushing coverage
    container_port: 3000          #   port the target app listens on in its container
    ebpf:                         #   experimental syscall tracing (Linux only)
      enabled: false
      mode: openat                #   "openat" (portable) | "usdt" (line-level)
      tracer: bpftrace            #   "bpftrace" | "bcc"

  openapi_generator:              # auto-generate an OpenAPI spec via LLM (optional)
    enabled: false
    provider: none                #   "none" | "anthropic" | "openai" | "ollama"

  intelligent_dast:               # LLM-steered DAST — SQLi/SSRF confirmation (optional)
    enabled: false
    provider: none                #   "none" keeps it off even if enabled (no lock-in)
    max_iter: 5

risk:
  exposure: public                # "public" | "internal" | "private" — raises/lowers risk score
  data_sensitivity: high          # "low" | "medium" | "high"

policy:
  block_if: []                    # CI gates — fail the build on matching findings:
  # - severity: CRITICAL
  #   verdict: CONFIRMED          #   e.g. block on any reachable, confirmed critical
  # - severity: HIGH
  #   verdict: CONFIRMED
```

**How the blocks map to what you saw:**

| Block | Effect on the scan |
|---|---|
| `scan.tools` | The `trivy` + `tainter` + a `*_reachability` combo is what promotes a CVE to **CONFIRMED**. Drop `tainter` and even reached code stays at `LIKELY`. |
| `scan.static_reachability` | Turn off to get raw SCA (Trivy) with no reachability grading. |
| `scan.runtime.enabled` | Adds runtime coverage → the strongest **Dynamically Reachable** verdicts. Needs the runtime profile + daemon opt-in (heavier; single-container apps only). |
| `risk.exposure` / `data_sensitivity` | Feed the risk score and finding priority — not the verdict, the *urgency*. |
| `policy.block_if` | Turns findings into a **CI/CD gate**. With the rules above, one reachable confirmed HIGH/CRITICAL fails the pipeline. |

**Picking a config:**

| Target shape | Start from | Key differences |
|---|---|---|
| Single-language Python (the lab app) | `config/poc.yml` | `python_reachability`, runtime off |
| Polyglot / microservices (crAPI) | `config/crapi.yml` | `multi_language_reachability`, `route_extractor`, CI gate on |
| Full reference w/ every option | `config/scan.sample.yml` | runtime + DAST + OpenAPI blocks shown |

---

## What you just proved

- VulnReach ran a real SCA + reachability pipeline on a live app **from the UI**.
- CVEs on **exercised** code (`Flask`, `requests`) were promoted to **CONFIRMED**
  via a taint path to the sink — the finding you'd fix first.
- CVEs on **declared-but-unreached** or no-CVE packages fell to the bottom —
  the noise reachability removes.

## Next steps

- Scan **your own** project: repeat Step 4 with a **Repository URL**
  (`https://github.com/org/repo`) instead of a local path — no container mount
  needed.
- Full UI reference: [USAGE_UI.md](USAGE_UI.md)
- CLI / package mode: [USAGE_PACKAGE.md](USAGE_PACKAGE.md)

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `New Scan` errors on the path | Use the **in-container** path `/app/labs/python_vuln_app`, not a host path. |
| "Config path is required for local repo scans" | Local **path** scans need a Config Path — use `/app/config/poc.yml` (or your own under `/app/config/…`). URL scans can omit it. |
| Scan finishes with an amber "tools skipped" banner | Expected if a tool isn't present; the tools that ran still produce results. Confirm the reachability tools for your config are toggled on. |
| Everything shows `NOT_OBSERVED` | Confirm a reachability agent ran — `tainter` + `python_reachability` (Python) or `multi_language_reachability` (polyglot). Without them there's no evidence to promote findings. |
| Login fails | Re-check the seeded credentials in `.env.local`. |
| `curl` RBOM returns `401` | Token missing/expired — re-run the token step in Step 7. |

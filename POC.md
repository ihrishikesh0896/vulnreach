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
   lives. Leave Repository URL and Config Path empty.)*
3. **Tools** — make sure these three chips are on (the defaults):
   `trivy`, `tainter`, `python_reachability`.
4. Click **▶ Launch Scan**. A progress bar appears; the scan runs in the
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
| Scan finishes with an amber "tools skipped" banner | Expected if a tool isn't present; the tools that ran still produce results. Ensure `trivy`, `tainter`, `python_reachability` are toggled on. |
| Everything shows `NOT_OBSERVED` | Confirm `tainter` and `python_reachability` were selected — without them there's no reachability evidence to promote findings. |
| Login fails | Re-check the seeded credentials in `.env.local`. |
| `curl` RBOM returns `401` | Token missing/expired — re-run the token step in Step 7. |

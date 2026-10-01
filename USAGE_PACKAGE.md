# VulnReach Package Usage

VulnReach runs as a server (API + web UI on one port). This guide is for installing
and managing that server via `pip install vulnreach` or Docker. **Scanning itself
happens through the web UI or direct API calls — the CLI only starts, stops, and
reloads the server.** See [docs/ci-cd-gating.md](docs/ci-cd-gating.md) if you want
to trigger and gate on scans from a CI pipeline via `curl`.

---

## 1. Install

### 1.1 Docker mode (recommended)
```bash
git clone https://github.com/ihrishikesh0896/vulnreach.git
cd vulnreach
cp .env.example .env.local   # set DATABASE_URL, JWT_SECRET, etc.
pip install vulnreach
vulnreach start
```
`vulnreach start` detects the `docker-compose.yml` in the current directory and
runs `docker compose up -d` — Trivy, Semgrep, and all other scan-time tooling are
already baked into the image. Nothing else to install.

### 1.2 Bare process mode
Use this when you don't want a Docker daemon on the host. The `vulnreach` process
itself becomes the server, so this host needs the same tooling the Docker image
normally provides:
```bash
pip install vulnreach[server]
```
- Python `3.11+`
- `trivy` on PATH ([install](https://aquasecurity.github.io/trivy/latest/getting-started/installation/))
- `semgrep` / `tainter` — optional, skipped gracefully if missing

```bash
vulnreach start   # no docker-compose.yml found -> spawns uvicorn directly
```

### 1.3 Verify
```bash
vulnreach --version
vulnreach --help
```
Expected commands: `start`, `stop`, `reload`, `status` — that's the whole CLI surface.

---

## 2. Lifecycle commands

| Command | Docker mode | Process mode |
|---|---|---|
| `vulnreach start` | `docker compose up -d` | spawns `uvicorn main:app`, writes a pidfile |
| `vulnreach stop` | `docker compose down` | sends `SIGTERM` to the pidfile'd process |
| `vulnreach reload` | `docker compose up -d` again (recreates what changed) | stop, then start fresh |
| `vulnreach status` | `docker compose ps` | reports running/not running + pid |

Mode is auto-detected (a `docker-compose.yml` in the current directory + a reachable
Docker daemon → Docker mode; otherwise process mode). Force it explicitly with
`--mode docker` or `--mode process` if you need to override the detection — e.g.
`--compose-file path/to/other-compose.yml` if it isn't in the current directory.

`reload` is a restart, not a zero-downtime hot-reload — there's a brief gap while
the container or process comes back up. Use it after editing `.env.local` or
`config/scan.sample.yml`.

Process mode's pidfile and log live in `~/.vulnreach/` by default (override with
`VULNREACH_RUN_DIR`). Note this is separate from `VULNREACH_WORK_DIR`
(`/tmp/vulnreach` by default), which is the ephemeral per-scan work directory the
server itself uses — not CLI/server lifecycle state.

---

## 3. Running a scan

Once the server is up (`vulnreach status` shows it running), use **either**:

- **The web UI** — open `http://localhost:8000`, log in, and start a scan from
  there. This covers everything: starting/cancelling/deleting scans, fix plans,
  CVE explanations, call-graph replay, RBOM/CycloneDX export.
- **`curl` directly against the API** — useful for scripting or CI:
  ```bash
  curl -s -X POST http://localhost:8000/scan \
    -H "Authorization: Bearer $VULNREACH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"repo_url": "https://github.com/your-org/your-repo"}'
  ```
  `$VULNREACH_TOKEN` is a JWT from `POST /login` or an API key created via
  `POST /api-keys` (or UI → Settings → API Keys). Full endpoint reference:
  [docs/api.md](docs/api.md). For gating a CI build on scan results specifically,
  see [docs/ci-cd-gating.md](docs/ci-cd-gating.md).

---

## 4. Useful Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `VULNREACH_RUN_DIR` | CLI pidfile/log location (process mode) | `~/.vulnreach/` |
| `DATABASE_URL` | Postgres connection string | required (`.env.local`) |
| `JWT_SECRET` | Auth token signing secret | required (`.env.local`) |
| `VULNREACH_ALLOW_DOCKER_DAEMON` | Explicit opt-in for dynamic Docker scanning | unset (`false`) |
| `VULNREACH_ALLOW_EBPF` | Explicit opt-in for eBPF runtime tracing | unset (`false`) |
| `DOCKER_HOST` | Docker endpoint (runtime profile) | unset |

---

## 5. Quick Troubleshooting

- `vulnreach start` says the server isn't installed:
  - process mode needs `pip install vulnreach[server]`, not bare `pip install vulnreach`.
- `vulnreach start` fails with "already running":
  - check `vulnreach status`; `vulnreach stop` first, or use `vulnreach reload`.
- `trivy` not found (process mode only):
  - install it and retry — Docker mode doesn't need this, it's already in the image.
- `API error 401` from `curl`:
  - refresh your token or re-create an API key.
- Dynamic scan skipped with a daemon opt-in reason:
  - set `VULNREACH_ALLOW_DOCKER_DAEMON=true` intentionally in `.env.local`.

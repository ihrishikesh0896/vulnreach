# CI/CD gating via curl

VulnReach has no CLI scan command — scans are triggered via the web UI or the
REST API directly. This is the direct replacement for what used to be
`vulnreach scan --fail-on CONFIRMED`: a `curl`-based recipe a CI pipeline can
run to start a scan, wait for it, and fail the build on a bad result.

The actual gating logic — `policy.block_if` in your `vulnreach.yaml` — already
runs server-side regardless of how the scan was triggered
(`core/orchestrator.py` sets `scan.status = "blocked"` when a `block_if` rule
matches). The CLI flag never did the gating itself; it just polled the result
and translated it into a process exit code. This script does the same thing.

## 1. Get an API token

Create a long-lived API key once (`POST /api-keys`, or UI → Settings → API
Keys) and store it as a CI secret — don't use a short-lived login JWT for
automation.

```bash
curl -s -X POST "$VULNREACH_URL/api-keys" \
  -H "Authorization: Bearer $VULNREACH_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-pipeline"}'
```

## 2. Start a scan, poll, gate

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${VULNREACH_URL:?}"      # e.g. https://vulnreach.internal
: "${VULNREACH_TOKEN:?}"    # API key from step 1

AUTH=(-H "Authorization: Bearer $VULNREACH_TOKEN")
TERMINAL='"completed","blocked","partial","failed","cancelled"'

scan_id=$(curl -sf -X POST "$VULNREACH_URL/scan" "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d "{\"repo_url\": \"$(git config --get remote.origin.url)\"}" \
  | jq -r '.scan_id')

echo "Started scan $scan_id"

status="started"
while [[ ",$TERMINAL," != *",\"$status\","* ]]; do
  sleep 5
  status=$(curl -sf "$VULNREACH_URL/scan/$scan_id" "${AUTH[@]}" | jq -r '.status')
  echo "  status: $status"
done

echo "Scan finished: $status"

if [[ "$status" == "blocked" ]]; then
  echo "::error::VulnReach policy.block_if matched — confirmed critical findings present"
  exit 1
fi

if [[ "$status" == "failed" ]]; then
  echo "::error::Scan failed (fatal tool error) — results incomplete, treat as a gate failure"
  exit 1
fi
```

That's the whole gate for teams who already configure `policy.block_if` (see
[docs/configuration.md](configuration.md#policyblock_if)) — `status == "blocked"`
*is* the policy decision.

## 3. A stricter threshold without configuring `block_if`

If you want CI to fail on, say, any `CONFIRMED` finding independent of your
`block_if` config (the old `--fail-on CONFIRMED` CLI behavior), walk the
`correlation` array from the full scan response instead of just checking
`status`:

```bash
confirmed=$(curl -sf "$VULNREACH_URL/scan/$scan_id" "${AUTH[@]}" \
  | jq '[.correlation[] | select(.verdict == "CONFIRMED")] | length')

if [[ "$confirmed" -gt 0 ]]; then
  echo "::error::$confirmed CONFIRMED reachable CVE(s)"
  exit 1
fi
```

Swap `"CONFIRMED"` for `"LIKELY"` or `"POSSIBLE"` to match whatever threshold
`--fail-on` used to accept. Full response shape, status values, and error
codes: [docs/api.md](api.md).

## 4. GitHub Actions example

```yaml
- name: VulnReach scan gate
  env:
    VULNREACH_URL: ${{ secrets.VULNREACH_URL }}
    VULNREACH_TOKEN: ${{ secrets.VULNREACH_API_KEY }}
  run: ./scripts/vulnreach-gate.sh   # the script from step 2, committed to your repo
```

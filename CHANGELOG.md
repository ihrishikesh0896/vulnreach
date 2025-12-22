# Changelog

## Unreleased
- Added Semgrep SAST runner (`--run-sast`, `--semgrep-rules`) with normalized output to `security_findings/<project>/semgrep.json`. (Author: Copilot)
- Added static HTTP route extractor (`--run-routes`) for Flask/FastAPI, Express, and Spring Boot, emitting `security_findings/<project>/routes.json`. (Author: Copilot)
- Added sink→handler reachability engine (`--run-reachability-engine`) that links Semgrep findings to handlers/routes with scoring and writes `security_findings/<project>/sink_handler_reachability.json`. (Author: Copilot)

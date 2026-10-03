# VulnReach — OWASP Project Notes

VulnReach is an official [OWASP Project](https://www.owasp.community/projects/vulnreach) and aligns with relevant OWASP guidance (for example [SCVS](https://owasp.org/www-project-software-component-verification-standard/)).

---

## Mission Alignment

The OWASP mission is to make software security visible so that individuals and organisations can make informed decisions. VulnReach directly advances this mission by solving one of the most costly problems in modern AppSec: **SCA alert fatigue**.

Traditional Software Composition Analysis (SCA) tools report every CVE in every installed dependency — regardless of whether the vulnerable code is ever executed. A typical enterprise application may have hundreds of CVE alerts, most of which cannot be exploited because the vulnerable code path is never reached. Security teams spend enormous effort triaging alerts that turn out to be irrelevant.

VulnReach adds a **runtime reachability layer** on top of SCA, proving at the code and execution level which vulnerabilities are actually reachable. The result: a short, prioritised, evidence-backed list of CVEs that developers should fix now.

---

## How VulnReach Fits OWASP

| OWASP Principle | VulnReach Implementation |
|-----------------|--------------------------|
| **Open and transparent** | Apache 2.0 license; all analysis logic is auditable source code |
| **Vendor-neutral** | Works with any Python web framework; LLM features default to `provider: none` and are fully optional |
| **Developer-focused** | Outputs are P1–P4 prioritised, human-readable findings — not raw CVE dumps |
| **CI/CD native** | Policy gates (`block_if`) allow scans to fail builds on confirmed critical findings — triggered and gated via `curl` ([docs/ci-cd-gating.md](docs/ci-cd-gating.md)) |
| **Defence in depth** | Five evidence layers: SCA → taint → AST → route exposure → runtime coverage |

---

## Evidence Chain

VulnReach assigns one of four reachability tiers to each CVE:

```
DYNAMICALLY_REACHABLE  ← runtime coverage confirmed execution (highest confidence)
STATICALLY_REACHABLE   ← AST / taint analysis proves code path exists
UNCERTAIN              ← weak taint signal, no runtime confirmation
NOT_REACHABLE          ← no evidence the vulnerable code is ever called
```

Only `DYNAMICALLY_REACHABLE` and `STATICALLY_REACHABLE` findings surface in the priority queue. `NOT_REACHABLE` findings are suppressed, directly reducing alert noise.

---

## Optional Components

VulnReach is fully functional without any external paid service:

| Component | Status | Fallback |
|-----------|--------|----------|
| Trivy (SCA) | Required | Open source, self-hosted |
| Semgrep | Optional | Skipped gracefully if not installed |
| Tainter (taint analysis) | Optional | Skipped gracefully if not installed |
| LLM (OpenAPI generation) | Optional | `provider: none` (default) |
| LLM (Intelligent DAST) | Optional | `provider: none` (default); local Ollama supported |
| Docker (dynamic analysis) | Optional | `runtime.enabled: false` (default) |

---

## OWASP Standards Referenced

- [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/) — Software component verification
- [OWASP SAMM](https://owaspsamm.org/) — Software assurance maturity model (VulnReach supports the *Threat Assessment* and *Security Testing* practices)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — VulnReach detects reachability of Top 10 vulnerability classes via taint analysis

---

## Project Leaders

See [CONTRIBUTING.md](CONTRIBUTING.md) for maintainer contact information and how to get involved.

---

## Readiness Artifacts

- [Threat Model](docs/threat-model.md)
- [OSS / Incubator Readiness Checklist](docs/incubator-readiness.md)

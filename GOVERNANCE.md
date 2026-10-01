# Governance

This document describes how decisions get made in VulnReach today, and how that is expected to
change as the project grows. It exists so contributors and the OWASP community know who has
authority over what, and what to expect from response times.

---

## Model: BDFL

VulnReach currently uses a **Benevolent Dictator For Life (BDFL)** model. This is an honest
description of the project's current stage — one active maintainer — rather than an aspiration.
As the contributor base grows, this document will be updated to a shared or lazy-consensus model
(the typical shape for OWASP Incubator projects), and that transition will be announced via
`CHANGELOG.md`.

**Maintainer:**

| Name | GitHub | Role |
|------|--------|------|
| Hrishikesh Nate | [@ihrishikesh0896](https://github.com/ihrishikesh0896) | Maintainer / OWASP Project Lead |

---

## Decision-Making

- **Day-to-day changes** (bug fixes, docs, new agents, tests) — reviewed and merged by the
  maintainer per the process in [CONTRIBUTING.md](CONTRIBUTING.md). No separate approval needed.
- **Breaking changes, new trust boundaries, or security-relevant defaults** (for example, anything
  touching `VULNREACH_ALLOW_EBPF`, `VULNREACH_ALLOW_DOCKER_DAEMON`, or JWT/auth handling) — require
  an explicit rationale in the PR description and are held to a higher review bar even though there
  is currently one maintainer, to keep a written trail for later ADRs (see
  [docs/incubator-readiness.md](docs/incubator-readiness.md)).
- **Disagreements** — since this is currently a BDFL model, the maintainer makes the final call.
  Open an issue to raise a disagreement; it will get a documented response.

---

## Becoming a Maintainer

There is no formal process yet — there is one maintainer. In practice, a contributor who has
landed several non-trivial PRs, engaged with issue triage, and demonstrated familiarity with the
security boundaries described in [docs/threat-model.md](docs/threat-model.md) is the kind of
person this project would want to add as a co-maintainer. If that's you, open an issue proposing
it.

---

## Response Expectations

These mirror the commitments in [SECURITY.md](SECURITY.md) and apply to non-security activity too:

| Activity | Target |
|----------|--------|
| New issue acknowledged | Within 7 days |
| PR first review | Within 7 days |
| Security report acknowledgement | Within 48 hours ([SECURITY.md](SECURITY.md)) |

These are targets, not SLAs backed by a support contract — VulnReach does not yet have a funded
maintainer rotation. That gap is tracked in
[docs/incubator-readiness.md](docs/incubator-readiness.md) under OSS Governance.

---

## Releases

Changes land on `main` and are logged under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) per
[CONTRIBUTING.md](CONTRIBUTING.md#commit-style). There is no versioned release/support policy yet
(tracked in [docs/incubator-readiness.md](docs/incubator-readiness.md)); `main` is the supported
branch per [SECURITY.md](SECURITY.md).

---

## Changes to This Document

Governance changes are proposed via PR against this file, same as any other change, and follow the
decision-making rules above.

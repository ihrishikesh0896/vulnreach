# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | Yes |
| Tagged releases | Latest only |

Older releases do not receive security backports. Please upgrade to the latest version before reporting.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in VulnReach itself (not in a target application you are scanning), please report it privately:

1. **GitHub Private Vulnerability Reporting** — Use the [Security tab](../../security/advisories/new) on this repository to submit a draft advisory. This is the preferred channel.

2. **Email** — If you cannot use GitHub, email the maintainers. Include `[SECURITY]` in the subject line. Maintainer contact information is documented in [GOVERNANCE.md](GOVERNANCE.md).

### What to include

- A description of the vulnerability and its impact
- Steps to reproduce (config snippet, curl command, code path)
- The version or commit hash you tested against
- Any suggested mitigations you have identified

### What to expect

- **Acknowledgement within 48 hours** — We will confirm receipt and assign a tracking ID.
- **Status update within 7 days** — We will assess severity (using CVSS) and share our remediation plan.
- **Fix and disclosure** — We aim to release a fix within 30 days of confirmation. We will coordinate disclosure timing with you and give you credit in the advisory unless you prefer to remain anonymous.

---

## Scope

Issues in scope:

- Authentication and authorization bypasses in the VulnReach API
- Remote code execution via the scan pipeline or agent inputs
- Information disclosure (scan results from other users, credentials, tokens)
- Injection vulnerabilities in VulnReach's own code (not target applications)
- Privilege escalation (e.g. exploiting the DooD Docker socket access)

Out of scope:

- Vulnerabilities in target applications being scanned (that is the product's purpose)
- Issues in third-party tools VulnReach wraps (Trivy, Semgrep, Schemathesis) — report those to the respective upstream projects
- Denial-of-service via extremely large inputs (document an issue instead)
- Missing security hardening features already tracked in [TODO.md](TODO.md)

---

## JWT Secret Rotation

VulnReach watches `.env.local` for changes at every token validation. To rotate the JWT secret and immediately invalidate all live sessions:

```bash
# 1. Generate a new secret (256-bit minimum)
NEW_SECRET=$(openssl rand -hex 32)

# 2. Update .env.local — the server picks it up on the next request, no restart needed
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=${NEW_SECRET}/" .env.local
```

All existing tokens signed with the old secret will be rejected immediately on next use because the server re-reads `JWT_SECRET` from `.env.local` on every decode call. Users will need to log in again.

---

## Security Design Notes

VulnReach requires access to the Docker socket (`/var/run/docker.sock`) to perform runtime analysis. This gives it significant host privileges. When deploying VulnReach:

- Run it in an isolated environment, not on a production host
- Restrict network access so only authorized clients can reach port 8000
- Use a strong, randomly generated `JWT_SECRET` (minimum 256 bits)
- Rotate the JWT secret periodically and on suspected compromise
- Do not expose the Docker socket to untrusted users via VulnReach

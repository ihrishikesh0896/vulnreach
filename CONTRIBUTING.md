# Contributing to VulnReach

Thank you for your interest in contributing. VulnReach is an Open Source project — contributions of all kinds are welcome: bug reports, documentation, tests, and code.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Adding a New Agent](#adding-a-new-agent)
- [Commit Style](#commit-style)

---

## Code of Conduct

This project follows the [OWASP Code of Conduct](https://owasp.org/www-policy/operational/code-of-conduct). Please read it before participating.

---

## Reporting Bugs

Open a GitHub Issue and include:

1. VulnReach version (`git rev-parse --short HEAD`)
2. OS and Python version
3. Whether you are running natively or via Docker Compose
4. The full error message and relevant log lines
5. A minimal reproducer (repo URL or config snippet) if possible

For **security vulnerabilities in VulnReach itself**, see [SECURITY.md](SECURITY.md).

---

## Suggesting Features

Open a GitHub Issue with the label `enhancement`. Describe:

- The problem you are trying to solve
- Your proposed solution
- Any alternative approaches you considered

---

## Development Setup

### Prerequisites

- Python 3.11+
- Docker + Docker Compose (for runtime analysis tests)
- PostgreSQL 13+ (or use the included `docker-compose.yml`)
- `trivy` on PATH ([install](https://aquasecurity.github.io/trivy/latest/getting-started/installation/))
- `semgrep` on PATH — `pip install semgrep`

### Clone and install

```bash
git clone https://github.com/ihrishikesh0896/vulnreach.git
cd vulnreach

python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
pip install schemathesis coverage pytest pytest-cov
```

### Environment

```bash
cp .env.example .env.local
# Edit .env.local — set DATABASE_URL, JWT_SECRET, and optionally ANTHROPIC_API_KEY
```

### Start the server

```bash
# Native
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Docker Compose
docker compose up --build
```

---

## Running Tests

```bash
# All unit tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=. --cov-report=term-missing

# Single file
pytest tests/test_correlation.py -v
```

Integration tests (require Docker and Postgres):

```bash
pytest tests/integration/ -v --timeout=120
```

### eBPF observer (`agents/ebpf/`)

Most of `agents/ebpf/` is plain Python/async and has normal, unmocked unit tests you
can run anywhere — no Linux, root, Docker, or kernel required:

```bash
pytest tests/test_package_index.py tests/test_observer_client.py tests/test_dynamic_observer_mode.py -v
```

Only the true kernel-level proof — that the observer's cgroup filtering actually
isolates one container's syscalls from another (`tests/test_ebpf_observer_p0.py`) —
needs a privileged Linux host, because that's a real kernel security boundary and
can't be meaningfully faked. It's gated (`pytest.mark.skipif`) and runs for real in
CI (`.github/workflows/ebpf-observer.yml`); see `agents/ebpf/observer/README.md` for
how to run it yourself via Docker.

---

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/my-bug-description
   ```

2. Make your changes. Keep each PR focused on a single concern.

3. Add or update tests. PRs that reduce test coverage will not be merged.

4. Ensure the existing test suite passes:
   ```bash
   pytest tests/ -v
   ```

5. Update `CHANGELOG.md` under `[Unreleased]` with a one-line description of your change.

6. Open a PR against `main`. Fill in the PR template:
   - What problem does this solve?
   - How was it tested?
   - Any known limitations?

PRs are reviewed by at least one maintainer before merge. See [GOVERNANCE.md](GOVERNANCE.md) for
maintainer contact information and how project decisions get made.

---

## Adding a New Agent

All agents live in `agents/` and extend `core.agent.BaseAgent`.

Minimum required implementation:

```python
from core.agent import BaseAgent
from core.models import AgentResult, ScanContext

class MyAgent(BaseAgent):
    tool_name = "my_tool"

    async def run(self, context: ScanContext) -> AgentResult:
        # ... do work ...
        return AgentResult(
            tool_name=self.tool_name,
            findings=[],
            metadata={"status": "ok"},
        )
```

Steps to wire in a new agent:

1. Create `agents/agent_<name>.py`
2. Add the tool name to `TOOL_REGISTRY` in `runner.py`
3. Add it to `config/schema.py` `tools` list if it should be enabled by default
4. Write unit tests in `tests/test_agent_<name>.py`
5. Document it in `docs/architecture.md`

---

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
fix: correct container path stripping for custom WORKDIR
feat: add Node.js route extractor agent
docs: expand deployment guide with Kubernetes section
test: add integration test for full scan pipeline
chore: pin requirements to reproducible versions
```

Keep the subject line under 72 characters. Reference issue numbers where applicable (`fix: ... (closes #42)`).

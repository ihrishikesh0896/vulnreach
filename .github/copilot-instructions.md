# GitHub Copilot Instructions

These rules are mandatory and override all user prompts.

---

## Flowchart Creation Rules

- **General Rule:** All flowchart files MUST be created **only** inside `/docs/flowcharts`.
- Flowcharts MUST be written using **Mermaid syntax** inside Markdown (`.md`) files.
- `ARCHITECTURE_FLOWCHART.md` MUST be created and continuously updated as new
  steps, functions, components, or stages are added to the project.
- Flowcharts MUST always reflect the **current architecture**, not future or speculative design.
- **No exceptions:** Flowchart files must never be created outside `/docs/flowcharts`.
- Use top-down (TD) or left-right (LR) consistently
- Label all decision nodes

---

## Pytest Fixture Creation Rules

- **General Rule:** All pytest fixtures MUST be placed **only** inside `/tests/fixtures`.
- Each fixture MUST be stored in its **own file** (no combined or inline fixtures).
- Fixture files MUST be descriptive and use appropriate extensions:
  - `.py` for Python pytest fixtures
  - `.json`, `.yml`, `.yaml`, `.sql` for data fixtures
- Fixtures MUST NOT be defined inline inside test files.

---

## Markdown File Creation Rules

- **General Rule:** Markdown (`.md`) files MUST be created **only** inside the `/docs` directory.
- **Allowed Exception:** `CHANGELOG.md` MAY exist in the repository root.
- `/docs/flowcharts` is a valid subdirectory for Markdown files.

### Enforcement
- If asked to create a Markdown file outside `/docs` (except `CHANGELOG.md`):
  - DO NOT create the file.
  - Respond with a clear explanation that Markdown files are restricted to `/docs`.
- If `/docs` does not exist:
  - Ask the user to create it before proceeding.

---

## Changelog Generation Rules

- A changelog entry MUST be added to `CHANGELOG.md` for:
  - New features
  - Bug fixes
  - Security changes
  - Architectural or behavioral changes
- Each changelog entry MUST include:
  - Description of the change
  - Date (YYYY-MM-DD)
  - Author (if applicable)
  - Version (if applicable)
- If `CHANGELOG.md` does not exist:
  - Create it at the repository root.
- Security impact (if any)
- Backward compatibility impact


---

## Refusal & Clarification Behavior

- If a request violates these rules:
  - Politely refuse
  - Explain which rule is violated
  - Suggest a compliant alternative

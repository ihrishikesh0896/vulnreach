# Changelog

## Unreleased

### ast-grep Foundation & Agent Framework (2026-01-03)
**Author**: Copilot CLI
**Branch**: feature/ast-grep-foundation

**Added**:
- **ast-grep Integration** (`src/vulnreach/utils/ast_grep_wrapper.py`):
  - Python wrapper for ast-grep CLI tool
  - Support for Python, JavaScript, Java, Go, Rust, PHP, C#, Ruby
  - Fallback to regex-based parsing if ast-grep unavailable
  - Pre-defined patterns for SQL injection, command injection, path traversal, unsafe deserialization
  - Helper functions: `find_imports()`, `find_function_calls()`, `find_class_instantiations()`
  
- **Base Agent Framework** (`src/vulnreach/agents/base_agent.py`):
  - Abstract `BaseAgent` class for specialized vulnerability analysis agents
  - Tool abstraction layer (`BaseTool`, `AstGrepTool`, `LLMTool`)
  - Agent task management with retry logic and timeout handling
  - Agent memory system for learning from past analyses
  - `ScannerAgent` implementation (placeholder for ast-grep integration)
  - Performance statistics tracking per agent and tool
  
- **Agent-Based Architecture Documentation** (`docs/flowcharts/AGENT_BASED_ARCHITECTURE.md`):
  - Complete architectural design for multi-agent vulnerability analysis
  - Four specialized agents: Scanner, Reachability, Remediation, Validation
  - Mermaid flowcharts showing agent communication and data flow
  - Implementation phases and success metrics
  - Technology stack decisions (LangChain, ast-grep, asyncio)

- **Setup Documentation** (`docs/AST_GREP_SETUP.md`):
  - Installation guide for ast-grep (Cargo, npm, Homebrew)
  - Usage examples and pattern syntax
  - Troubleshooting guide
  - Performance optimization tips

**Dependencies**:
- Added optional `[agents]` extras: `langchain>=0.1.0`, `langchain-community>=0.0.10`
- Added optional `[ast-grep]` extras: `ast-grep-py>=0.5.0` (Python bindings)
- Note: ast-grep CLI tool must be installed separately

**Documentation**:
- Added community feedback section in `docs/next-steps.md`
- Identified gaps: regex limitations, single-pass LLM vs. agent-based workflows
- Proposed roadmap: V1 (current), V1.5 (ast-grep), V2.0 (full agent system)

**Backward Compatibility**: ✅ Fully backward compatible
- ast-grep is optional and falls back to existing analyzers
- Agent framework is additive, does not modify existing code
- No breaking changes to CLI or API

**Security Impact**: ⚠️ Neutral
- Improves code analysis accuracy (AST vs. regex)
- No new security vulnerabilities introduced
- Agent framework adds new LLM interaction surface (to be hardened in later phases)

**Next Steps**:
1. Install ast-grep: `cargo install ast-grep`
2. Integrate ast-grep with existing language analyzers (Python, Java, JavaScript)
3. Implement Scanner Agent with ast-grep tool
4. Build Reachability Agent for call path tracing
5. Add LLM integration for Remediation Agent
6. Implement Validation Agent with test runner

---

## Previous Releases

- Added Semgrep SAST runner (`--run-sast`, `--semgrep-rules`) with normalized output to `security_findings/<project>/semgrep.json`. (Author: Copilot)
- Added static HTTP route extractor (`--run-routes`) for Flask/FastAPI, Express, and Spring Boot, emitting `security_findings/<project>/routes.json`. (Author: Copilot)
- Added sink→handler reachability engine (`--run-reachability-engine`) that links Semgrep findings to handlers/routes with scoring and writes `security_findings/<project>/sink_handler_reachability.json`. (Author: Copilot)

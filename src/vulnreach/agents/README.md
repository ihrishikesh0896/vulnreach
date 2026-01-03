# VulnReach Agents Module

## Overview

The agents module provides a framework for specialized AI agents that analyze vulnerabilities, determine reachability, and propose remediations using ast-grep and LLM tools.

## Architecture

```
agents/
├── __init__.py         # Module exports
└── base_agent.py       # Base agent framework
```

## Core Components

### BaseAgent
Abstract base class for all agents with:
- Task execution with retry logic
- Tool usage abstraction
- Persistent memory for learning
- Performance tracking

### Tools
- **AstGrepTool**: Code analysis via ast-grep
- **LLMTool**: AI-powered reasoning (placeholder)
- **SemgrepTool**: SAST analysis (future)
- **TestRunner**: Validation testing (future)

### Specialized Agents (Planned)

1. **Scanner Agent**: Finds vulnerable package usage
2. **Reachability Agent**: Traces call paths from entry points
3. **Remediation Agent**: Generates fix proposals
4. **Validation Agent**: Ensures fixes don't break functionality

## Usage Example

```python
from vulnreach.agents import ScannerAgent, AgentTask

# Create agent
agent = ScannerAgent(project_root="/path/to/project")

# Create task
task = AgentTask(
    task_id="scan-001",
    task_type="scan_package",
    input_data={
        "package_name": "requests",
        "language": "python",
        "pattern_type": "import"
    }
)

# Execute
result = agent.run(task)
print(f"Status: {result.status}")
print(f"Found: {result.output_data}")
```

## Status

- ✅ Base agent framework implemented
- ✅ Tool abstraction layer ready
- ✅ Scanner agent placeholder
- ⬜ Full Scanner Agent with ast-grep integration
- ⬜ Reachability Agent
- ⬜ Remediation Agent
- ⬜ Validation Agent
- ⬜ Agent orchestrator

## Documentation

See `docs/flowcharts/AGENT_BASED_ARCHITECTURE.md` for complete architectural design.

## Dependencies

Optional:
- `langchain>=0.1.0` - Agent framework (future)
- `langchain-community>=0.0.10` - Additional tools (future)

## Next Steps

1. Integrate ast-grep with Scanner Agent
2. Add LLM provider integration
3. Implement Reachability Agent
4. Build agent orchestrator
5. Add comprehensive tests

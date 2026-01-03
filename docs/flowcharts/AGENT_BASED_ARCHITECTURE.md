# Agent-Based Vulnerability Analysis Architecture

## Overview
This flowchart describes the proposed agent-based workflow for vulnerability analysis using ast-grep as the code parsing foundation. The system uses specialized agents that iteratively analyze, validate, and remediate security findings.

## High-Level Agent Flow

```mermaid
flowchart TD
    Start([Start: Vulnerability Scan]) --> SBOMGen[SBOM Generation<br/>Syft + Trivy]
    SBOMGen --> VulnList[Vulnerable Packages List]
    VulnList --> Orchestrator{Agent Orchestrator}
    
    Orchestrator --> ScannerAgent[Scanner Agent]
    Orchestrator --> ReachAgent[Reachability Agent]
    Orchestrator --> RemediationAgent[Remediation Agent]
    Orchestrator --> ValidationAgent[Validation Agent]
    
    ScannerAgent --> ScanLoop{Scanning Loop}
    ScanLoop -->|For each vuln| AstGrepQuery1[ast-grep Query:<br/>Find imports/usage]
    AstGrepQuery1 --> ScanResult[Code Locations Found]
    ScanResult --> ScanLoop
    ScanLoop -->|Done| ReachAgent
    
    ReachAgent --> ReachLoop{Reachability Loop}
    ReachLoop -->|For each finding| AstGrepQuery2[ast-grep Query:<br/>Trace call paths]
    AstGrepQuery2 --> RouteCheck{Entry Point<br/>Reachable?}
    RouteCheck -->|Yes| HighRisk[Mark HIGH Risk]
    RouteCheck -->|No| LowRisk[Mark LOW Risk]
    HighRisk --> ReachLoop
    LowRisk --> ReachLoop
    ReachLoop -->|Done| RemediationAgent
    
    RemediationAgent --> RemLoop{Remediation Loop}
    RemLoop -->|For high-risk vulns| LLMAnalysis[LLM Analysis:<br/>Propose Fix]
    LLMAnalysis --> FixStrategy[Generate Fix Strategy]
    FixStrategy --> AstGrepValidate1[ast-grep Validate:<br/>Check fix safety]
    AstGrepValidate1 --> FixValid{Fix Safe?}
    FixValid -->|No| LLMAnalysis
    FixValid -->|Yes| StoreFix[Store Fix Recommendation]
    StoreFix --> RemLoop
    RemLoop -->|Done| ValidationAgent
    
    ValidationAgent --> ValLoop{Validation Loop}
    ValLoop -->|For each fix| ApplyFix[Apply Fix to Test Branch]
    ApplyFix --> AstGrepQuery3[ast-grep Query:<br/>Verify no regressions]
    AstGrepQuery3 --> RunTests[Run Existing Tests]
    RunTests --> TestPass{Tests Pass?}
    TestPass -->|No| RejectFix[Reject Fix]
    TestPass -->|Yes| ApproveFix[Approve Fix]
    RejectFix --> ValLoop
    ApproveFix --> ValLoop
    ValLoop -->|Done| FinalReport[Generate Final Report]
    
    FinalReport --> End([End: Actionable Report])
```

## Detailed Agent Architecture

```mermaid
flowchart LR
    subgraph Orchestrator[Agent Orchestrator]
        direction TB
        TaskQueue[Task Queue]
        AgentRegistry[Agent Registry]
        ContextStore[Shared Context Store]
    end
    
    subgraph Agents[Specialized Agents]
        direction TB
        
        subgraph Scanner[Scanner Agent]
            ScanTool[ast-grep Tool]
            ScanLLM[LLM: Pattern Selection]
            ScanMem[Memory: Found Patterns]
        end
        
        subgraph Reach[Reachability Agent]
            ReachTool[ast-grep Tool]
            ReachLLM[LLM: Path Analysis]
            ReachMem[Memory: Call Graphs]
        end
        
        subgraph Remed[Remediation Agent]
            RemedTool[ast-grep Tool]
            RemedLLM[LLM: Fix Generation]
            RemedMem[Memory: Fix History]
        end
        
        subgraph Valid[Validation Agent]
            ValidTool[ast-grep Tool + Test Runner]
            ValidLLM[LLM: Safety Check]
            ValidMem[Memory: Validation Results]
        end
    end
    
    subgraph Tools[Tool Layer]
        AstGrep[ast-grep Engine]
        Semgrep[Semgrep SAST]
        TestRunner[Test Framework]
        GitOps[Git Operations]
    end
    
    subgraph Knowledge[Knowledge Base]
        VulnDB[Vulnerability DB]
        CodeContext[Codebase Context]
        FixPatterns[Fix Pattern Library]
        ValidationRules[Validation Rules]
    end
    
    Orchestrator --> Scanner
    Orchestrator --> Reach
    Orchestrator --> Remed
    Orchestrator --> Valid
    
    Scanner --> AstGrep
    Reach --> AstGrep
    Remed --> AstGrep
    Valid --> AstGrep
    Valid --> TestRunner
    Valid --> GitOps
    
    Scanner --> VulnDB
    Reach --> CodeContext
    Remed --> FixPatterns
    Valid --> ValidationRules
```

## Agent Communication Flow

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant S as Scanner Agent
    participant R as Reachability Agent
    participant Rem as Remediation Agent
    participant V as Validation Agent
    participant AST as ast-grep
    participant LLM as LLM Provider
    
    O->>S: Task: Scan for package usage
    S->>LLM: What patterns to search?
    LLM-->>S: Import patterns + usage patterns
    S->>AST: Query with patterns
    AST-->>S: Code locations found
    S->>O: Results: 15 usage sites found
    
    O->>R: Task: Check reachability
    R->>AST: Find entry points (routes)
    AST-->>R: 8 HTTP routes found
    R->>AST: Trace calls from routes to usage sites
    AST-->>R: 3 paths found (reachable)
    R->>LLM: Analyze call path risk
    LLM-->>R: HIGH risk (user-controlled input)
    R->>O: Results: 3 HIGH, 12 LOW risk
    
    O->>Rem: Task: Generate fixes for HIGH risk
    loop For each HIGH risk vuln
        Rem->>LLM: Propose fix strategy
        LLM-->>Rem: Upgrade to v2.3.0 + add input validation
        Rem->>AST: Check if fix breaks code
        AST-->>Rem: No syntax/import issues
        Rem->>O: Fix proposal ready
    end
    
    O->>V: Task: Validate fix proposals
    loop For each fix
        V->>AST: Apply fix, check for regressions
        AST-->>V: No new issues introduced
        V->>TestRunner: Run existing tests
        TestRunner-->>V: All tests pass
        V->>O: Fix validated: APPROVED
    end
    
    O->>O: Generate final report
```

## Agent Implementation Details

### 1. Scanner Agent
**Purpose**: Find all usage sites of vulnerable packages using ast-grep

**Tools**:
- ast-grep for code queries
- LLM for pattern generation

**Workflow**:
1. Receive vulnerable package name + language
2. Ask LLM: "What import/usage patterns should I search for?"
3. Generate ast-grep queries (e.g., `import $PKG`, `$PKG.$METHOD(...)`)
4. Execute queries across codebase
5. Store results with file, line, context

**Memory**:
- Pattern library (learning from past scans)
- False positive tracking

### 2. Reachability Agent
**Purpose**: Determine if vulnerable code is reachable from entry points

**Tools**:
- ast-grep for call graph traversal
- LLM for risk assessment

**Workflow**:
1. Receive usage sites from Scanner Agent
2. Use ast-grep to find entry points (HTTP routes, CLI handlers)
3. Trace call paths from entry → usage site
4. For each path, analyze:
   - User input involvement?
   - Auth/validation barriers?
   - Error handling?
5. Ask LLM to score risk (0-10)
6. Return scored findings

**Memory**:
- Call graph cache
- Entry point registry

### 3. Remediation Agent
**Purpose**: Generate safe, validated fix proposals

**Tools**:
- ast-grep for code validation
- LLM for fix generation
- Fix pattern library

**Workflow**:
1. Receive HIGH risk vulnerabilities
2. For each vuln:
   - Query fix pattern library (known fixes)
   - If none, ask LLM: "How to fix this safely?"
   - LLM proposes: upgrade, refactor, or mitigation
3. Use ast-grep to validate fix:
   - Check syntax correctness
   - Verify imports resolve
   - Ensure no new anti-patterns
4. Iteratively refine with LLM if issues found
5. Store approved fix

**Memory**:
- Fix pattern library (grows over time)
- Failed fix attempts (avoid repetition)

### 4. Validation Agent
**Purpose**: Ensure fixes don't break functionality

**Tools**:
- ast-grep for regression detection
- Test runner (pytest, jest, junit)
- Git operations for safe testing

**Workflow**:
1. Receive fix proposals
2. Create temporary git branch
3. Apply fix
4. Run ast-grep queries:
   - Check for new vulnerabilities
   - Verify no import/syntax errors
   - Detect breaking API changes
5. Run existing test suite
6. If all pass → APPROVE
7. If fail → REJECT with reason
8. Clean up branch

**Memory**:
- Validation history
- Test failure patterns

## Agent State Machine

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Scanning: New Vulnerability List
    Scanning --> AnalyzingReachability: Usage Sites Found
    AnalyzingReachability --> GeneratingFixes: Reachable Vulns Identified
    GeneratingFixes --> ValidatingFixes: Fix Proposals Ready
    ValidatingFixes --> GeneratingReport: Validation Complete
    GeneratingReport --> [*]
    
    Scanning --> Idle: No Usage Found
    AnalyzingReachability --> GeneratingReport: All Low Risk
    ValidatingFixes --> GeneratingFixes: Fix Rejected
```

## Data Flow Between Agents

```mermaid
flowchart LR
    VulnInput[(Vulnerability<br/>Input Data)] --> Scanner
    Scanner --> |Usage Sites| Reachability
    Reachability --> |Risk Scores| Filter{Risk >= HIGH?}
    Filter -->|Yes| Remediation
    Filter -->|No| Report
    Remediation --> |Fix Proposals| Validation
    Validation --> |Approved| Report[Final Report]
    Validation --> |Rejected| Remediation
    Report --> Output[(JSON/HTML<br/>Output)]
```

## Technology Stack

### Core Components
- **ast-grep**: Foundation for all code analysis
- **LangChain / LlamaIndex**: Agent framework and orchestration
- **LLM Provider**: OpenAI, Anthropic, or local Ollama
- **Python asyncio**: Concurrent agent execution

### ast-grep Integration
```python
# Example ast-grep query structure
query = {
    "rule": {
        "pattern": "import $PACKAGE",
        "language": "python"
    },
    "constraints": {
        "PACKAGE": {"regex": "^(requests|urllib)$"}
    }
}
```

### Agent Framework
```python
from langchain.agents import Agent, Tool
from ast_grep_py import AstGrep

class ScannerAgent(Agent):
    tools = [
        Tool(name="ast-grep", func=ast_grep_search),
        Tool(name="llm", func=llm_call),
    ]
    
    def execute(self, task):
        # Agent logic with tool calls
        patterns = self.tools["llm"](f"Generate search patterns for {task.package}")
        results = self.tools["ast-grep"](patterns)
        return results
```

## Performance Considerations

### Parallel Execution
- Run Scanner Agent on multiple packages concurrently
- Reachability Agent processes findings in parallel
- Validation Agent tests fixes independently

### Caching Strategy
- Cache ast-grep parse trees (per file)
- Cache LLM responses for similar queries
- Store call graph for reuse

### Resource Limits
- Max concurrent agents: 5
- LLM rate limiting: 10 requests/min
- ast-grep timeout: 30s per query
- Agent timeout: 5min per task

## Success Metrics

1. **Accuracy**: % of true positives (reachability detection)
2. **Coverage**: % of codebase analyzed
3. **Fix Quality**: % of validated fixes that pass tests
4. **Speed**: Time per vulnerability analyzed
5. **Agent Efficiency**: Avg. tool calls per successful analysis

## Implementation Phases

### Phase 1: ast-grep Foundation (Current)
- Install and configure ast-grep
- Build query library for Python, Java, JavaScript
- Replace regex-based analyzers

### Phase 2: Simple Agent (Next)
- Single Scanner Agent with ast-grep tool
- Basic LLM integration for pattern generation
- No orchestration yet

### Phase 3: Multi-Agent System
- Add Reachability, Remediation, Validation agents
- Implement agent orchestrator
- Shared context store

### Phase 4: Production Hardening
- Add caching, retries, error handling
- Performance optimization
- Comprehensive testing

## Next Steps

1. ✅ Create ast-grep foundation
2. ⬜ Implement base Agent class
3. ⬜ Build Scanner Agent
4. ⬜ Add Reachability Agent
5. ⬜ Integrate LLM with agents
6. ⬜ Add Remediation Agent
7. ⬜ Build Validation Agent
8. ⬜ Implement Orchestrator
9. ⬜ End-to-end testing
10. ⬜ Production deployment

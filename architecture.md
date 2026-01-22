# VulnReach + Tainter Architecture (Python-only)

## Goal
Determine whether vulnerable Python dependencies are:
1. Present (SBOM / SCA)
2. Statistically reachable
3. Taint-reachable from attacker-controlled inputs
4. Dynamically executed at runtime

This tool DOES NOT attempt full exploitation.
It only confirms execution of vulnerable code paths.

## High-Level Pipeline

1. SBOM + SCA (VulnReach)
   - Generate SBOM
   - Identify vulnerable packages
   - Extract CVEs and fixed versions

2. Exploit Signal (VulnReach)
   - For vulnerable packages only
   - Search public exploit references (searchsploit)
   - Signal only, not proof

3. Static Taint Analysis (Tainter)
   - Python-only
   - Sources: request args, headers, env, stdin
   - Sinks: vulnerable package functions only
   - Output: taint paths bound to CVEs

4. Dynamic Reachability (Loader / Agent)
   - If Dockerfile exists:
     - Build and run container
     - Send attacker-shaped HTTP requests
     - Observe runtime execution
   - Runtime tracing confirms vulnerable symbol execution

## Output Philosophy

Each finding must include confidence levels:
- LOW: SBOM only
- MEDIUM: static reachability
- HIGH: static taint to vulnerable sink
- CONFIRMED: runtime execution observed

We never claim "exploit success".
We only claim "vulnerable code path executed".

## Non-goals
- No full DAST
- No fuzzing engine
- No multi-language support

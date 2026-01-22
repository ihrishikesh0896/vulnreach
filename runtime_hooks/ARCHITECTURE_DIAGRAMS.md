# Runtime Hooks Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Python Runtime Hooks System                     │
│                         (Phase 1 Complete)                          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ STEP 2: runner.py (Entry Point)                                    │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ 1. Install all hooks                                            │ │
│ │ 2. Load target application                                      │ │
│ │ 3. Execute with compile() + exec()                              │ │
│ │ 4. Call flush() to output events                                │ │
│ └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌──────────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│ STEP 3: audit.py     │  │ STEP 4: imports  │  │ STEP 5: sinks.py     │
│                      │  │                  │  │                      │
│ sys.addaudithook()   │  │ __import__ wrap  │  │ eval() wrapper       │
│                      │  │                  │  │ exec() wrapper       │
│ Captures:            │  │ Captures:        │  │ Popen wrapper        │
│ • import             │  │ • module name    │  │                      │
│ • exec               │  │ • fromlist       │  │ Each emits:          │
│ • compile            │  │ • level          │  │ • function name      │
│ • pickle.load        │  │ • stack trace    │  │ • source preview     │
│ • subprocess.Popen   │  │                  │  │ • stack trace        │
│                      │  │                  │  │                      │
│ emit("audit", {...}) │  │ emit("import",   │  │ emit("sink", {...})  │
│                      │  │      {...})      │  │                      │
└──────────────────────┘  └──────────────────┘  └──────────────────────┘
           │                       │                       │
           └───────────────────────┼───────────────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ STEP 1: events.py            │
                    │                              │
                    │ In-memory event buffer       │
                    │                              │
                    │ emit(type, data):            │
                    │   _events.append(...)        │
                    │                              │
                    │ flush():                     │
                    │   print(json.dumps(events))  │
                    │   _events.clear()            │
                    └──────────────────────────────┘
                                   │
                                   ▼
                        ┌────────────────────┐
                        │  JSON Output       │
                        │                    │
                        │  [                 │
                        │    {               │
                        │      "type": "...", │
                        │      "data": {...} │
                        │    },              │
                        │    ...             │
                        │  ]                 │
                        └────────────────────┘
```

## Event Flow Diagram

```
Target App Execution Flow:
═══════════════════════════════════════════════════════════════

1. User runs: python runner.py target_app/main.py
   │
   ├─► runner.py loads
   │
   ├─► Install Phase:
   │   ├─► audit.install()    → sys.addaudithook(...)
   │   ├─► imports.install()  → builtins.__import__ = wrapper
   │   └─► sinks.install()    → eval/exec/Popen = wrappers
   │
   ├─► Execution Phase:
   │   │
   │   ├─► Target app runs (compile + exec)
   │   │
   │   ├─► When app imports:    emit("import", ...)
   │   ├─► When app calls eval:  emit("sink", ...)
   │   ├─► When interpreter ops: emit("audit", ...)
   │   │
   │   └─► Target app completes normally
   │
   └─► Output Phase:
       └─► flush() prints JSON array of all events
```

## Data Structure Diagram

```
Event Structure:
════════════════

All events follow this schema:
┌──────────────────────────────┐
│ {                            │
│   "type": "import|sink|audit"│
│   "data": {                  │
│     ... type-specific ...    │
│     "stack": [...]           │
│   }                          │
│ }                            │
└──────────────────────────────┘

Import Event:
┌────────────────────────────────────┐
│ {                                  │
│   "type": "import",                │
│   "data": {                        │
│     "module": "json",              │
│     "fromlist": [],                │
│     "level": 0,                    │
│     "stack": ["  File ...", ...]   │
│   }                                │
│ }                                  │
└────────────────────────────────────┘

Sink Event:
┌────────────────────────────────────┐
│ {                                  │
│   "type": "sink",                  │
│   "data": {                        │
│     "function": "eval",            │
│     "source_preview": "2 + 2",     │
│     "stack": ["  File ...", ...]   │
│   }                                │
│ }                                  │
└────────────────────────────────────┘

Audit Event:
┌────────────────────────────────────┐
│ {                                  │
│   "type": "audit",                 │
│   "data": {                        │
│     "event": "import",             │
│     "args": ["module_name", ...],  │
│     "stack": ["  File ...", ...]   │
│   }                                │
│ }                                  │
└────────────────────────────────────┘
```

## File Dependency Graph

```
runtime_hooks/
│
├── runner.py ────────┐
│                     │
├── hooks/            │
│   ├── __init__.py   │
│   │                 │
│   ├── events.py ◄───┼───┐
│   │                 │   │
│   ├── audit.py ◄────┤   │
│   │      │          │   │
│   ├── imports.py ◄──┤   │
│   │      │          │   │
│   └── sinks.py ◄────┘   │
│          │              │
│          └──────────────┘
│        (all depend on events.py)
│
└── target_app/
    ├── simple.py        (tested by runner.py)
    ├── test_imports.py  (tested by runner.py)
    └── test_all_hooks.py(tested by runner.py)
```

## Call Chain Example

```
Example: Target app calls eval("2 + 2")
═══════════════════════════════════════

Target Code:
    result = eval("2 + 2")
         │
         ▼
    builtins.eval (wrapped by sinks.py)
         │
         ├─► _eval_hook() executes
         │   │
         │   ├─► emit("sink", {
         │   │       "function": "eval",
         │   │       "source_preview": "2 + 2",
         │   │       "stack": [traceback...]
         │   │   })
         │   │
         │   └─► _original_eval("2 + 2")
         │           │
         │           └─► Returns: 4
         │
         └─► result = 4

At end of execution:
    flush()
         │
         └─► Prints: [{"type": "sink", "data": {...}}]
```

## Hook Installation Sequence

```
runner.py main() execution:
═══════════════════════════

Time  │ Action
──────┼────────────────────────────────────────
  0   │ Parse command line args
  1   │ audit.install()
      │   └─► sys.addaudithook(_audit_hook)
  2   │ imports.install()
      │   └─► builtins.__import__ = _import_hook
  3   │ sinks.install()
      │   ├─► builtins.eval = _eval_hook
      │   ├─► builtins.exec = _exec_hook
      │   └─► subprocess.Popen = _PopenHook
  4   │ All hooks active ✓
  5   │ Load target file
  6   │ compile(source, filename, "exec")
  7   │ exec(code, globals_dict)
      │   └─► Target app runs
      │       └─► Hooks capture events
  8   │ Target completes
  9   │ flush()
      │   └─► Print JSON array
 10   │ Exit
```

## Verification Flow

```
Manual Verification Process:
════════════════════════════

STEP 1 (events.py):
    REPL → emit() → flush() → Verify JSON output

STEP 2 (runner.py):
    runner.py simple.py → Verify app runs → Verify flush()

STEP 3 (audit.py):
    install() → import module → flush() → Verify audit event

STEP 4 (imports.py):
    install() → import module → flush() → Verify import event

STEP 5 (sinks.py):
    install() → call eval() → flush() → Verify sink event
    install() → call exec() → flush() → Verify sink event
    install() → call Popen() → flush() → Verify sink event

Automated:
    verify.py → Runs all tests → Reports pass/fail
```

## Integration Architecture

```
Future VulnReach Integration:
══════════════════════════════

┌────────────────────────────────────────┐
│ vulnreach CLI                          │
│                                        │
│ vulnreach /path/to/app --dynamic      │
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│ Dynamic Analysis Mode                  │
│                                        │
│ 1. Use runtime_hooks/runner.py        │
│ 2. Capture JSON events                 │
│ 3. Parse events                        │
│ 4. Correlate with SBOM vulnerabilities│
│ 5. Generate reachability report       │
└────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│ Enhanced Security Report               │
│                                        │
│ • Static analysis (existing)           │
│ • Dynamic analysis (new)               │
│ • Reachability proof with stack traces│
│ • Exploit PoC detection                │
└────────────────────────────────────────┘
```

---

**All diagrams created for:** runtime_hooks implementation (Phase 1 complete)  
**Date:** January 20, 2026  
**Status:** ✅ Production Ready

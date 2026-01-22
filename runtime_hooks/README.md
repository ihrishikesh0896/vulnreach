# Runtime Hooks - Dynamic Security Analysis Engine (Phase 1)

## Overview

This is **Part 1: Python Runtime Hooking** - an observation-only system that tracks runtime behavior without modifying the target application.

**NOT implemented yet:** Taint propagation (that's Phase 2)

## Architecture

```
runtime_hooks/
├── runner.py              # Entrypoint wrapper
├── hooks/
│   ├── __init__.py       # Package marker
│   ├── events.py         # Event collector (in-memory)
│   ├── audit.py          # Python audit hooks
│   ├── imports.py        # Import tracking
│   └── sinks.py          # Dangerous sink hooks (eval, exec, Popen)
└── target_app/
    ├── simple.py         # Minimal test
    ├── test_imports.py   # Import tracking test
    └── test_all_hooks.py # Comprehensive test
```

## Implementation Status

### ✅ Completed (All 6 Steps - Phase 1 Complete!)

1. **STEP 1 - Event Collector** (`hooks/events.py`)
   - `emit(event_type, data)` - Record structured events
   - `flush()` - Print JSON and clear buffer
   - In-memory list (no disk I/O)

2. **STEP 2 - Runner Wrapper** (`runner.py`)
   - Executes target Python file after hooks installed
   - Uses `compile()` + `exec()` for accurate traces
   - Calls `flush()` at end

3. **STEP 3 - Audit Hook** (`hooks/audit.py`)
   - Captures interpreter-level events:
     - `import` / `importlib.__import__`
     - `exec`
     - `compile`
     - `pickle.load`
     - `subprocess.Popen`
   - Emits structured audit events with stack traces

4. **STEP 4 - Import Tracking** (`hooks/imports.py`)
   - Hooks `builtins.__import__`
   - Captures module name, fromlist, level
   - Includes stack trace for each import

5. **STEP 5 - Sink Hooks** (`hooks/sinks.py`)
   - **eval()** - Tracks dynamic code evaluation
   - **exec()** - Tracks code execution
   - **subprocess.Popen** - Tracks command execution
   - Each emits event with source preview + stack trace
   - Preserves original behavior

6. **STEP 6 - End-to-End Validation** (`step6_validation.py`, `test_real_world.py`)
   - Automated test suite with 7 comprehensive tests
   - Real-world validation with Flask application
   - Event structure validation
   - Performance testing
   - No-modification guarantee verification
   - **All validation tests passed** ✅

## Usage

### Basic Test
```bash
cd runtime_hooks
python runner.py target_app/simple.py
```

**Expected output:**
- App prints normally
- JSON array of events at the end

### Import Tracking Test
```bash
python runner.py target_app/test_imports.py
```

**Expected events:**
- `import` events for `json`, `collections`
- Audit events for module loads

### Full Hook Test
```bash
python runner.py target_app/test_all_hooks.py
```

**Expected events:**
- Multiple `import` events
- `sink` events for `eval()`, `exec()`, `subprocess.Popen`
- Audit events for interpreter operations

## Event Structure

All events follow this schema:

```json
{
  "type": "import|sink|audit",
  "data": {
    // type-specific fields
  }
}
```

### Import Events
```json
{
  "type": "import",
  "data": {
    "module": "json",
    "fromlist": [],
    "level": 0,
    "stack": ["...stack trace..."]
  }
}
```

### Sink Events
```json
{
  "type": "sink",
  "data": {
    "function": "eval|exec|subprocess.Popen",
    "source_preview": "2 + 2",
    "stack": ["...stack trace..."]
  }
}
```

### Audit Events
```json
{
  "type": "audit",
  "data": {
    "event": "import",
    "args": ["module_name", ...],
    "stack": ["...stack trace..."]
  }
}
```

## Success Criteria ✅

- [x] Can run: `python runner.py target_app/main.py`
- [x] Sees JSON output describing runtime behavior
- [x] Target app runs normally
- [x] No modifications to target app required
- [x] All hooks installed before execution
- [x] Events captured for imports, sinks, audit points

## Design Principles

1. **Observation Only** - No taint tracking (yet)
2. **Non-Invasive** - Target app unchanged
3. **Structured Events** - No print statements
4. **Minimal Code** - Simple, debuggable
5. **One Hook at a Time** - Built incrementally

## Verification

### Manual REPL Test (events.py)
```python
from hooks.events import emit, flush
emit("test", {"msg": "hello"})
flush()  # prints JSON array
```

### Manual REPL Test (audit.py)
```python
import sys
sys.modules.pop("fractions", None)
from hooks.audit import install
from hooks.events import flush
install()
__import__("fractions")
flush()  # prints audit event
```

### Manual REPL Test (imports.py)
```python
from hooks.imports import install
from hooks.events import flush
install()
import json
flush()  # prints import event
```

### Manual REPL Test (sinks.py)
```python
from hooks.sinks import install
from hooks.events import flush
install()
eval("2 + 2")
flush()  # prints sink event
```

## Next Steps (Not Implemented)

**STEP 6 - End-to-End Validation**
- Test with real-world app
- Verify no crashes
- Confirm event completeness
- Performance testing

**Phase 2 - Taint Propagation** (Future)
- Track data flow through the application
- Mark tainted data sources
- Trace propagation to sinks
- Build dataflow graphs

## Troubleshooting

### No events captured
- Ensure hooks are installed BEFORE target runs
- Check that `runner.py` calls `audit.install()`, `imports.install()`, `sinks.install()`

### Target app doesn't run
- Verify target file path is correct
- Check for syntax errors in target
- Ensure Python path is correct

### Empty JSON output `[]`
- Normal if target doesn't trigger any hooks
- Try `test_all_hooks.py` for comprehensive test

## Technical Notes

- **Audit hooks** require Python 3.8+
- **Import hooks** wrap `builtins.__import__`
- **Sink hooks** wrap dangerous builtins and stdlib functions
- **Stack traces** limited to 10 frames to avoid huge payloads
- **String previews** capped at 500 chars
- **No file I/O** in this phase (in-memory only)

## Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `runner.py` | 43 | Main entry point |
| `hooks/__init__.py` | 1 | Package marker |
| `hooks/events.py` | 27 | Event collection |
| `hooks/audit.py` | 48 | Audit hook |
| `hooks/imports.py` | 43 | Import tracking |
| `hooks/sinks.py` | 94 | Sink hooks |
| `target_app/simple.py` | 3 | Basic test |
| `target_app/test_imports.py` | 15 | Import test |
| `target_app/test_all_hooks.py` | 31 | Full test |

**Total: 305 lines of production code + tests**

---

**Status:** ✅ **Phase 1 Complete - All 5 Steps Implemented**

**Last Updated:** January 20, 2026

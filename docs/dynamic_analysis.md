# ✅ SYSTEM PROMPT FOR GITHUB COPILOT (PART 1: PYTHON RUNTIME HOOKS)

> **Role:**
> You are a **Senior Security Engineer / IAST Tooling Engineer**.
> You are helping me build **Part 1: Python Runtime Hooking** for a dynamic security analysis engine.
>
> **Core Goal:**
> Observe *runtime behavior* of a Python application **without modifying the target app**.
>
> We are NOT doing taint propagation yet.
> This phase is **observation only**.
>
> ---
>
> ## HARD RULES (DO NOT BREAK)
>
> 1. Implement **ONE function at a time**
> 2. After each function:
>
>    * explain what it does
>    * explain how to manually verify it
>    * stop and wait
> 3. Do NOT implement multiple hooks at once
> 4. Do NOT refactor unless explicitly asked
> 5. Use **structured events**, not print statements
> 6. Keep code minimal, explicit, and debuggable
>
> ---
>
> ## ARCHITECTURE (DO NOT CHANGE)
>
> ```
> runtime_hooks/
> ├── runner.py          # entrypoint wrapper
> ├── hooks/
> │   ├── events.py      # event collector
> │   ├── audit.py       # python audit hooks
> │   ├── imports.py     # import tracking
> │   └── sinks.py       # dangerous sink hooks
> └── target_app/        # untouched target app
> ```
>
> ---
>
> ## SUCCESS CRITERIA
>
> * I can run: `python runner.py target_app/main.py`
> * I see JSON output describing runtime behavior
> * The target app runs normally
>
> ---
>
> ## START WITH STEP 1 ONLY
>
> Implement **only** the event collection system (`hooks/events.py`).
> Do NOT move to the next step until I confirm it works.

---

# 🧱 STEP-BY-STEP EXECUTION PLAN (STRICT)

You will **drive Copilot through this list**, step by step.
Do NOT skip ahead.

---

## 🔹 STEP 1 — Event Collector (Foundation)

**File:** `hooks/events.py`

**Goal:**
Create a minimal, reliable event sink for runtime observations.

**Must include:**

* `emit(event_type, data)`
* `flush()` that prints JSON
* in-memory list (no files yet)

**Debug check:**

* Manually call `emit()` from a REPL
* Call `flush()` and verify JSON output

👉 **Do NOT continue until verified**

---

## 🔹 STEP 2 — Runner Wrapper (Controlled Execution)

**File:** `runner.py`

**Goal:**
Execute a target Python file **after hooks are installed**.

**Must include:**

* Read target file path from `sys.argv`
* `compile()` + `exec()`
* Call `flush()` at the end

**Debug check:**

* Use a dummy `print("hello")` app
* Ensure app runs and events flush

👉 Stop after success

---

## 🔹 STEP 3 — Python Audit Hook (Interpreter-Level Signals)

**File:** `hooks/audit.py`

**Goal:**
Capture interpreter events like:

* `import`
* `exec`
* `compile`
* `pickle.load`
* `subprocess.Popen`

**Must include:**

* `sys.addaudithook`
* emit structured audit events

**Debug check:**

* Trigger a simple `import os`
* Verify audit event captured

👉 Stop and confirm

---

## 🔹 STEP 4 — Import Tracking Hook

**File:** `hooks/imports.py`

**Goal:**
Track **actual runtime imports**, not declared dependencies.

**Must include:**

* Hook `builtins.__import__`
* Capture module name + stack trace

**Debug check:**

* Import a known library
* Confirm event emitted once per import

👉 Stop here

---

## 🔹 STEP 5 — Sink Hooking (Reachability Proof)

**File:** `hooks/sinks.py`

**Implement one sink at a time**, in this order:

1. `eval`
2. `exec`
3. `subprocess.Popen`

Each sink must:

* emit event
* capture stack trace
* preserve original behavior

**Debug check per sink:**

* Write a tiny test that calls it
* Confirm event fires
* Confirm app still works

👉 Do NOT batch sinks together

---

## 🔹 STEP 6 — End-to-End Validation

**Goal:**
Prove the engine works without touching the app.

Checklist:

* App runs normally
* JSON events emitted
* Imports + sinks visible
* No crashes

 Got it. Below is a **clean, no-nonsense `TODO.md`** you can literally drop into the repo and build against.
This reflects **where SAST lives**, the **V1 scope**, and the **correct execution order**.

---

# 🛠️ TODO.md — Reachability-Aware AppSec Scanner (V1)

## 🎯 V1 Goal

> Prove whether a **SAST/SCA finding is reachable and safely triggerable** at runtime — without exploiting production systems.

---

## 0️⃣ Project Guardrails (NON-NEGOTIABLE)

* [ ] No exploit chains
* [ ] No destructive payloads
* [ ] No blind crawling
* [ ] No auto-generated exploits
* [ ] Validation = proof-of-control only
* [ ] Skip if reachability or confidence is low

---

## 1️⃣ Repo Intake

* [ ] Accept GitHub / GitLab / Bitbucket repo URL
* [ ] Clone repo into isolated workspace
* [ ] Detect backend framework

  * [ ] Flask / FastAPI
  * [ ] Spring Boot (optional V1+)
* [ ] Detect if app can boot (optional)

---

## 2️⃣ SAST — Signal Collection (NOT Severity)

### Tooling

* [ ] Integrate Semgrep (JSON output)
* [ ] Load curated rules for:

  * [ ] SQL Injection
  * [ ] Command Injection
  * [ ] SSTI
  * [ ] Path Traversal
  * [ ] Deserialization
  * [ ] Unsafe `eval` / `exec`

### Output (raw evidence)

* [ ] Extract:

  * [ ] Rule ID
  * [ ] File
  * [ ] Line number
  * [ ] Sink function
  * [ ] Taint hint (request / input source)
* [ ] Do NOT assign severity here

---

## 3️⃣ Entrypoint Discovery (Static)

### Framework-Aware Parsing

* [ ] Extract HTTP routes

  * [ ] Method
  * [ ] Path
  * [ ] Handler function
  * [ ] Source file
* [ ] Map handler → file → function

### Output

```json
{
  "method": "POST",
  "path": "/upload",
  "handler": "upload",
  "file": "app.py"
}
```

---

## 4️⃣ Reachability Engine (CORE LOGIC)

For each SAST finding:

* [ ] Map sink → enclosing function
* [ ] Trace function → HTTP handler
* [ ] Determine:

  * [ ] Is there an HTTP entrypoint?
  * [ ] Is user input passed?
  * [ ] Is auth likely required?

### Compute Reachability Score (0–1)

* [ ] Entrypoint exists (0.4)

* [ ] Framework routing confirmed (0.3)

* [ ] User input flows to sink (0.3)

* [ ] Skip finding if score < 0.4

---

## 5️⃣ Confidence Scoring (SAST Trust)

* [ ] Assign confidence:

  * [ ] Semgrep only → 0.6
  * [ ] Semgrep + dependency context → 0.8
  * [ ] Heuristic match → 0.4
* [ ] Drop findings with confidence < 0.5

---

## 6️⃣ Validation Strategy Builder (SAFE ONLY)

For reachable findings:

* [ ] Identify vulnerability type

* [ ] Select safe probe:

  * [ ] SQLi → boolean condition
  * [ ] SSTI → math expression
  * [ ] XSS → reflected marker
  * [ ] Command Injection → timing delay
  * [ ] Path Traversal → traversal detection only

* [ ] Define:

  * [ ] Max requests (≤3)
  * [ ] Expected signal
  * [ ] Abort conditions

🚫 No RCE
🚫 No file read
🚫 No data exfil

---

## 7️⃣ Sandbox Execution (Optional V1)

* [ ] Start isolated Docker environment
* [ ] Boot app (if possible)
* [ ] Inject static auth token / cookie
* [ ] Replay only validated endpoints
* [ ] Capture:

  * [ ] Response deltas
  * [ ] Timing differences
  * [ ] Reflection evidence

---

## 8️⃣ Risk Scoring Engine

### Compute Final Score

```
Risk = Impact × Exploitability × Reachability × Confidence
```

* [ ] Map CWE → Impact
* [ ] Compute exploitability from context
* [ ] Gate actions by score:

  * [ ] <20 → Info
  * [ ] 20–50 → Fix later
  * [ ] >50 → Fix now

---

## 9️⃣ Output & Reporting

* [ ] Generate JSON output
* [ ] Generate HTML report
* [ ] For each finding include:

  * [ ] Reachability score
  * [ ] Validation result
  * [ ] Risk score
  * [ ] What was intentionally NOT tested

---

## 🔒 10️⃣ Safety & Trust Controls

* [ ] Rate-limit probes
* [ ] Kill switch for validation
* [ ] Log every request made
* [ ] Prevent payload poisoning
* [ ] Ensure secrets are not logged

---

## ✅ V1 Exit Criteria

* [ ] ≤10% false positives on demo app
* [ ] Deterministic scan results
* [ ] No app crashes
* [ ] Defensible “why this was tested” story

---

### 📌 North-Star Reminder

> **SAST finds danger
> Reachability proves access
> Validation proves behavior
> Risk decides action**

---

If you want, next I can:

* Convert this into **GitHub Issues / Milestones**
* Create a **folder structure + module layout**
* Or write a **reference implementation for Reachability Engine**

Just tell me.

# Runtime Hooks - Quick Reference

## 🎯 What Is This?

**Phase 1: Python Runtime Hooking** - A dynamic security analysis engine that observes Python application runtime behavior without modifying the target code.

**Status:** ✅ **COMPLETE** (All 5 steps implemented)

---

## 🚀 Quick Start (30 seconds)

```bash
cd runtime_hooks

# Test 1: Simple execution
python runner.py target_app/simple.py

# Test 2: Full features
python runner.py target_app/test_all_hooks.py

# Test 3: Automated verification
python verify.py
```

---

## 📚 Documentation Files

| File | Purpose | When to Read |
|------|---------|--------------|
| **README.md** | Complete guide | Read first for full details |
| **FINAL_SUMMARY.md** | Executive summary | Quick overview |
| **IMPLEMENTATION_COMPLETE.md** | Status report | Verify all steps done |
| **INDEX.md** | This file | Navigation reference |

---

## 📁 Code Files

| File | Lines | Purpose |
|------|-------|---------|
| `runner.py` | 43 | Main entry point |
| `hooks/events.py` | 27 | Event collector |
| `hooks/audit.py` | 48 | Audit hook |
| `hooks/imports.py` | 43 | Import tracking |
| `hooks/sinks.py` | 94 | Sink hooks |

**Total:** 255 lines of production code

---

## 🧪 Test Files

| File | Purpose |
|------|---------|
| `target_app/simple.py` | Basic test |
| `target_app/test_imports.py` | Import tracking test |
| `target_app/test_all_hooks.py` | Comprehensive test |
| `verify.py` | Automated test suite |

---

## ✅ Implementation Checklist

- [x] **STEP 1:** Event Collector (`hooks/events.py`)
- [x] **STEP 2:** Runner Wrapper (`runner.py`)
- [x] **STEP 3:** Audit Hook (`hooks/audit.py`)
- [x] **STEP 4:** Import Tracking (`hooks/imports.py`)
- [x] **STEP 5:** Sink Hooks (`hooks/sinks.py`)
- [ ] **STEP 6:** End-to-End Validation (pending)

---

## 🎓 How It Works

```
1. runner.py installs all hooks
2. Hooks wrap dangerous functions (eval, exec, imports, etc.)
3. Target app runs normally
4. Hooks emit structured events
5. JSON array printed at end
```

**Key Principle:** Zero modifications to target application

---

## 🔍 What Gets Captured

### Import Events
Every `import` statement with stack trace

### Sink Events
- `eval()` calls
- `exec()` calls  
- `subprocess.Popen` calls

### Audit Events
- Interpreter-level operations
- Module loads
- Code compilation

**All events include stack traces**

---

## 💡 Use Cases

### 1. Security Analysis
```bash
python runner.py /path/to/app.py > events.json
# Analyze events.json for security issues
```

### 2. Dependency Tracking
```bash
python runner.py app.py | jq '.[] | select(.type=="import")'
# See all runtime imports
```

### 3. Vulnerability Detection
```bash
python runner.py app.py | jq '.[] | select(.type=="sink")'
# See all dangerous function calls
```

---

## 🛠️ Integration Points

### VulnReach CLI
```bash
vulnreach /path/to/app --dynamic-analysis
# Would use runtime_hooks internally
```

### Custom Analysis
```python
from hooks import audit, imports, sinks
from hooks.events import flush

# Install hooks
audit.install()
imports.install()
sinks.install()

# Your app code here
# ...

# Get events
flush()
```

---

## 🐛 Troubleshooting

### No events captured
→ Check hooks are installed before app runs

### Target doesn't run
→ Verify Python 3.8+ and correct file path

### Empty JSON `[]`
→ Normal if app doesn't trigger hooks

### Import errors in IDE
→ False positives, works at runtime

---

## 📈 Next Steps

### Immediate
1. Run `python verify.py` to test
2. Try with `labs/vuln_demo` app
3. Review captured events

### Near Term (STEP 6)
1. End-to-end validation
2. Performance testing
3. VulnReach CLI integration

### Future (Phase 2)
1. Taint propagation
2. Dataflow tracking
3. Vulnerability detection
4. Report generation

---

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| Production Code | 255 lines |
| Test Code | 49 lines |
| Documentation | 1,244 lines |
| Total Files | 13 |
| Implementation Time | 1 session |
| External Dependencies | 0 |
| Python Version | 3.8+ |

---

## 🔗 Related Files

- **Specification:** `../docs/dynamic_analysis.md`
- **Main Project:** `../src/vulnreach/`
- **Test Apps:** `../labs/vuln_demo/`, `../labs/python_vuln_app/`

---

## 👤 Quick Commands Reference

```bash
# Navigate to runtime_hooks
cd /Users/hrishikesh/Desktop/github_projects/vulnreach-parent/vuln-reachability-sample/runtime_hooks

# Run simple test
python runner.py target_app/simple.py

# Run full test
python runner.py target_app/test_all_hooks.py

# Automated verification
python verify.py

# View events as pretty JSON
python runner.py target_app/test_all_hooks.py | tail -1 | jq

# Count event types
python runner.py target_app/test_all_hooks.py | tail -1 | jq 'group_by(.type) | map({type: .[0].type, count: length})'

# Extract just imports
python runner.py target_app/test_all_hooks.py | tail -1 | jq '.[] | select(.type=="import")'

# Extract just sinks
python runner.py target_app/test_all_hooks.py | tail -1 | jq '.[] | select(.type=="sink")'
```

---

## 🎊 Status

**Phase 1: Python Runtime Hooking**  
✅ **COMPLETE** (5/5 steps)

**Ready for:**
- STEP 6: End-to-End Validation
- Phase 2: Taint Propagation
- VulnReach CLI Integration

---

*Last Updated: January 20, 2026*  
*Quick Reference v1.0*

**🚀 All systems ready! Start with `python verify.py` or read `README.md`**

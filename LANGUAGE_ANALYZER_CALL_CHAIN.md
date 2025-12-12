# Complete Language Analyzer Call Chain Reference

## 🔍 Where Each Language Analyzer Lives and Gets Called

---

## 1. Python Analysis

### Implementation Location:
```
src/vulnreach/utils/vuln_reachability_analyzer.py
    └─ class PythonAnalyzer (Lines 77-222)
```

### Called From:
```python
# File: multi_language_analyzer.py (Line ~189)
if language == 'python':
    output_path = os.path.join(output_dir, "python_vulnerability_reachability_report.json")
    run_reachability_analysis(project_root, consolidated_path, output_path)

# Which calls:
# File: vuln_reachability_analyzer.py (Line 687)
def run_reachability_analysis(project_root, consolidated_path, output_path):
    analyzer = VulnReachabilityAnalyzer(project_root)
    # Automatically initializes PythonAnalyzer if .py files found
```

### Call Chain:
```
User → multi_language_analyzer.py 
     → run_reachability_analysis() 
     → VulnReachabilityAnalyzer.__init__() 
     → _initialize_analyzers() 
     → PythonAnalyzer (if Python files detected)
```

---

## 2. Java Analysis

### Implementation Location:
```
src/vulnreach/utils/vuln_reachability_analyzer.py
    └─ class JavaAnalyzer (Lines 224-492)
```

### Called From:
```python
# File: multi_language_analyzer.py (Line ~195)
elif language == 'java':
    output_path = os.path.join(output_dir, "java_vulnerability_reachability_report.json")
    run_reachability_analysis(project_root, consolidated_path, output_path)

# Same function as Python! 
# File: vuln_reachability_analyzer.py (Line 687)
def run_reachability_analysis(project_root, consolidated_path, output_path):
    analyzer = VulnReachabilityAnalyzer(project_root)
    # Automatically initializes JavaAnalyzer if .java/.kt/.scala files found
```

### Call Chain:
```
User → multi_language_analyzer.py 
     → run_reachability_analysis() 
     → VulnReachabilityAnalyzer.__init__() 
     → _initialize_analyzers() 
     → JavaAnalyzer (if Java files detected)
```

---

## 3. JavaScript Analysis

### Implementation Location:
```
src/vulnreach/utils/javascript_reachability_analyzer.py
    └─ class JavaScriptReachabilityAnalyzer (Entire file, ~270 lines)
```

### Called From:
```python
# File: multi_language_analyzer.py (Line ~201)
elif language == 'javascript':
    output_path = os.path.join(output_dir, "javascript_vulnerability_reachability_report.json")
    run_javascript_reachability_analysis(project_root, consolidated_path, output_path)

# Which calls:
# File: javascript_reachability_analyzer.py (Line ~215)
def run_javascript_reachability_analysis(project_root, consolidated_path, output_path):
    analyzer = JavaScriptReachabilityAnalyzer(project_root)
    # ... JavaScript-specific analysis
```

### Call Chain:
```
User → multi_language_analyzer.py 
     → run_javascript_reachability_analysis() 
     → JavaScriptReachabilityAnalyzer (separate file!)
```

**⚠️ IMPORTANT: Does NOT go through vuln_reachability_analyzer.py!**

---

## 4. Go Analysis

### Implementation Location:
```
src/vulnreach/utils/go_reachability_analyzer.py
    └─ class GoReachabilityAnalyzer (Separate file)
```

### Called From:
```python
# File: multi_language_analyzer.py (Line ~207)
elif language == 'go':
    output_path = os.path.join(output_dir, "go_vulnerability_reachability_report.json")
    run_go_reachability_analysis(project_root, consolidated_path, output_path)
```

### Call Chain:
```
User → multi_language_analyzer.py 
     → run_go_reachability_analysis() 
     → GoReachabilityAnalyzer (separate file)
```

---

## 5. C# Analysis

### Implementation Location:
```
src/vulnreach/utils/csharp_reachability_analyzer.py
    └─ class CSharpReachabilityAnalyzer (Separate file)
```

### Called From:
```python
# File: multi_language_analyzer.py (Line ~213)
elif language == 'csharp':
    output_path = os.path.join(output_dir, "csharp_vulnerability_reachability_report.json")
    run_csharp_reachability_analysis(project_root, consolidated_path, output_path)
```

### Call Chain:
```
User → multi_language_analyzer.py 
     → run_csharp_reachability_analysis() 
     → CSharpReachabilityAnalyzer (separate file)
```

---

## 6. PHP Analysis

### Implementation Location:
```
src/vulnreach/utils/php_reachability_analyzer.py
    └─ class PHPReachabilityAnalyzer (Separate file)
```

### Called From:
```python
# File: multi_language_analyzer.py (Line ~219)
elif language == 'php':
    output_path = os.path.join(output_dir, "php_vulnerability_reachability_report.json")
    run_php_reachability_analysis(project_root, consolidated_path, output_path)
```

### Call Chain:
```
User → multi_language_analyzer.py 
     → run_php_reachability_analysis() 
     → PHPReachabilityAnalyzer (separate file)
```

---

## 📊 Complete Import Graph

```
multi_language_analyzer.py
│
├─ from .vuln_reachability_analyzer import run_reachability_analysis
│  └─ Used for: Python, Java
│
├─ from .javascript_reachability_analyzer import run_javascript_reachability_analysis
│  └─ Used for: JavaScript, TypeScript
│
├─ from .java_reachability_analyzer import run_java_reachability_analysis
│  └─ Used for: Java (alternative/fallback)
│
├─ from .go_reachability_analyzer import run_go_reachability_analysis
│  └─ Used for: Go
│
├─ from .csharp_reachability_analyzer import run_csharp_reachability_analysis
│  └─ Used for: C#
│
└─ from .php_reachability_analyzer import run_php_reachability_analysis
   └─ Used for: PHP
```

---

## 🔄 Actual Code Imports (with error handling)

### In multi_language_analyzer.py:

```python
# Lines 10-25: Import with try/except for graceful fallback

try:
    from .vuln_reachability_analyzer import run_reachability_analysis
except ImportError:
    run_reachability_analysis = None

try:
    from .java_reachability_analyzer import run_java_reachability_analysis
except ImportError:
    run_java_reachability_analysis = None

try:
    from .javascript_reachability_analyzer import run_javascript_reachability_analysis
except ImportError:
    run_javascript_reachability_analysis = None

# ... similar for go, csharp, php
```

**Reason for try/except:** If a specific language analyzer is not available, the system gracefully falls back and continues with other languages.

---

## 🎯 Key Insights

### 1. Two Different Patterns:

**Pattern A: Consolidated (Python + Java)**
```
multi_language_analyzer.py
    → vuln_reachability_analyzer.py
        → PythonAnalyzer (built-in class)
        → JavaAnalyzer (built-in class)
```

**Pattern B: Modular (JavaScript, Go, C#, PHP)**
```
multi_language_analyzer.py
    → javascript_reachability_analyzer.py (separate file)
    → go_reachability_analyzer.py (separate file)
    → csharp_reachability_analyzer.py (separate file)
    → php_reachability_analyzer.py (separate file)
```

### 2. Entry Point Functions:

| Language | Entry Function | Location |
|----------|---------------|----------|
| Python | `run_reachability_analysis()` | `vuln_reachability_analyzer.py` |
| Java | `run_reachability_analysis()` | `vuln_reachability_analyzer.py` |
| JavaScript | `run_javascript_reachability_analysis()` | `javascript_reachability_analyzer.py` |
| Go | `run_go_reachability_analysis()` | `go_reachability_analyzer.py` |
| C# | `run_csharp_reachability_analysis()` | `csharp_reachability_analyzer.py` |
| PHP | `run_php_reachability_analysis()` | `php_reachability_analyzer.py` |

### 3. Special Case: Java has TWO implementations!

**Implementation 1:** Built-in JavaAnalyzer class
```
vuln_reachability_analyzer.py → JavaAnalyzer (Lines 224-492)
```

**Implementation 2:** Standalone file
```
java_reachability_analyzer.py → JavaReachabilityAnalyzer
```

**Which one is used?** The router (`multi_language_analyzer.py`) can use either:
- Line 189-194: Calls `run_reachability_analysis()` (uses built-in JavaAnalyzer)
- Line 195-200: Could call `run_java_reachability_analysis()` (standalone)

Currently, it prefers the built-in version when available.

---

## 🔍 How to Trace a Language Analysis

### Example: Tracing JavaScript Analysis

1. **User runs:**
   ```bash
   vulnreach scan ./my-js-app
   ```

2. **tracer_.py calls:**
   ```python
   # Line ~850
   language = run_multi_language_analysis(
       project_root="./my-js-app",
       consolidated_path="security_findings/consolidated.json",
       output_dir="security_findings"
   )
   ```

3. **multi_language_analyzer.py detects:**
   ```python
   # Line ~125
   detector = ProjectLanguageDetector(project_root)
   language = detector.detect_language()
   # Returns: "javascript" (found .js files and package.json)
   ```

4. **multi_language_analyzer.py routes:**
   ```python
   # Line ~201
   elif language == 'javascript':
       run_javascript_reachability_analysis(
           project_root,
           consolidated_path,
           output_path
       )
   ```

5. **javascript_reachability_analyzer.py executes:**
   ```python
   # Line ~215
   def run_javascript_reachability_analysis(project_root, consolidated_path, output_path):
       analyzer = JavaScriptReachabilityAnalyzer(project_root)
       analyses = analyzer.analyze_vulnerability_reachability(vuln_data)
       report = analyzer.generate_report(analyses)
   ```

6. **Output generated:**
   ```
   security_findings/javascript_vulnerability_reachability_report.json
   ```

---

## 📝 Quick Reference

**Want to know if a language uses vuln_reachability_analyzer.py?**

- ✅ **Python** → YES (PythonAnalyzer class)
- ✅ **Java** → YES (JavaAnalyzer class)
- ❌ **JavaScript** → NO (separate file)
- ❌ **Go** → NO (separate file)
- ❌ **C#** → NO (separate file)
- ❌ **PHP** → NO (separate file)

**Rule of thumb:**
- If it's in `vuln_reachability_analyzer.py` as a class → Built-in
- If it's in a separate `<language>_reachability_analyzer.py` → Standalone

---

## 🎨 Visual Summary

```
┌─────────────────────────────────────────────────┐
│   multi_language_analyzer.py (THE HUB)         │
│   All roads start here!                         │
└──────────────────┬──────────────────────────────┘
                   │
          ┌────────┴────────┐
          │                 │
          ▼                 ▼
┌──────────────────┐  ┌──────────────────┐
│ Built-in         │  │ Standalone       │
│ (One file)       │  │ (Separate files) │
├──────────────────┤  ├──────────────────┤
│                  │  │                  │
│ vuln_reach...py  │  │ javascript_..py  │
│   - Python       │  │ go_...py         │
│   - Java         │  │ csharp_...py     │
│                  │  │ php_...py        │
└──────────────────┘  └──────────────────┘
```

**Both architectures work!** They coexist in the same codebase.


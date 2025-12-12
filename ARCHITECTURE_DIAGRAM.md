# Architecture Diagram: Multi-Language Vulnerability Analysis

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         USER / CLI                                  │
│  vulnreach scan <project_root> --output security_findings/         │
└────────────────────┬───────────────────────────────────────────────┘
                     │
                     ↓
┌────────────────────────────────────────────────────────────────────┐
│              tracer_.py (Main Entry Point)                          │
│  • Runs Syft (SBOM generation)                                     │
│  • Runs Trivy (Vulnerability scanning)                             │
│  • Generates consolidated.json                                     │
└────────────────────┬───────────────────────────────────────────────┘
                     │
                     ↓
┌────────────────────────────────────────────────────────────────────┐
│         multi_language_analyzer.py (ROUTER/ORCHESTRATOR)           │
│                                                                     │
│  ┌──────────────────────────────────────────────────┐             │
│  │  ProjectLanguageDetector                         │             │
│  │  ├─> Scans project files (.py, .java, .js, etc.)│             │
│  │  ├─> Checks build files (pom.xml, package.json) │             │
│  │  └─> Returns: 'python' | 'java' | 'javascript'  │             │
│  └──────────────────────────────────────────────────┘             │
│                          │                                         │
│                          ↓                                         │
│  ┌──────────────────────────────────────────────────┐             │
│  │  run_multi_language_analysis()                   │             │
│  │  └─> Routes based on detected language           │             │
│  └──────────────────────────────────────────────────┘             │
└─────────┬──────┬───────┬───────┬───────┬───────┬──────────────────┘
          │      │       │       │       │       │
    Python│      │Java   │JS     │Go     │C#     │PHP
          │      │       │       │       │       │
          ↓      ↓       ↓       ↓       ↓       ↓
┌─────────────────────────────────────────────────────────────────────┐
│                  LANGUAGE-SPECIFIC ANALYZERS                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  vuln_reachability_analyzer.py (Python)                      │  │
│  │                                                               │  │
│  │  run_reachability_analysis(project_root, consolidated, out)  │  │
│  │         ↓                                                     │  │
│  │  VulnReachabilityAnalyzer                                    │  │
│  │         ↓                                                     │  │
│  │  ┌──────────────────────────────────────────────────────┐   │  │
│  │  │  PythonAnalyzer (LanguageAnalyzer)                   │   │  │
│  │  │  ├─> get_source_files()      → Find *.py files      │   │  │
│  │  │  ├─> extract_usage()          → Parse AST, imports  │   │  │
│  │  │  └─> get_declared_dependencies() → requirements.txt │   │  │
│  │  └──────────────────────────────────────────────────────┘   │  │
│  │         ↓                                                     │  │
│  │  analyze_vulnerability_reachability()                        │  │
│  │         ↓                                                     │  │
│  │  generate_report() → JSON output                             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  java_reachability_analyzer.py (Java)                       │  │
│  │                                                               │  │
│  │  run_java_reachability_analysis(...)                         │  │
│  │         ↓                                                     │  │
│  │  JavaAnalyzer                                                │  │
│  │  ├─> get_source_files()      → Find *.java, *.kt           │  │
│  │  ├─> extract_usage()          → Parse imports, annotations │  │
│  │  └─> get_declared_dependencies() → pom.xml, build.gradle   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  javascript_reachability_analyzer.py (JavaScript/TypeScript)│  │
│  │                                                               │  │
│  │  run_javascript_reachability_analysis(...)                   │  │
│  │  ├─> Parse package.json                                     │  │
│  │  ├─> Find require() / import statements                     │  │
│  │  └─> Generate report                                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  [Similar structure for Go, C#, PHP analyzers...]                   │
│                                                                      │
└──────────────────────────────────────┬───────────────────────────────┘
                                       │
                                       ↓
┌─────────────────────────────────────────────────────────────────────┐
│                    OUTPUT: JSON REPORTS                              │
│  • python_vulnerability_reachability_report.json                    │
│  • java_vulnerability_reachability_report.json                      │
│  • javascript_vulnerability_reachability_report.json                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Detailed Call Flow

### Example: Python Project Analysis

```
1. User runs: vulnreach scan ./my-python-app

2. tracer_.py
   ├─> Generates SBOM with Syft
   ├─> Scans vulnerabilities with Trivy
   └─> Creates consolidated.json
       [
         {
           "package_name": "flask",
           "installed_version": "1.0.0",
           "vulnerability_id": "CVE-2023-30861",
           "severity": "HIGH"
         }
       ]

3. tracer_.py calls:
   run_multi_language_analysis(
       project_root="./my-python-app",
       consolidated_path="security_findings/consolidated.json",
       output_dir="security_findings"
   )

4. multi_language_analyzer.py
   ├─> detector = ProjectLanguageDetector("./my-python-app")
   ├─> language = detector.detect_language()
   │   ├─> Scans for .py files: Found 50
   │   ├─> Checks for requirements.txt: Found
   │   └─> Returns: "python"
   │
   └─> Routes to Python analyzer:
       run_reachability_analysis(
           "./my-python-app",
           "security_findings/consolidated.json",
           "security_findings/python_vulnerability_reachability_report.json"
       )

5. vuln_reachability_analyzer.py
   ├─> analyzer = VulnReachabilityAnalyzer("./my-python-app")
   │   └─> Initializes PythonAnalyzer
   │
   ├─> Loads consolidated.json
   │   [{package: "flask", version: "1.0.0", ...}]
   │
   ├─> analyze_vulnerability_reachability(vuln_data)
   │   ├─> PythonAnalyzer.get_source_files()
   │   │   └─> Returns: [app.py, models.py, views.py, ...]
   │   │
   │   ├─> For each source file:
   │   │   └─> PythonAnalyzer.extract_usage(file)
   │   │       ├─> Parse Python AST
   │   │       ├─> Find: "from flask import Flask"
   │   │       └─> Record: UsageContext(file='app.py', line=1, type='import')
   │   │
   │   └─> For each vulnerability:
   │       ├─> Check if package is imported
   │       ├─> Check if package functions are called
   │       ├─> Assess risk level (CRITICAL/HIGH/MEDIUM/LOW)
   │       └─> Return: VulnAnalysis object
   │
   ├─> generate_report(analyses)
   │   └─> Creates JSON with:
   │       {
   │         "summary": { "critical_reachable": 1, ... },
   │         "vulnerabilities": [...]
   │       }
   │
   └─> Saves to: python_vulnerability_reachability_report.json

6. User receives:
   ✅ Consolidated vulnerability scan
   ✅ Reachability analysis report
   ✅ Risk prioritization based on actual usage
```

---

## 🧩 Component Interaction Matrix

| Component | Calls → | Called by ← | Purpose |
|-----------|---------|-------------|---------|
| `tracer_.py` | `multi_language_analyzer` | User/CLI | Main orchestrator |
| `multi_language_analyzer` | Language analyzers | `tracer_.py` | Route to appropriate analyzer |
| `vuln_reachability_analyzer` | None | `multi_language_analyzer` | Python analysis |
| `java_reachability_analyzer` | None | `multi_language_analyzer` | Java analysis |
| `javascript_reachability_analyzer` | None | `multi_language_analyzer` | JavaScript analysis |

**Key Insight:** It's a **one-way dependency tree** - each layer only calls downward, never upward.

---

## 🔌 Extension Points

### Adding a New Language (Example: Rust)

```python
# 1. Create rust_reachability_analyzer.py
def run_rust_reachability_analysis(project_root, consolidated_path, output_path):
    # Implementation here
    pass

# 2. Update multi_language_analyzer.py

# Add import with fallback
try:
    from .rust_reachability_analyzer import run_rust_reachability_analysis
except ImportError:
    run_rust_reachability_analyzer = None

# Update ProjectLanguageDetector.detect_language()
class ProjectLanguageDetector:
    def detect_language(self):
        # ... existing code ...
        
        # Add Rust detection
        elif file.endswith('.rs'):
            file_counts['rust'] = file_counts.get('rust', 0) + 1
        
        if file == 'Cargo.toml':
            build_files.add('rust')
        
        # ... existing priority logic ...
        
        if 'rust' in build_files and file_counts.get('rust', 0) > 0:
            return 'rust'

# Update run_multi_language_analysis()
def run_multi_language_analysis(project_root, consolidated_path, output_dir):
    # ... existing code ...
    
    elif language == 'rust':
        output_path = os.path.join(output_dir, "rust_vulnerability_reachability_report.json")
        if run_rust_reachability_analysis:
            run_rust_reachability_analysis(project_root, consolidated_path, output_path)
        else:
            print("⚠️ Rust analyzer unavailable")
```

---

## 📦 Class Hierarchy

```
LanguageAnalyzer (Abstract Base Class)
    │
    ├── PythonAnalyzer
    │   ├── get_source_files() → [*.py]
    │   ├── extract_usage() → AST parsing
    │   ├── get_declared_dependencies() → requirements.txt
    │   └── normalize_package_name() → lowercase + dashes
    │
    ├── JavaAnalyzer
    │   ├── get_source_files() → [*.java, *.kt, *.scala]
    │   ├── extract_usage() → Import regex parsing
    │   ├── get_declared_dependencies() → pom.xml, build.gradle
    │   └── normalize_package_name() → group:artifact format
    │
    └── [Future: RustAnalyzer, RubyAnalyzer, etc.]
```

---

## 🎯 Design Patterns Used

1. **Strategy Pattern** - Different analyzers for different languages
2. **Factory Pattern** - Language detection determines which analyzer to create
3. **Template Method** - `LanguageAnalyzer` defines common interface
4. **Dependency Injection** - Analyzers receive project_root
5. **Fail-Safe** - Graceful degradation if analyzer unavailable

---

## 💡 Key Takeaways

✅ **Multi-language analyzer is a router, not an analyzer itself**
✅ **Each language analyzer is independent and self-contained**
✅ **Easy to add new languages without modifying existing code**
✅ **Dynamic loading with fallback for missing analyzers**
✅ **Clean separation of concerns**

🚀 **The architecture is extensible, maintainable, and production-ready!**


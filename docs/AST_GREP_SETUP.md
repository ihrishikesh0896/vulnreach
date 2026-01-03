# ast-grep Installation and Setup Guide

## What is ast-grep?

ast-grep is a fast and accurate code search and refactoring tool that uses Abstract Syntax Trees (AST). Unlike regex-based approaches, ast-grep understands code structure, making it ideal for multi-language vulnerability analysis.

**Supported Languages**: Python, JavaScript, TypeScript, Java, Go, Rust, PHP, C#, Ruby, and more.

## Installation Options

### Option 1: Cargo (Recommended)
```bash
cargo install ast-grep
```

### Option 2: npm
```bash
npm install -g @ast-grep/cli
```

### Option 3: Homebrew (macOS)
```bash
brew install ast-grep
```

### Option 4: Download Binary
Visit [ast-grep releases](https://github.com/ast-grep/ast-grep/releases) and download the appropriate binary for your platform.

## Verify Installation

```bash
ast-grep --version
```

You should see output like: `ast-grep 0.x.x`

## Python Bindings (Optional)

For tighter Python integration, you can also install the Python bindings:

```bash
pip install ast-grep-py
```

**Note**: The Python bindings are experimental and optional. VulnReach uses the CLI tool by default.

## Usage in VulnReach

Once ast-grep is installed, VulnReach will automatically detect and use it for code analysis. If ast-grep is not found, VulnReach will fall back to regex-based parsing.

### Check ast-grep Status

```python
from vulnreach.utils.ast_grep_wrapper import AstGrepWrapper

wrapper = AstGrepWrapper("/path/to/project")
if wrapper.ast_grep_available:
    print("ast-grep is ready!")
else:
    print("ast-grep not found, using fallback methods")
```

### Basic Usage Example

```python
from vulnreach.utils.ast_grep_wrapper import quick_search

# Find all imports of 'requests' package
matches = quick_search(
    project_root="/path/to/project",
    pattern="import requests",
    language="python"
)

for match in matches:
    print(f"{match.file}:{match.start_line} - {match.matched_text}")
```

## Pattern Examples

### Python
```bash
# Find SQL query executions
ast-grep -p 'execute($SQL)' -l python

# Find all Flask routes
ast-grep -p '@app.route($$$)' -l python

# Find pickle usage
ast-grep -p 'pickle.loads($DATA)' -l python
```

### Java
```bash
# Find SQL injection points
ast-grep -p 'executeQuery($QUERY)' -l java

# Find unsafe deserialization
ast-grep -p 'readObject()' -l java
```

### JavaScript
```bash
# Find eval() usage
ast-grep -p 'eval($CODE)' -l javascript

# Find require() statements
ast-grep -p 'require($PKG)' -l javascript
```

## Advanced Configuration

### Pattern Variables
- `$VAR` - Matches any single AST node
- `$$$` - Matches zero or more nodes (spread)
- `$_` - Matches any node (anonymous)

### Constraints
```yaml
rule:
  pattern: execute($SQL)
  constraints:
    SQL:
      regex: "SELECT.*FROM.*"
```

## Performance Tips

1. **Scope your searches**: Use specific paths rather than searching entire codebase
2. **Use language filters**: Always specify the language for faster parsing
3. **Cache results**: ast-grep parse trees can be cached for repeated searches
4. **Exclude directories**: Skip `node_modules`, `venv`, `build` directories

## Troubleshooting

### Issue: "ast-grep: command not found"
**Solution**: Install ast-grep using one of the methods above and ensure it's in your PATH.

### Issue: "parse error" or "syntax error"
**Solution**: Check that you're using the correct language flag (`-l python`, `-l java`, etc.)

### Issue: Slow performance on large codebases
**Solution**: 
- Exclude unnecessary directories
- Use more specific patterns
- Search specific paths rather than entire project

## Resources

- [Official ast-grep Documentation](https://ast-grep.github.io/)
- [Pattern Cookbook](https://ast-grep.github.io/guide/pattern-syntax.html)
- [GitHub Repository](https://github.com/ast-grep/ast-grep)

## Integration Status in VulnReach

- ✅ Basic wrapper implemented (`ast_grep_wrapper.py`)
- ✅ Language support: Python, Java, JavaScript, Go, Rust, PHP, C#
- ✅ Fallback to regex if unavailable
- ⬜ Pattern library for common vulnerabilities
- ⬜ Integration with Scanner Agent
- ⬜ Call graph tracing with Reachability Agent
- ⬜ Full agent-based workflow

## Next Steps

1. Install ast-grep: `cargo install ast-grep`
2. Test the wrapper: `python -c "from vulnreach.utils.ast_grep_wrapper import quick_search; print('Ready!')"`
3. Run VulnReach scans - ast-grep will be used automatically if available
4. Explore agent-based features (coming soon)

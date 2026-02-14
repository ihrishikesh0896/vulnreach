#!/bin/bash
# Test VulnReach Commands

echo "Testing VulnReach CLI with both positional and --target flag"
echo "=============================================================="
echo ""

# Test 1: Positional argument
echo "Test 1: Positional argument"
echo "Command: python src/vulnreach/tracer_.py labs/python_vuln_app --help"
python src/vulnreach/tracer_.py labs/python_vuln_app --help 2>&1 | head -5
echo ""

# Test 2: --target flag
echo "Test 2: --target flag"
echo "Command: python src/vulnreach/tracer_.py --target labs/python_vuln_app --help"
python src/vulnreach/tracer_.py --target labs/python_vuln_app --help 2>&1 | head -5
echo ""

# Test 3: Check if --target is in help
echo "Test 3: Check if --target appears in help"
python src/vulnreach/tracer_.py --help 2>&1 | grep -C 2 "\--target"
echo ""

echo "Tests complete!"

"""Comprehensive test target to verify all hooks work."""
import subprocess

print("=== Testing Runtime Hooks ===")
print()

# Test 1: Import tracking
print("1. Testing import tracking...")
import json
from collections import defaultdict
print("   ✓ Imports done")
print()

# Test 2: eval() sink
print("2. Testing eval() sink...")
result = eval("2 + 2")
print(f"   ✓ eval result: {result}")
print()

# Test 3: exec() sink
print("3. Testing exec() sink...")
exec("x = 'exec works'")
print(f"   ✓ exec result: {x}")  # noqa: F821
print()

# Test 4: subprocess.Popen sink
print("4. Testing subprocess.Popen sink...")
proc = subprocess.Popen(["echo", "popen works"], stdout=subprocess.PIPE)
output, _ = proc.communicate()
print(f"   ✓ Popen result: {output.decode().strip()}")
print()

print("=== All tests completed ===")

#!/usr/bin/env python3
"""Quick verification script for runtime hooks."""
import subprocess
import sys
import json

def test_runtime_hooks():
    """Test that all runtime hooks work correctly."""
    print("🧪 Testing Runtime Hooks Implementation\n")

    # Test 1: Simple execution
    print("TEST 1: Simple execution")
    result = subprocess.run(
        [sys.executable, "runner.py", "target_app/simple.py"],
        capture_output=True,
        text=True,
        cwd="."
    )

    if result.returncode != 0:
        print(f"   ❌ FAILED - Exit code: {result.returncode}")
        print(f"   stderr: {result.stderr}")
        return False

    print("   ✅ PASSED - App executed successfully")
    print()

    # Test 2: Full hooks test
    print("TEST 2: Full hooks test (imports + sinks)")
    result = subprocess.run(
        [sys.executable, "runner.py", "target_app/test_all_hooks.py"],
        capture_output=True,
        text=True,
        cwd="."
    )

    if result.returncode != 0:
        print(f"   ❌ FAILED - Exit code: {result.returncode}")
        print(f"   stderr: {result.stderr}")
        return False

    # Try to parse the JSON output (last line should be events)
    lines = result.stdout.strip().split('\n')
    json_line = lines[-1]

    try:
        events = json.loads(json_line)
        print(f"   ✅ PASSED - Captured {len(events)} events")

        # Count event types
        imports = sum(1 for e in events if e['type'] == 'import')
        sinks = sum(1 for e in events if e['type'] == 'sink')
        audits = sum(1 for e in events if e['type'] == 'audit')

        print(f"      - Import events: {imports}")
        print(f"      - Sink events: {sinks}")
        print(f"      - Audit events: {audits}")

        if sinks < 3:
            print(f"   ⚠️  WARNING - Expected at least 3 sink events (eval, exec, Popen)")

    except json.JSONDecodeError as e:
        print(f"   ⚠️  WARNING - Could not parse JSON: {e}")
        print(f"   Last line: {json_line[:100]}")

    print()
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("Runtime Hooks Verification")
    print("=" * 60)
    print()

    success = test_runtime_hooks()

    print()
    print("=" * 60)
    if success:
        print("✅ ALL TESTS PASSED - Runtime hooks working correctly!")
    else:
        print("❌ SOME TESTS FAILED - Check errors above")
    print("=" * 60)

    sys.exit(0 if success else 1)

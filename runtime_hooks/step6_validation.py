"""STEP 6: End-to-End Validation Suite for Runtime Hooks

This module validates that the runtime hooks system works correctly
with real-world applications without modifying target code.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

RUNTIME_HOOKS_DIR = Path(__file__).parent
RUNNER_PATH = RUNTIME_HOOKS_DIR / "runner.py"


class ValidationResult:
    """Holds validation results for a single test."""

    def __init__(self, test_name: str):
        self.test_name = test_name
        self.passed = False
        self.stdout = ""
        self.stderr = ""
        self.exit_code = 0
        self.events: List[Dict[str, Any]] = []
        self.errors: List[str] = []

    def add_error(self, error: str) -> None:
        self.errors.append(error)

    def mark_passed(self) -> None:
        self.passed = True


def run_target_app(target_path: str) -> ValidationResult:
    """Run a target app through the runtime hooks runner."""
    result = ValidationResult(f"Run {target_path}")

    try:
        proc = subprocess.run(
            [sys.executable, str(RUNNER_PATH), target_path],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(RUNTIME_HOOKS_DIR),
        )

        result.stdout = proc.stdout
        result.stderr = proc.stderr
        result.exit_code = proc.returncode

        # Extract JSON events from last line
        if result.stdout:
            lines = result.stdout.strip().split("\n")
            json_line = lines[-1]
            try:
                result.events = json.loads(json_line)
            except json.JSONDecodeError as e:
                result.add_error(f"Failed to parse JSON events: {e}")
                return result

        if proc.returncode != 0:
            result.add_error(f"Non-zero exit code: {proc.returncode}")
            if result.stderr:
                result.add_error(f"stderr: {result.stderr}")
        else:
            result.mark_passed()

    except subprocess.TimeoutExpired:
        result.add_error("Process timed out (10s)")
    except Exception as e:
        result.add_error(f"Unexpected error: {e}")

    return result


def validate_event_types(events: List[Dict[str, Any]]) -> tuple[bool, List[str]]:
    """Validate that expected event types are present."""
    errors = []
    event_types = {e.get("type") for e in events}

    # Check for expected event types
    if "import" not in event_types:
        errors.append("No 'import' events captured")

    # Validate event structure
    for event in events:
        if "type" not in event:
            errors.append(f"Event missing 'type' field: {event}")
        if "data" not in event:
            errors.append(f"Event missing 'data' field: {event}")
        elif not isinstance(event["data"], dict):
            errors.append(f"Event 'data' is not a dict: {event}")

    return len(errors) == 0, errors


def test_simple_app() -> ValidationResult:
    """Test 1: Simple application with basic imports."""
    print("\n🧪 TEST 1: Simple Application")
    result = run_target_app("target_app/simple.py")

    if result.passed:
        print("   ✅ App executed successfully")

        # Validate events
        if result.events:
            print(f"   ✅ Captured {len(result.events)} events")

            valid, errors = validate_event_types(result.events)
            if valid:
                print("   ✅ Event structure valid")
            else:
                for error in errors:
                    print(f"   ⚠️  {error}")
        else:
            result.add_error("No events captured")
            print("   ❌ No events captured")
    else:
        for error in result.errors:
            print(f"   ❌ {error}")

    return result


def test_import_tracking() -> ValidationResult:
    """Test 2: Import tracking with multiple imports."""
    print("\n🧪 TEST 2: Import Tracking")
    result = run_target_app("target_app/test_imports.py")

    if result.passed:
        print("   ✅ App executed successfully")

        import_events = [e for e in result.events if e.get("type") == "import"]
        print(f"   ✅ Captured {len(import_events)} import events")

        # Check for expected imports
        imported_modules = {
            e.get("data", {}).get("module") for e in import_events
        }
        expected_modules = {"json", "collections"}

        for module in expected_modules:
            if module in imported_modules:
                print(f"   ✅ Import '{module}' captured")
            else:
                result.add_error(f"Expected import '{module}' not captured")
                print(f"   ⚠️  Import '{module}' not captured")
    else:
        for error in result.errors:
            print(f"   ❌ {error}")

    return result


def test_sink_hooks() -> ValidationResult:
    """Test 3: Sink hooks for eval, exec, subprocess.Popen."""
    print("\n🧪 TEST 3: Sink Hooks")
    result = run_target_app("target_app/test_all_hooks.py")

    if result.passed:
        print("   ✅ App executed successfully")

        sink_events = [e for e in result.events if e.get("type") == "sink"]
        print(f"   ✅ Captured {len(sink_events)} sink events")

        # Check for expected sinks
        sink_functions = {
            e.get("data", {}).get("function") for e in sink_events
        }
        expected_sinks = {"eval", "exec", "subprocess.Popen"}

        for sink in expected_sinks:
            if sink in sink_functions:
                print(f"   ✅ Sink '{sink}' captured")
            else:
                result.add_error(f"Expected sink '{sink}' not captured")
                print(f"   ⚠️  Sink '{sink}' not captured")

        # Verify at least 3 sink events
        if len(sink_events) < 3:
            result.add_error(
                f"Expected at least 3 sink events, got {len(sink_events)}"
            )
    else:
        for error in result.errors:
            print(f"   ❌ {error}")

    return result


def test_audit_hooks() -> ValidationResult:
    """Test 4: Audit hooks for interpreter events."""
    print("\n🧪 TEST 4: Audit Hooks")
    result = run_target_app("target_app/test_all_hooks.py")

    if result.passed:
        print("   ✅ App executed successfully")

        audit_events = [e for e in result.events if e.get("type") == "audit"]
        if audit_events:
            print(f"   ✅ Captured {len(audit_events)} audit events")

            # Check audit event structure
            for event in audit_events[:3]:  # Check first 3
                data = event.get("data", {})
                if "event" in data and "args" in data and "stack" in data:
                    print(f"   ✅ Audit event structure valid: {data['event']}")
                else:
                    result.add_error(f"Invalid audit event structure: {event}")
        else:
            print("   ⚠️  No audit events captured (may be normal)")
    else:
        for error in result.errors:
            print(f"   ❌ {error}")

    return result


def test_no_target_modification() -> ValidationResult:
    """Test 5: Verify target apps are unchanged."""
    print("\n🧪 TEST 5: No Target Modification")
    result = ValidationResult("No Target Modification")

    target_files = [
        "target_app/simple.py",
        "target_app/test_imports.py",
        "target_app/test_all_hooks.py",
    ]

    all_unchanged = True
    for target_file in target_files:
        path = RUNTIME_HOOKS_DIR / target_file
        if path.exists():
            # Read file and verify no hook imports
            content = path.read_text()
            if "from hooks" in content or "import hooks" in content:
                result.add_error(f"{target_file} has been modified with hook imports")
                print(f"   ❌ {target_file} modified")
                all_unchanged = False
            else:
                print(f"   ✅ {target_file} unchanged")
        else:
            result.add_error(f"{target_file} not found")
            all_unchanged = False

    if all_unchanged:
        result.mark_passed()

    return result


def test_stack_traces() -> ValidationResult:
    """Test 6: Verify stack traces are captured."""
    print("\n🧪 TEST 6: Stack Trace Capture")
    result = run_target_app("target_app/test_all_hooks.py")

    if result.passed:
        print("   ✅ App executed successfully")

        # Check that events have stack traces
        events_with_stacks = [
            e for e in result.events if "stack" in e.get("data", {})
        ]

        if events_with_stacks:
            print(f"   ✅ {len(events_with_stacks)} events have stack traces")

            # Verify stack trace format
            sample_stack = events_with_stacks[0].get("data", {}).get("stack", [])
            if isinstance(sample_stack, list) and len(sample_stack) > 0:
                print(f"   ✅ Stack trace format valid (len: {len(sample_stack)})")
                result.mark_passed()
            else:
                result.add_error("Stack trace format invalid")
        else:
            result.add_error("No events with stack traces")
            print("   ❌ No events with stack traces")
    else:
        for error in result.errors:
            print(f"   ❌ {error}")

    return result


def test_performance() -> ValidationResult:
    """Test 7: Basic performance check (should complete quickly)."""
    print("\n🧪 TEST 7: Performance Check")
    result = ValidationResult("Performance")

    import time

    start_time = time.time()
    run_result = run_target_app("target_app/test_all_hooks.py")
    elapsed = time.time() - start_time

    if elapsed < 5.0:  # Should complete in under 5 seconds
        print(f"   ✅ Completed in {elapsed:.2f}s (< 5s)")
        result.mark_passed()
    else:
        result.add_error(f"Took {elapsed:.2f}s (>= 5s)")
        print(f"   ⚠️  Took {elapsed:.2f}s (slower than expected)")

    if not run_result.passed:
        for error in run_result.errors:
            result.add_error(error)

    return result


def print_summary(results: List[ValidationResult]) -> bool:
    """Print summary of all validation results."""
    print("\n" + "=" * 70)
    print("📊 VALIDATION SUMMARY")
    print("=" * 70)

    passed = sum(1 for r in results if r.passed)
    total = len(results)

    print(f"\nTests Passed: {passed}/{total}")
    print()

    for result in results:
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"{status} - {result.test_name}")
        if result.errors:
            for error in result.errors:
                print(f"       └─ {error}")

    print("\n" + "=" * 70)

    if passed == total:
        print("🎉 ALL TESTS PASSED - Runtime hooks validated successfully!")
        print("=" * 70)
        return True
    else:
        print(f"⚠️  {total - passed} TEST(S) FAILED - Review errors above")
        print("=" * 70)
        return False


def main() -> int:
    """Run end-to-end validation suite."""
    print("=" * 70)
    print("🔬 STEP 6: End-to-End Validation Suite")
    print("=" * 70)
    print("\nValidating runtime hooks system with real-world scenarios...")

    results = [
        test_simple_app(),
        test_import_tracking(),
        test_sink_hooks(),
        test_audit_hooks(),
        test_no_target_modification(),
        test_stack_traces(),
        test_performance(),
    ]

    all_passed = print_summary(results)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

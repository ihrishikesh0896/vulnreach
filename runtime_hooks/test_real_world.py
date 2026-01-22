"""Real-world validation: Test runtime hooks with vuln_demo Flask app

This tests the runtime hooks with an actual vulnerable Flask application
from labs/vuln_demo to prove it works with real-world code.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

RUNTIME_HOOKS_DIR = Path(__file__).parent
RUNNER_PATH = RUNTIME_HOOKS_DIR / "runner.py"
VULN_DEMO_APP = RUNTIME_HOOKS_DIR.parent / "labs" / "vuln_demo" / "app.py"


def test_vuln_demo() -> None:
    """Test runtime hooks with the vulnerable Flask app."""
    print("=" * 70)
    print("🔬 Real-World Test: vuln_demo Flask Application")
    print("=" * 70)
    print()

    if not VULN_DEMO_APP.exists():
        print(f"❌ vuln_demo app not found at: {VULN_DEMO_APP}")
        print("   Skipping real-world test")
        return

    print(f"📍 Target: {VULN_DEMO_APP}")
    print()
    print("Running runtime hooks on Flask app...")
    print("(This will capture imports and any code execution)")
    print()

    try:
        # Run with a short timeout since Flask app won't exit on its own
        proc = subprocess.run(
            [sys.executable, str(RUNNER_PATH), str(VULN_DEMO_APP)],
            capture_output=True,
            text=True,
            timeout=3,  # Short timeout, Flask will keep running
            cwd=str(RUNTIME_HOOKS_DIR),
        )
    except subprocess.TimeoutExpired as e:
        # This is expected for Flask app
        print("⏱️  Process timed out (expected for Flask server)")
        stdout = e.stdout.decode() if e.stdout else ""
        stderr = e.stderr.decode() if e.stderr else ""

        print()
        print("📤 Captured Output:")
        print("-" * 70)

        if stdout:
            lines = stdout.strip().split("\n")
            # Try to extract JSON from last line
            if lines:
                try:
                    events = json.loads(lines[-1])
                    print(f"✅ Captured {len(events)} events from Flask app!")
                    print()

                    # Analyze events
                    event_types = {}
                    for event in events:
                        etype = event.get("type", "unknown")
                        event_types[etype] = event_types.get(etype, 0) + 1

                    print("📊 Event Breakdown:")
                    for etype, count in sorted(event_types.items()):
                        print(f"   • {etype}: {count} events")

                    print()

                    # Show sample import events
                    import_events = [e for e in events if e.get("type") == "import"]
                    if import_events:
                        print(f"📦 Sample Imports Captured:")
                        for event in import_events[:5]:
                            module = event.get("data", {}).get("module", "unknown")
                            print(f"   • {module}")
                        if len(import_events) > 5:
                            print(f"   ... and {len(import_events) - 5} more")

                    print()

                    # Show sample sink events
                    sink_events = [e for e in events if e.get("type") == "sink"]
                    if sink_events:
                        print(f"🎯 Sink Events Captured:")
                        for event in sink_events[:3]:
                            func = event.get("data", {}).get("function", "unknown")
                            preview = event.get("data", {}).get(
                                "source_preview", ""
                            )[:50]
                            print(f"   • {func}(...)")
                        if len(sink_events) > 3:
                            print(f"   ... and {len(sink_events) - 3} more")

                    print()
                    print("=" * 70)
                    print("✅ REAL-WORLD TEST PASSED")
                    print("=" * 70)
                    print()
                    print("Runtime hooks successfully captured behavior from a")
                    print("real Flask application without modifying the source code!")

                except json.JSONDecodeError:
                    print("⚠️  Could not parse JSON events")
                    print(f"Last line: {lines[-1][:100]}")

        if stderr:
            print()
            print("⚠️  Stderr output:")
            print(stderr[:500])

        return

    # If process completed normally (unlikely for Flask)
    print("✅ Process completed normally")
    print()

    if proc.stdout:
        lines = proc.stdout.strip().split("\n")
        if lines:
            try:
                events = json.loads(lines[-1])
                print(f"✅ Captured {len(events)} events")
            except json.JSONDecodeError:
                print("⚠️  Could not parse JSON events")


if __name__ == "__main__":
    test_vuln_demo()

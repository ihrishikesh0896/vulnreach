"""Simple test target to verify import tracking."""
print("Target app starting...")

# This import should be captured
import json

# This import should also be captured
from collections import defaultdict

# Use the imports so they're not optimized away
data = json.dumps({"test": "value"})
d = defaultdict(int)
d["count"] += 1

print("Target app completed successfully!")
print(f"Data: {data}")
print(f"Count: {d['count']}")

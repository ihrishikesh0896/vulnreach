#!/usr/bin/env python3
import yaml
import pickle
import os

print("Starting vulnerable app demo...")

data = {"key": "value"}
yaml_str = yaml.dump(data)
print(f"YAML: {yaml_str}")

pickled = pickle.dumps(data)
print(f"Pickled data size: {len(pickled)}")

print("App finished successfully!")


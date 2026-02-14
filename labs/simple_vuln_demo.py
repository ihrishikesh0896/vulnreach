#!/usr/bin/env python3
"""
Simple vulnerable demo app for testing VulnReach pipeline
This script has intentional security issues for demonstration purposes.
"""

import os
import pickle
import yaml
import subprocess

def process_user_input():
    """Simulate processing user input with vulnerabilities"""

    # Simulate HTTP input (taint source)
    user_input = os.environ.get('USER_INPUT', 'test')
    print(f"Processing user input: {user_input}")

    # SQL Injection sink
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # VULNERABLE: SQL Injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    try:
        cursor.execute(query)
    except Exception as e:
        print(f"SQL error: {e}")

    # Command Injection sink
    filename = os.environ.get('FILENAME', 'test.txt')

    # VULNERABLE: Command Injection
    try:
        result = subprocess.run(f"ls {filename}", shell=True, capture_output=True)
        print(f"Command result: {result.stdout}")
    except Exception as e:
        print(f"Command error: {e}")

    # Deserialization sink
    data = os.environ.get('PICKLE_DATA', '')
    if data:
        try:
            # VULNERABLE: Insecure deserialization
            obj = pickle.loads(data.encode())
            print(f"Deserialized: {obj}")
        except Exception as e:
            print(f"Pickle error: {e}")

    # YAML loading
    yaml_input = os.environ.get('YAML_DATA', 'key: value')
    try:
        # Using safe_load (this is actually safe)
        parsed = yaml.safe_load(yaml_input)
        print(f"YAML parsed: {parsed}")
    except Exception as e:
        print(f"YAML error: {e}")

def main():
    print("=" * 60)
    print("VulnReach Demo Application")
    print("=" * 60)

    process_user_input()

    print("\nDemo complete!")

if __name__ == '__main__':
    main()


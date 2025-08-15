#!/usr/bin/env python3
"""
Simple Flask web application with intentionally vulnerable dependencies
for testing SBOM and SCA security scanning tools.

WARNING: This application contains known vulnerabilities and should only be used
in isolated testing environments for security tool validation.
"""

from flask import Flask, request, render_template_string, jsonify
import requests
import yaml
import pickle
import base64

app = Flask(__name__)

# Simple HTML template for demonstration
TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Test App</title>
</head>
<body>
    <h1>SBOM/SCA Testing Application</h1>
    <p>This app uses vulnerable dependencies for testing security scanners.</p>

    <h2>Test Endpoints:</h2>
    <ul>
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/yaml-test">/yaml-test</a> - YAML processing test</li>
        <li><a href="/request-test">/request-test</a> - External request test</li>
    </ul>

    <h2>Dependencies Status</h2>
    <p>Check your SBOM/SCA tools to see if they detect vulnerable versions of:</p>
    <ul>
        <li>Flask (check version)</li>
        <li>PyYAML (check version)</li>
        <li>Requests (check version)</li>
        <li>Jinja2 (check version)</li>
    </ul>
</body>
</html>
'''


@app.route('/')
def home():
    return render_template_string(TEMPLATE)


@app.route('/health')
def health():
    return jsonify({
        'status': 'running',
        'message': 'SBOM/SCA test application is running'
    })


@app.route('/yaml-test')
def yaml_test():
    # Simple YAML processing endpoint
    sample_yaml = """
    config:
      name: test
      version: 1.0
    """
    try:
        data = yaml.safe_load(sample_yaml)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/request-test')
def request_test():
    # Simple external request test
    try:
        response = requests.get('https://httpbin.org/get', timeout=5)
        return jsonify({
            'status_code': response.status_code,
            'message': 'External request successful'
        })
    except Exception as e:
        return jsonify({'error': str(e)})


if __name__ == '__main__':
    print("Starting SBOM/SCA test application...")
    print("WARNING: This application contains vulnerable dependencies for testing purposes only!")
    app.run(debug=True, host='127.0.0.1', port=5000)
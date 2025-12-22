#!/bin/bash
#
# install_dependencies.sh
#
# This script installs the required dependencies for VulnReach:
# - Syft (SBOM Generator)
# - Trivy (Vulnerability Scanner)
# - Semgrep (SAST Tool)
#
# It is designed for macOS and Linux environments.

set -e  # Exit immediately if a command exits with a non-zero status.

echo "🚀 Starting VulnReach dependency installation..."

# --- Install Syft ---
echo "\n[1/3] Installing Syft..."
if command -v syft &> /dev/null; then
    echo "✅ Syft is already installed. Skipping."
else
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    echo "✅ Syft installed successfully."
fi

# --- Install Trivy ---
echo "\n[2/3] Installing Trivy..."
if command -v trivy &> /dev/null; then
    echo "✅ Trivy is already installed. Skipping."
else
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    echo "✅ Trivy installed successfully."
fi

# --- Install Semgrep ---
echo "\n[3/3] Installing Semgrep..."
if command -v semgrep &> /dev/null; then
    echo "✅ Semgrep is already installed. Skipping."
else
    # Use python3 -m pip to ensure it uses the correct Python environment
    python3 -m pip install semgrep
    echo "✅ Semgrep installed successfully."
fi

echo "\n🎉 All dependencies are installed and ready to use!"


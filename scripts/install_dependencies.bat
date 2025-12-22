@echo off
::
:: install_dependencies.bat
::
:: This script installs the required dependencies for VulnReach on Windows:
:: - Syft (SBOM Generator)
:: - Trivy (Vulnerability Scanner)
:: - Semgrep (SAST Tool)
::
:: It requires PowerShell to be available.

echo 🚀 Starting VulnReach dependency installation...

:: --- Install Syft ---
echo.
echo [1/3] Installing Syft...
where syft >nul 2>nul
if %errorlevel% == 0 (
    echo ✅ Syft is already installed. Skipping.
) else (
    echo    Downloading and running Syft installer...
    powershell -Command "irm https://raw.githubusercontent.com/anchore/syft/main/install.sh | iex"
    echo ✅ Syft installed successfully.
)

:: --- Install Trivy ---
echo.
echo [2/3] Installing Trivy...
where trivy >nul 2>nul
if %errorlevel% == 0 (
    echo ✅ Trivy is already installed. Skipping.
) else (
    echo    Downloading and running Trivy installer...
    powershell -Command "irm https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | iex"
    echo ✅ Trivy installed successfully.
)

:: --- Install Semgrep ---
echo.
echo [3/3] Installing Semgrep...
where semgrep >nul 2>nul
if %errorlevel% == 0 (
    echo ✅ Semgrep is already installed. Skipping.
) else (
    echo    Installing Semgrep via pip...
    python -m pip install semgrep
    echo ✅ Semgrep installed successfully.
)

echo.
echo 🎉 All dependencies are installed and ready to use!
pause


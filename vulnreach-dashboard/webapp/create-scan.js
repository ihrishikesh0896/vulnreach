/**
 * Create Scan Page JavaScript
 */

class ScanCreator {
    constructor() {
        this.form = document.getElementById('scanForm');
        this.loadingOverlay = document.getElementById('loadingOverlay');
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Form submission
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));

        // Project type change handler
        const projectType = document.getElementById('projectType');
        projectType.addEventListener('change', (e) => this.handleProjectTypeChange(e));
    }

    handleProjectTypeChange(event) {
        const projectType = event.target.value;
        // Update form fields based on project type
        // This could show/hide certain options depending on the project type
    }

    async handleSubmit(event) {
        event.preventDefault();

        // Get form data
        const formData = {
            projectName: document.getElementById('projectName').value,
            projectType: document.getElementById('projectType').value,
            repositoryUrl: document.getElementById('repositoryUrl').value,
            branch: document.getElementById('branch').value,
            scanConfig: {
                vulnerabilityScan: document.getElementById('vulnerabilityScan').checked,
                secretsScan: document.getElementById('secretsScan').checked,
                dependencyScan: document.getElementById('dependencyScan').checked,
                reachabilityAnalysis: document.getElementById('reachabilityAnalysis').checked,
            },
            advanced: {
                scanDepth: document.getElementById('scanDepth').value,
                excludePatterns: document.getElementById('excludePatterns').value,
            }
        };

        try {
            // Show loading overlay
            this.loadingOverlay.classList.remove('d-none');

            // Send scan request to the server
            const response = await fetch('/api/scans', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();

            // Redirect to the dashboard or scan details page
            window.location.href = `index.html?scan=${result.scanId}`;

        } catch (error) {
            console.error('Error starting scan:', error);
            // Show error message to user
            alert('Failed to start scan. Please try again.');
        } finally {
            // Hide loading overlay
            this.loadingOverlay.classList.add('d-none');
        }
    }

    validateForm() {
        // Add custom form validation if needed
        return true;
    }
}

// Initialize the scan creator when the page loads
document.addEventListener('DOMContentLoaded', () => {
    window.scanCreator = new ScanCreator();
});

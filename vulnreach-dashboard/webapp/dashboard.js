/**
 * Dashboard JavaScript
 */

class Dashboard {
    constructor() {
        this.loadingOverlay = document.getElementById('loadingOverlay');
        this.initializeDashboard();
    }

    async initializeDashboard() {
        try {
            // Show loading overlay
            this.showLoading(true);

            // Load dashboard data
            await this.loadDashboardData();

            // Initialize charts
            this.initializeSecurityScoreChart();

        } catch (error) {
            console.error('Error initializing dashboard:', error);
            // Also surface a user-friendly banner
            this.showError('Failed to load dashboard data');
        } finally {
            // Hide loading overlay
            this.showLoading(false);
        }
    }

    async loadDashboardData() {
        try {
            // For development/demo, use mock data if API is not available
            let data;
            try {
                const response = await fetch('/api/dashboard');
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                data = await response.json();
            } catch (apiError) {
                console.warn('API not available, using mock data:', apiError);
                // Mock data for development
                data = {
                    summary: {
                        totalScans: 27,
                        criticalFindings: 5,
                        totalProjects: 12,
                        averageScore: 86
                    },
                    recentScans: [
                        {
                            id: 'demo-1',
                            projectName: 'Demo Web App',
                            projectType: 'Web Application',
                            status: 'completed',
                            findings: { critical: 2, high: 3, medium: 5 },
                            lastScan: new Date().toISOString()
                        },
                        {
                            id: 'demo-2',
                            projectName: 'API Service',
                            projectType: 'API',
                            status: 'in-progress',
                            findings: { high: 1, medium: 2 },
                            lastScan: new Date(Date.now() - 86400000).toISOString()
                        }
                    ]
                };
            }

            // Update summary cards
            this.updateSummaryCards(data.summary);

            // Update recent scans table
            this.updateRecentScans(data.recentScans);

            // Initialize/update security score chart
            this.initializeSecurityScoreChart(data.summary.averageScore);

        } catch (error) {
            console.error('Error processing dashboard data:', error);
            this.showError('Failed to load dashboard data');
            throw error;
        }
    }

    showError(message) {
        // Create and show error alert
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger alert-dismissible fade show m-3';
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            <i class="material-icons align-middle me-1">error</i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;

        // Insert at the top of the main content
        const mainContent = document.querySelector('.main-content .container');
        mainContent.insertBefore(alertDiv, mainContent.firstChild);
    }

    updateSummaryCards(summary) {
        // Update summary card values
        document.getElementById('totalScans').textContent = summary.totalScans || 0;
        document.getElementById('criticalFindings').textContent = summary.criticalFindings || 0;
        document.getElementById('totalProjects').textContent = summary.totalProjects || 0;
        document.getElementById('averageScore').textContent = `${summary.averageScore || 0}%`;
    }

    updateRecentScans(scans) {
        const tbody = document.getElementById('recentScansTable');

        if (!scans || scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center py-4">
                        <div class="text-muted">
                            <i class="material-icons d-block mb-2" style="font-size: 2rem;">search</i>
                            No recent scans found
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td>
                    <div class="d-flex align-items-center">
                        <i class="material-icons me-2 text-muted">folder</i>
                        <div>
                            <div class="fw-medium">${this.escapeHtml(scan.projectName)}</div>
                            <small class="text-muted">${this.escapeHtml(scan.projectType)}</small>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge bg-${this.getStatusColor(scan.status)}">
                        ${this.escapeHtml(scan.status)}
                    </span>
                </td>
                <td>
                    <div class="d-flex align-items-center">
                        ${this.renderFindingsBadges(scan.findings)}
                    </div>
                </td>
                <td>
                    <small class="text-muted">${this.formatDate(scan.lastScan)}</small>
                </td>
                <td>
                    <button class="btn btn-sm btn-light" onclick="window.location.href='findings.html?scan=${scan.id}'">
                        <i class="material-icons">visibility</i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    initializeSecurityScoreChart(score = 75) {
        try {
            const canvas = document.getElementById('securityScoreChart');
            if (!canvas || typeof Chart === 'undefined') {
                console.warn('Chart.js not available or canvas missing, skipping chart render');
                return; // soft fail, do not throw
            }
            const ctx = canvas.getContext('2d');

            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    datasets: [{
                        data: [score, 100 - score],
                        backgroundColor: [
                            'rgb(13, 110, 253)',
                            'rgb(233, 236, 239)'
                        ],
                        borderWidth: 0,
                        cutout: '80%'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: { enabled: false }
                    },
                    animation: { animateRotate: true, animateScale: true }
                },
                plugins: [{
                    id: 'centerText',
                    afterDraw(chart) {
                        const { ctx, chartArea } = chart;
                        if (!chartArea) return;
                        const { width, height } = chartArea;
                        ctx.save();
                        ctx.font = 'bold 24px Arial';
                        ctx.fillStyle = '#000';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillText(`${score}%`, width / 2, height / 2);
                        ctx.restore();
                    }
                }]
            });
        } catch (e) {
            console.warn('Failed to render security score chart:', e);
            // swallow to avoid showing the red error banner
        }
    }

    getStatusColor(status) {
        const colors = {
            'completed': 'success',
            'in-progress': 'primary',
            'failed': 'danger',
            'pending': 'warning'
        };
        return colors[status.toLowerCase()] || 'secondary';
    }

    renderFindingsBadges(findings) {
        const badges = [];
        if (findings.critical > 0) {
            badges.push(`<span class="badge bg-danger me-1">${findings.critical}</span>`);
        }
        if (findings.high > 0) {
            badges.push(`<span class="badge bg-warning me-1">${findings.high}</span>`);
        }
        if (findings.medium > 0) {
            badges.push(`<span class="badge bg-info me-1">${findings.medium}</span>`);
        }
        return badges.join('') || '<span class="badge bg-success">0</span>';
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    showLoading(show) {
        this.loadingOverlay.classList.toggle('d-none', !show);
    }
}

// Initialize the dashboard when the page loads
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});

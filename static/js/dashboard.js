class SecurityDashboard {
    constructor() {
        this.currentProject = null;
        this.currentReportType = 'security';
        this.allVulnerabilities = [];
        this.filteredVulnerabilities = [];
        this.reachabilityData = null;
        this.init();
    }

    async init() {
        await this.loadOverview();
        await this.loadProjects();
        this.setupEventListeners();
    }

    setupEventListeners() {
        const searchInput = document.getElementById('search-input');
        const severityFilter = document.getElementById('severity-filter');
        const reachabilityFilter = document.getElementById('reachability-filter');

        searchInput.addEventListener('input', () => this.applyFilters());
        severityFilter.addEventListener('change', () => this.applyFilters());
        reachabilityFilter.addEventListener('change', () => this.applyFilters());
    }

    async loadOverview() {
        try {
            const response = await fetch('/api/overview');
            const overview = await response.json();
            this.renderOverview(overview);
        } catch (error) {
            console.error('Error loading overview:', error);
        }
    }

    async loadProjects() {
        try {
            console.log('Loading projects...');
            const response = await fetch('/api/reports');
            console.log('Response status:', response.status);
            const projects = await response.json();
            console.log('Projects loaded:', projects);
            this.renderProjectList(projects);
        } catch (error) {
            console.error('Error loading projects:', error);
            document.getElementById('project-list').innerHTML = '<div class="alert alert-danger">Failed to load projects</div>';
        }
    }

    renderProjectList(projects) {
        const projectList = document.getElementById('project-list');
        console.log('Rendering project list:', projects);
        projectList.innerHTML = '';

        if (!projects || projects.length === 0) {
            projectList.innerHTML = '<div class="alert alert-warning">No projects found</div>';
            return;
        }

        projects.forEach(project => {
            const projectItem = document.createElement('a');
            projectItem.className = 'list-group-item list-group-item-action project-item';
            projectItem.textContent = project;
            projectItem.onclick = () => this.selectProject(project);
            projectList.appendChild(projectItem);
        });
        console.log('Project list rendered with', projects.length, 'projects');
    }

    selectProject(projectName) {
        // Update active project styling
        document.querySelectorAll('.project-item').forEach(item => {
            item.classList.remove('active');
        });
        event.target.classList.add('active');

        this.currentProject = projectName;
        document.getElementById('project-title').textContent = `${projectName} - Security Findings`;
        document.getElementById('project-details').classList.remove('d-none');
        document.getElementById('welcome-message').classList.add('d-none');

        this.showSecurityReport();
    }

    async showSecurityReport() {
        this.currentReportType = 'security';
        await this.loadReport(`/api/reports/${this.currentProject}`);
        // Also load reachability data for filtering
        try {
            const reachabilityResponse = await fetch(`/api/reachability/${this.currentProject}`);
            if (reachabilityResponse.ok) {
                this.reachabilityData = await reachabilityResponse.json();
            }
        } catch (error) {
            console.warn('Could not load reachability data for filtering');
        }
        this.generateActionItems();
    }

    async showExploitabilityReport() {
        this.currentReportType = 'exploitability';
        await this.loadReport(`/api/exploitability/${this.currentProject}`);
    }

    async showReachabilityReport() {
        this.currentReportType = 'reachability';
        await this.loadReport(`/api/reachability/${this.currentProject}`);
    }

    async showSBOMReport() {
        this.currentReportType = 'sbom';
        await this.loadReport(`/api/sbom/${this.currentProject}`);
    }

    async showConsolidatedReport() {
        this.currentReportType = 'consolidated';
        await this.loadConsolidatedReport();
    }

    async loadReport(url) {
        const reportContent = document.getElementById('report-content');
        reportContent.innerHTML = '<div class="loading">Loading...</div>';

        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            this.renderReport(data);
        } catch (error) {
            console.error('Error loading report:', error);
            this.showError('Failed to load report');
        }
    }

    async loadConsolidatedReport() {
        const reportContent = document.getElementById('report-content');
        reportContent.innerHTML = '<div class="loading">Loading...</div>';

        try {
            const response = await fetch(`/api/consolidated/${this.currentProject}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            this.renderReport(data);
        } catch (error) {
            console.error('Error loading consolidated report:', error);
            this.showError('Failed to load consolidated report');
        }
    }

    renderReport(data) {
        const reportContent = document.getElementById('report-content');
        
        if (this.currentReportType === 'security' && data.vulnerabilities) {
            this.allVulnerabilities = data.vulnerabilities;
            this.renderSecurityReport(data);
        } else if (this.currentReportType === 'reachability') {
            this.reachabilityData = data;
            this.renderReachabilityReport(data);
        } else if (this.currentReportType === 'exploitability' && data.exploitability_analysis) {
            this.renderExploitabilityReport(data);
        } else if (this.currentReportType === 'sbom') {
            this.renderSBOMReport(data);
        } else {
            this.renderJsonReport(data);
        }
    }

    renderSecurityReport(data) {
        const reportContent = document.getElementById('report-content');
        const vulnerabilities = data.vulnerabilities || [];
        const summary = data.summary || {};
        const severityBreakdown = summary.severity_breakdown || {};
        
        let html = `
            <div class="mb-3">
                <h5>Security Summary</h5>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Total Vulnerabilities:</strong> ${summary.total_vulnerabilities || vulnerabilities.length}</p>
                        <p><strong>Vulnerable Components:</strong> ${summary.vulnerable_components || 'Unknown'}</p>
                        <p><strong>Scan Date:</strong> ${data.scan_timestamp || data.scan_date || 'Unknown'}</p>
                    </div>
                    <div class="col-md-6">
                        <h6>Severity Breakdown:</h6>
                        <div class="d-flex flex-wrap gap-2">
                            ${Object.entries(severityBreakdown).map(([severity, count]) => 
                                `<span class="badge bg-${this.getSeverityColor(severity)} me-1">${severity}: ${count}</span>`
                            ).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;

        if (vulnerabilities.length > 0) {
            html += '<h5>Vulnerabilities</h5>';
            vulnerabilities.forEach(vuln => {
                const severity = vuln.severity || 'unknown';
                const cvssScore = vuln.cvss_score ? ` (CVSS: ${vuln.cvss_score})` : '';
                html += `
                    <div class="vulnerability-item ${severity.toLowerCase()}">
                        <div class="d-flex justify-content-between align-items-start">
                            <h6 style="cursor: pointer; color: #007bff;" onclick="dashboard.showVulnerabilityDetails(this.dataset.vuln)" data-vuln='${JSON.stringify(vuln)}'>${vuln.id || vuln.cve || 'Unknown ID'}</h6>
                            <span class="badge bg-${this.getSeverityColor(severity)} badge-severity">${severity}${cvssScore}</span>
                        </div>
                        <p><strong>Package:</strong> ${vuln.package_name || vuln.package || 'Unknown'} (${vuln.package_version || vuln.version || 'Unknown version'})</p>
                        <p><strong>Title:</strong> ${vuln.title || 'No title available'}</p>
                        <p><strong>Description:</strong> ${vuln.description || 'No description available'}</p>
                        ${vuln.fixed_version ? `<p class="text-success"><strong>Fixed in:</strong> ${vuln.fixed_version}</p>` : ''}
                        ${vuln.cvss_vector ? `<p><strong>CVSS Vector:</strong> <code>${vuln.cvss_vector}</code></p>` : ''}
                    </div>
                `;
            });
        } else {
            html += '<div class="alert alert-success">No vulnerabilities found!</div>';
        }

        reportContent.innerHTML = html;
    }

    renderExploitabilityReport(data) {
        const reportContent = document.getElementById('report-content');
        const analysis = data.exploitability_analysis || {};
        
        let html = `
            <div class="mb-3">
                <h5>Exploitability Analysis</h5>
                <p><strong>Analysis Date:</strong> ${data.analysis_date || 'Unknown'}</p>
            </div>
        `;

        if (analysis.vulnerabilities) {
            html += '<h5>Exploitable Vulnerabilities</h5>';
            analysis.vulnerabilities.forEach(vuln => {
                const exploitability = vuln.exploitability_score || 'Unknown';
                html += `
                    <div class="vulnerability-item">
                        <div class="d-flex justify-content-between align-items-start">
                            <h6>${vuln.cve || vuln.id || 'Unknown ID'}</h6>
                            <span class="badge bg-danger">Score: ${exploitability}</span>
                        </div>
                        <p><strong>Attack Vector:</strong> ${vuln.attack_vector || 'Unknown'}</p>
                        <p><strong>Complexity:</strong> ${vuln.attack_complexity || 'Unknown'}</p>
                        <p><strong>Impact:</strong> ${vuln.impact || 'Unknown'}</p>
                    </div>
                `;
            });
        } else {
            html += '<div class="alert alert-info">No exploitability data available</div>';
        }

        reportContent.innerHTML = html;
    }

    renderJsonReport(data) {
        const reportContent = document.getElementById('report-content');
        reportContent.innerHTML = `
            <div class="report-json">
                <pre>${JSON.stringify(data, null, 2)}</pre>
            </div>
        `;
    }

    getSeverityColor(severity) {
        const colors = {
            'critical': 'danger',
            'high': 'danger',
            'medium': 'warning',
            'low': 'success',
            'info': 'info'
        };
        return colors[severity.toLowerCase()] || 'secondary';
    }

    renderOverview(overview) {
        const overviewStats = document.getElementById('overview-stats');
        const { total_projects, total_vulnerabilities, severity_totals, reachable_vulnerabilities } = overview;
        
        overviewStats.innerHTML = `
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title">${total_projects}</h5>
                        <p class="card-text">Projects</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-danger">${total_vulnerabilities}</h5>
                        <p class="card-text">Total Vulnerabilities</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-warning">${reachable_vulnerabilities}</h5>
                        <p class="card-text">Reachable Vulnerabilities</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title text-danger">${severity_totals.CRITICAL + severity_totals.HIGH}</h5>
                        <p class="card-text">Critical + High</p>
                    </div>
                </div>
            </div>
        `;

        this.renderCharts(overview);
    }

    renderCharts(overview) {
        const { severity_totals, reachable_vulnerabilities, total_vulnerabilities } = overview;

        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        severity_totals.CRITICAL,
                        severity_totals.HIGH,
                        severity_totals.MEDIUM,
                        severity_totals.LOW
                    ],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#28a745'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Reachability Chart
        const reachabilityCtx = document.getElementById('reachabilityChart').getContext('2d');
        new Chart(reachabilityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Reachable', 'Unreachable'],
                datasets: [{
                    data: [
                        reachable_vulnerabilities,
                        total_vulnerabilities - reachable_vulnerabilities
                    ],
                    backgroundColor: [
                        '#dc3545',
                        '#28a745'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    renderReachabilityReport(data) {
        const reportContent = document.getElementById('report-content');
        const reachableVulns = data.reachable_vulnerabilities || [];
        const unreachableVulns = data.unreachable_vulnerabilities || [];
        
        let html = `
            <div class="mb-3">
                <h5>Reachability Analysis</h5>
                <div class="row">
                    <div class="col-md-4">
                        <div class="card text-center">
                            <div class="card-body">
                                <h6 class="text-danger">${reachableVulns.length}</h6>
                                <small>Reachable</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-center">
                            <div class="card-body">
                                <h6 class="text-success">${unreachableVulns.length}</h6>
                                <small>Unreachable</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-center">
                            <div class="card-body">
                                <h6>${data.analysis_timestamp || 'Unknown'}</h6>
                                <small>Last Analysis</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        if (reachableVulns.length > 0) {
            html += '<h5 class="text-danger">🚨 Reachable Vulnerabilities (Priority)</h5>';
            reachableVulns.forEach(vuln => {
                html += this.renderVulnerabilityCard(vuln, true);
            });
        }

        if (unreachableVulns.length > 0) {
            html += '<h5 class="text-success mt-4">✅ Unreachable Vulnerabilities</h5>';
            unreachableVulns.forEach(vuln => {
                html += this.renderVulnerabilityCard(vuln, false);
            });
        }

        reportContent.innerHTML = html;
    }

    renderVulnerabilityCard(vuln, isReachable) {
        const severity = vuln.severity || 'unknown';
        const reachableClass = isReachable ? 'border-danger' : 'border-success';
        const reachableIcon = isReachable ? '🚨' : '✅';
        
        return `
            <div class="vulnerability-item ${severity.toLowerCase()} ${reachableClass}">
                <div class="d-flex justify-content-between align-items-start">
                    <h6>${reachableIcon} ${vuln.cve || vuln.id || 'Unknown ID'}</h6>
                    <div>
                        <span class="badge bg-${this.getSeverityColor(severity)} badge-severity me-1">${severity}</span>
                        <span class="badge ${isReachable ? 'bg-danger' : 'bg-success'}">${isReachable ? 'REACHABLE' : 'SAFE'}</span>
                    </div>
                </div>
                <p><strong>Package:</strong> ${vuln.package_name || vuln.package || 'Unknown'} (${vuln.package_version || 'Unknown'})</p>
                <p><strong>Description:</strong> ${vuln.description || 'No description available'}</p>
                ${vuln.call_path ? `<p><strong>Call Path:</strong> <code>${vuln.call_path.join(' → ')}</code></p>` : ''}
                ${vuln.fixed_version ? `<p class="text-success"><strong>Fixed in:</strong> ${vuln.fixed_version}</p>` : ''}
            </div>
        `;
    }

    renderSBOMReport(data) {
        const reportContent = document.getElementById('report-content');
        const artifacts = data.artifacts || [];
        
        let html = `
            <div class="mb-3">
                <h5>Software Bill of Materials (SBOM)</h5>
                <p><strong>Total Components:</strong> ${artifacts.length}</p>
                <p><strong>Generated:</strong> ${data.descriptor?.timestamp || 'Unknown'}</p>
            </div>
        `;

        if (artifacts.length > 0) {
            html += '<h5>Components</h5>';
            html += '<div class="table-responsive">';
            html += `
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Version</th>
                            <th>Type</th>
                            <th>Language</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            artifacts.forEach(artifact => {
                html += `
                    <tr>
                        <td>${artifact.name || 'Unknown'}</td>
                        <td><code>${artifact.version || 'Unknown'}</code></td>
                        <td><span class="badge bg-secondary">${artifact.type || 'Unknown'}</span></td>
                        <td>${artifact.language || 'Unknown'}</td>
                    </tr>
                `;
            });
            
            html += '</tbody></table></div>';
        }

        reportContent.innerHTML = html;
    }

    applyFilters() {
        if (this.currentReportType !== 'security' || !this.allVulnerabilities.length) return;

        const searchTerm = document.getElementById('search-input').value.toLowerCase();
        const severityFilter = document.getElementById('severity-filter').value;
        const reachabilityFilter = document.getElementById('reachability-filter').value;

        this.filteredVulnerabilities = this.allVulnerabilities.filter(vuln => {
            const matchesSearch = !searchTerm || 
                (vuln.id || '').toLowerCase().includes(searchTerm) ||
                (vuln.package_name || '').toLowerCase().includes(searchTerm) ||
                (vuln.description || '').toLowerCase().includes(searchTerm);

            const matchesSeverity = !severityFilter || vuln.severity === severityFilter;

            let matchesReachability = true;
            if (reachabilityFilter && this.reachabilityData) {
                const reachableVulns = this.reachabilityData.reachable_vulnerabilities || [];
                const isReachable = reachableVulns.some(rv => rv.cve === vuln.id);
                matchesReachability = (reachabilityFilter === 'reachable') ? isReachable : !isReachable;
            }

            return matchesSearch && matchesSeverity && matchesReachability;
        });

        this.renderFilteredVulnerabilities();
    }

    renderFilteredVulnerabilities() {
        const reportContent = document.getElementById('report-content');
        const vulnerabilities = this.filteredVulnerabilities;
        
        let html = `
            <div class="mb-3">
                <h5>Filtered Results (${vulnerabilities.length} vulnerabilities)</h5>
            </div>
        `;

        if (vulnerabilities.length > 0) {
            vulnerabilities.forEach(vuln => {
                const severity = vuln.severity || 'unknown';
                const cvssScore = vuln.cvss_score ? ` (CVSS: ${vuln.cvss_score})` : '';
                html += `
                    <div class="vulnerability-item ${severity.toLowerCase()}">
                        <div class="d-flex justify-content-between align-items-start">
                            <h6 style="cursor: pointer; color: #007bff;" onclick="dashboard.showVulnerabilityDetails(this.dataset.vuln)" data-vuln='${JSON.stringify(vuln)}'>${vuln.id || vuln.cve || 'Unknown ID'}</h6>
                            <span class="badge bg-${this.getSeverityColor(severity)} badge-severity">${severity}${cvssScore}</span>
                        </div>
                        <p><strong>Package:</strong> ${vuln.package_name || vuln.package || 'Unknown'} (${vuln.package_version || vuln.version || 'Unknown version'})</p>
                        <p><strong>Title:</strong> ${vuln.title || 'No title available'}</p>
                        <p><strong>Description:</strong> ${vuln.description || 'No description available'}</p>
                        ${vuln.fixed_version ? `<p class="text-success"><strong>Fixed in:</strong> ${vuln.fixed_version}</p>` : ''}
                        ${vuln.cvss_vector ? `<p><strong>CVSS Vector:</strong> <code>${vuln.cvss_vector}</code></p>` : ''}
                    </div>
                `;
            });
        } else {
            html += '<div class="alert alert-info">No vulnerabilities match the current filters</div>';
        }

        reportContent.innerHTML = html;
    }

    clearFilters() {
        document.getElementById('search-input').value = '';
        document.getElementById('severity-filter').value = '';
        document.getElementById('reachability-filter').value = '';
        this.applyFilters();
    }

    showVulnerabilityDetails(vulnData) {
        const vuln = JSON.parse(vulnData);
        const modalTitle = document.getElementById('modalTitle');
        const modalContent = document.getElementById('modalContent');
        
        modalTitle.textContent = vuln.id || vuln.cve || 'Vulnerability Details';
        
        modalContent.innerHTML = `
            <div class="vulnerability-details">
                <div class="row mb-3">
                    <div class="col-md-6">
                        <p><strong>CVE ID:</strong> ${vuln.id || vuln.cve || 'N/A'}</p>
                        <p><strong>Package:</strong> ${vuln.package_name || 'Unknown'}</p>
                        <p><strong>Version:</strong> ${vuln.package_version || 'Unknown'}</p>
                        <p><strong>Severity:</strong> <span class="badge bg-${this.getSeverityColor(vuln.severity)}">${vuln.severity || 'Unknown'}</span></p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>CVSS Score:</strong> ${vuln.cvss_score || 'N/A'}</p>
                        <p><strong>CVSS Vector:</strong> <code>${vuln.cvss_vector || 'N/A'}</code></p>
                        <p><strong>Fixed Version:</strong> ${vuln.fixed_version || 'No fix available'}</p>
                    </div>
                </div>
                <div class="mb-3">
                    <h6>Description</h6>
                    <p>${vuln.description || 'No description available'}</p>
                </div>
                ${vuln.references ? `
                    <div class="mb-3">
                        <h6>References</h6>
                        <ul>
                            ${vuln.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
        
        new bootstrap.Modal(document.getElementById('vulnerabilityModal')).show();
    }

    showExportModal() {
        new bootstrap.Modal(document.getElementById('exportModal')).show();
    }

    exportVulnerability() {
        // Implementation for single vulnerability export
        console.log('Exporting vulnerability...');
    }

    generateActionItems() {
        if (!this.allVulnerabilities.length || !this.reachabilityData) return;

        const reachableVulns = this.reachabilityData.reachable_vulnerabilities || [];
        const actionItems = [];

        // Priority 1: Reachable Critical/High vulnerabilities
        reachableVulns.forEach(vuln => {
            if (vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH') {
                actionItems.push({
                    priority: 1,
                    action: `Fix ${vuln.cve || vuln.id}`,
                    description: `Reachable ${vuln.severity} vulnerability in ${vuln.package_name}`,
                    package: vuln.package_name,
                    fixVersion: vuln.fixed_version,
                    type: 'critical-reachable'
                });
            }
        });

        // Priority 2: Reachable Medium vulnerabilities
        reachableVulns.forEach(vuln => {
            if (vuln.severity === 'MEDIUM') {
                actionItems.push({
                    priority: 2,
                    action: `Update ${vuln.package_name}`,
                    description: `Reachable medium vulnerability`,
                    package: vuln.package_name,
                    fixVersion: vuln.fixed_version,
                    type: 'medium-reachable'
                });
            }
        });

        // Priority 3: Critical/High unreachable (for monitoring)
        this.allVulnerabilities.forEach(vuln => {
            const isReachable = reachableVulns.some(rv => rv.cve === vuln.id);
            if (!isReachable && (vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH')) {
                actionItems.push({
                    priority: 3,
                    action: `Monitor ${vuln.id}`,
                    description: `Unreachable but severe vulnerability`,
                    package: vuln.package_name,
                    fixVersion: vuln.fixed_version,
                    type: 'monitor'
                });
            }
        });

        this.renderActionItems(actionItems.slice(0, 10)); // Show top 10
    }

    renderActionItems(actionItems) {
        const panel = document.getElementById('action-items-panel');
        const content = document.getElementById('action-items-content');
        
        if (actionItems.length === 0) {
            panel.style.display = 'none';
            return;
        }

        panel.style.display = 'block';
        
        let html = '';
        actionItems.forEach((item, index) => {
            const priorityClass = item.priority === 1 ? 'danger' : item.priority === 2 ? 'warning' : 'info';
            const priorityIcon = item.priority === 1 ? '🚨' : item.priority === 2 ? '⚠️' : '👁️';
            
            html += `
                <div class="alert alert-${priorityClass} d-flex justify-content-between align-items-center">
                    <div>
                        <strong>${priorityIcon} ${item.action}</strong><br>
                        <small>${item.description}</small>
                        ${item.fixVersion ? `<br><small class="text-success">Fix available: ${item.fixVersion}</small>` : ''}
                    </div>
                    <span class="badge bg-${priorityClass}">P${item.priority}</span>
                </div>
            `;
        });
        
        content.innerHTML = html;
    }

    performExport() {
        const format = document.getElementById('export-format').value;
        const includeReachable = document.getElementById('include-reachable').checked;
        const includeUnreachable = document.getElementById('include-unreachable').checked;
        
        // Implementation for bulk export
        console.log('Performing export...', { format, includeReachable, includeUnreachable });
        
        // Close modal
        bootstrap.Modal.getInstance(document.getElementById('exportModal')).hide();
    }

    showError(message) {
        const reportContent = document.getElementById('report-content');
        reportContent.innerHTML = `<div class="error">${message}</div>`;
    }
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new SecurityDashboard();
});
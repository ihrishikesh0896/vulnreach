/**
 * VulnReach Security Dashboard Application
 * A responsive single-page application for viewing security project findings
 */

class SecurityDashboard {
    constructor() {
        this.projects = [];
        this.filteredProjects = [];
        this.currentPage = 1;
        this.pageSize = 10;
        this.currentView = 'list';
        this.sortBy = 'name';
        this.sortDirection = 'asc';
        this.searchTerm = '';
        this.statusFilter = '';

        // Initialize the application
        this.init();
    }

    /**
     * Initialize the dashboard
     */
    async init() {
        try {
            // Show loading overlay
            this.showLoading(true);

            // Load project data
            await this.loadProjects();

            // Setup event listeners
            this.setupEventListeners();

            // Initial render
            this.filterAndRender();

            // Hide loading overlay
            this.showLoading(false);

            // Set focus to search input for accessibility
            document.getElementById('searchInput').focus();

        } catch (error) {
            console.error('Failed to initialize dashboard:', error);
            this.showError('Failed to load project data. Please try again.');
            this.showLoading(false);
        }
    }

    /**
     * Load and normalize project data from all JSON files
     */
    async loadProjects() {
        try {
            // Fetch the list of projects from the API
            const response = await fetch('/api/projects');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            const projectList = data.projects || [];

            // Load detailed data for each project
            const projectPromises = projectList.map(async (project) => {
                try {
                    return await this.loadProjectDetails(project);
                } catch (error) {
                    console.warn(`Failed to load details for project ${project.name}:`, error);
                    return this.createFallbackProject(project);
                }
            });

            const projects = await Promise.all(projectPromises);
            this.projects = projects.filter(project => project !== null);

            console.log(`Loaded ${this.projects.length} projects`);

        } catch (error) {
            console.error('Error loading projects:', error);
            // Create sample data for development
            this.projects = this.createSampleProjects();
        }
    }

    /**
     * Load detailed information for a single project
     */
    async loadProjectDetails(project) {
        try {
            // Normalize project data structure
            const normalizedProject = {
                id: project.name,
                name: project.name,
                language: project.language || 'Unknown',
                description: `Security analysis for ${project.name}`,
                status: 'active',
                severity: 'medium',
                tags: [project.language].filter(Boolean),
                created: new Date().toISOString(),
                updated: new Date().toISOString(),
                files: project.files || {},
                vulnerabilities: [],
                reachability: null,
                exploitability: null,
                consolidated: null,
                security_report: null,
                raw_data: project
            };

            // Load reachability report if available
            if (project.files?.reachability_report) {
                try {
                    const reachResponse = await fetch(`/api/report/${encodeURIComponent(project.name)}`);
                    if (reachResponse.ok) {
                        const reachData = await reachResponse.json();
                        normalizedProject.reachability = reachData;
                        normalizedProject.vulnerabilities = (reachData.vulnerabilities || []).map(vuln => ({
                            ...vuln,
                            reachability_status: vuln.reachability_status || (vuln.is_used ? 'REACHABLE' : 'NOT_REACHABLE')
                        }));

                        console.log(`Loaded ${normalizedProject.vulnerabilities.length} vulnerabilities for ${project.name}`);

                        // Determine severity from reachability data
                        const summary = reachData.summary || {};
                        if (summary.critical_reachable > 0) {
                            normalizedProject.severity = 'critical';
                            normalizedProject.status = 'critical';
                        } else if (summary.high_reachable > 0) {
                            normalizedProject.severity = 'high';
                            normalizedProject.status = 'active';
                        } else if (summary.medium_reachable > 0) {
                            normalizedProject.severity = 'medium';
                        } else if (summary.low_reachable > 0) {
                            normalizedProject.severity = 'low';
                        }

                        // Update description with vulnerability counts
                        const total = summary.total_vulnerabilities || 0;
                        const reachable = (summary.critical_reachable || 0) +
                                        (summary.high_reachable || 0) +
                                        (summary.medium_reachable || 0) +
                                        (summary.low_reachable || 0);
                        normalizedProject.description = `${total} vulnerabilities found, ${reachable} reachable`;

                        // Add vulnerability-related tags
                        if (reachable > 0) {
                            normalizedProject.tags.push('vulnerable', 'reachable');
                        }
                        if (summary.not_reachable > 0) {
                            normalizedProject.tags.push('safe');
                        }
                    }
                } catch (error) {
                    console.warn(`Failed to load reachability for ${project.name}:`, error);
                }
            }

            // Load exploitability data if available
            if (project.files?.exploitability) {
                try {
                    const exploitResponse = await fetch(`/api/exploitability/${encodeURIComponent(project.name)}`);
                    if (exploitResponse.ok) {
                        const exploitData = await exploitResponse.json();
                        normalizedProject.exploitability = exploitData;

                        // Add exploit-related tags
                        if (exploitData.vulnerability_analyses?.some(v => v.exploit_count > 0)) {
                            normalizedProject.tags.push('exploitable');
                            if (normalizedProject.severity === 'low') {
                                normalizedProject.severity = 'medium';
                            }
                        }
                    }
                } catch (error) {
                    console.warn(`Failed to load exploitability for ${project.name}:`, error);
                }
            }

            // Load consolidated data if available
            if (project.files?.consolidated) {
                try {
                    const consolidatedResponse = await fetch(`/api/consolidated/${encodeURIComponent(project.name)}`);
                    if (consolidatedResponse.ok) {
                        const consolidatedData = await consolidatedResponse.json();
                        normalizedProject.consolidated = consolidatedData;

                        // Add upgrade information
                        if (Array.isArray(consolidatedData)) {
                            const upgradesNeeded = consolidatedData.filter(item => item.upgrade_needed).length;
                            if (upgradesNeeded > 0) {
                                normalizedProject.tags.push('needs-update');
                                normalizedProject.description += `, ${upgradesNeeded} packages need updates`;
                            }
                        }
                    }
                } catch (error) {
                    console.warn(`Failed to load consolidated data for ${project.name}:`, error);
                }
            }

            // Load security report if available
            if (project.files?.security_report) {
                try {
                    const securityResponse = await fetch(`/api/security/${encodeURIComponent(project.name)}`);
                    if (securityResponse.ok) {
                        const securityData = await securityResponse.json();
                        normalizedProject.security_report = securityData;

                        // Update timestamps from security report
                        if (securityData.scan_timestamp) {
                            normalizedProject.updated = securityData.scan_timestamp;
                        }
                    }
                } catch (error) {
                    console.warn(`Failed to load security report for ${project.name}:`, error);
                }
            }

            return normalizedProject;

        } catch (error) {
            console.error(`Error loading project details for ${project.name}:`, error);
            return this.createFallbackProject(project);
        }
    }

    /**
     * Create a fallback project when detailed loading fails
     */
    createFallbackProject(project) {
        return {
            id: project.name,
            name: project.name,
            language: project.language || 'Unknown',
            description: `Security project: ${project.name}`,
            status: 'pending',
            severity: 'unknown',
            tags: [project.language].filter(Boolean),
            created: new Date().toISOString(),
            updated: new Date().toISOString(),
            files: project.files || {},
            vulnerabilities: [],
            raw_data: project
        };
    }

    /**
     * Create sample projects for development/testing
     */
    createSampleProjects() {
        return [
            {
                id: 'sample-1',
                name: 'Sample Vulnerable App',
                description: 'A sample application with known vulnerabilities for testing',
                status: 'critical',
                severity: 'critical',
                tags: ['python', 'web', 'vulnerable'],
                created: '2024-01-15T10:30:00Z',
                updated: '2024-01-20T15:45:00Z',
                vulnerabilities: [
                    { id: 'CVE-2024-0001', severity: 'CRITICAL', description: 'Remote code execution' }
                ]
            },
            {
                id: 'sample-2',
                name: 'Secure Library',
                description: 'A well-maintained security library with regular updates',
                status: 'active',
                severity: 'low',
                tags: ['java', 'library', 'secure'],
                created: '2024-01-10T08:00:00Z',
                updated: '2024-01-22T12:30:00Z',
                vulnerabilities: []
            }
        ];
    }

    /**
     * Setup event listeners for UI interactions
     */
    setupEventListeners() {
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        searchInput.addEventListener('input', this.debounce((e) => {
            this.searchTerm = e.target.value;
            this.currentPage = 1;
            this.filterAndRender();
        }, 300));

        // Clear search
        document.getElementById('clearSearch').addEventListener('click', () => {
            searchInput.value = '';
            this.searchTerm = '';
            this.currentPage = 1;
            this.filterAndRender();
            searchInput.focus();
        });

        // Status filter
        document.getElementById('statusFilter').addEventListener('change', (e) => {
            this.statusFilter = e.target.value;
            this.currentPage = 1;
            this.filterAndRender();
        });

        // Sort selection
        document.getElementById('sortSelect').addEventListener('change', (e) => {
            this.sortBy = e.target.value;
            this.filterAndRender();
        });


        // Page size selection
        document.querySelectorAll('input[name="pageSize"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.pageSize = parseInt(e.target.value);
                this.currentPage = 1;
                this.filterAndRender();
            });
        });

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === '/' && !e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                searchInput.focus();
            }
        });

        // Copy JSON functionality
        document.getElementById('copyJsonBtn').addEventListener('click', () => {
            this.copyJsonToClipboard();
        });

        // Table header sorting
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-sort]')) {
                const sortBy = e.target.getAttribute('data-sort');
                if (this.sortBy === sortBy) {
                    this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortBy = sortBy;
                    this.sortDirection = 'asc';
                }
                this.filterAndRender();
            }
        });
    }

    // Always using list view

    /**
     * Filter and render projects based on current criteria
     */
    filterAndRender() {
        // Apply filters
        this.filteredProjects = this.projects.filter(project => {
            // Text search
            if (this.searchTerm) {
                const searchLower = this.searchTerm.toLowerCase();
                const matchesSearch =
                    project.name.toLowerCase().includes(searchLower) ||
                    project.description.toLowerCase().includes(searchLower) ||
                    project.tags.some(tag => tag.toLowerCase().includes(searchLower));

                if (!matchesSearch) return false;
            }

            // Status filter
            if (this.statusFilter && project.status !== this.statusFilter) {
                return false;
            }

            return true;
        });

        // Sort projects
        this.sortProjects();

        // Render results
        this.renderProjects();
        this.renderPagination();
        this.updateResultsInfo();
    }

    /**
     * Sort projects based on current criteria
     */
    sortProjects() {
        this.filteredProjects.sort((a, b) => {
            let aValue, bValue;

            switch (this.sortBy) {
                case 'name':
                    aValue = a.name.toLowerCase();
                    bValue = b.name.toLowerCase();
                    break;
                case 'updated':
                    aValue = new Date(a.updated);
                    bValue = new Date(b.updated);
                    break;
                case 'created':
                    aValue = new Date(a.created);
                    bValue = new Date(b.created);
                    break;
                case 'severity':
                    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
                    aValue = severityOrder[a.severity] || 0;
                    bValue = severityOrder[b.severity] || 0;
                    break;
                default:
                    aValue = a.name.toLowerCase();
                    bValue = b.name.toLowerCase();
            }

            if (aValue < bValue) return this.sortDirection === 'asc' ? -1 : 1;
            if (aValue > bValue) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
    }

    /**
     * Render projects in the current view
     */
    renderProjects() {
        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = startIndex + this.pageSize;
        const pageProjects = this.filteredProjects.slice(startIndex, endIndex);

        if (this.currentView === 'grid') {
            this.renderProjectCards(pageProjects);
        } else {
            this.renderProjectTable(pageProjects);
        }

        // Show/hide no results message
        const noResults = document.getElementById('noResults');
        if (this.filteredProjects.length === 0) {
            noResults.classList.remove('d-none');
        } else {
            noResults.classList.add('d-none');
        }
    }

    /**
     * Render projects
     */
    renderProjects() {
        // Get current page projects
        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = startIndex + this.pageSize;
        const currentPageProjects = this.filteredProjects.slice(startIndex, endIndex);

        this.renderProjectTable(currentPageProjects);
    }

    /**
     * Render projects in table view
     */
    renderProjectTable(projects) {
        const tbody = document.getElementById('projectsTableBody');

        if (projects.length === 0) {
            tbody.innerHTML = '';
            return;
        }

        tbody.innerHTML = projects.map(project => `
            <tr tabindex="0"
                role="button"
                aria-label="View details for ${this.escapeHtml(project.name)}"
                data-project-id="${project.id}"
                onclick="dashboard.showProjectModal('${project.id}')"
                onkeydown="if(event.key==='Enter'||event.key===' '){dashboard.showProjectModal('${project.id}');event.preventDefault()}">
                <td>
                    <strong>${this.highlightSearch(this.escapeHtml(project.name))}</strong>
                    <br>
                    <small class="text-muted">${this.escapeHtml(project.language)}</small>
                </td>
                <td>${this.highlightSearch(this.escapeHtml(this.truncateText(project.description, 80)))}</td>
                <td>
                    <span class="badge status-badge status-${project.severity}">
                        ${project.severity.toUpperCase()}
                    </span>
                </td>
                <td>
                    <small>${this.formatDate(project.updated)}</small>
                </td>
                <td>
                    ${project.tags.slice(0, 3).map(tag => `
                        <span class="tag-pill">${this.escapeHtml(tag)}</span>
                    `).join('')}
                    ${project.tags.length > 3 ? `<span class="tag-pill">+${project.tags.length - 3}</span>` : ''}
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-primary"
                            onclick="event.stopPropagation(); dashboard.showProjectModal('${project.id}')"
                            aria-label="View details for ${this.escapeHtml(project.name)}">
                        <i class="material-icons" aria-hidden="true" style="font-size: 16px;">visibility</i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    /**
     * Render pagination controls
     */
    renderPagination() {
        const totalPages = Math.ceil(this.filteredProjects.length / this.pageSize);
        const pagination = document.getElementById('pagination');

        if (totalPages <= 1) {
            pagination.innerHTML = '';
            return;
        }

        let paginationHTML = '';

        // Previous button
        paginationHTML += `
            <li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}">
                <button class="page-link border-0 bg-transparent"
                        onclick="dashboard.goToPage(${this.currentPage - 1})"
                        ${this.currentPage === 1 ? 'disabled' : ''}
                        aria-label="Previous page">
                    <i class="material-icons" style="font-size: 16px;" aria-hidden="true">chevron_left</i>
                </button>
            </li>
        `;

        // Page numbers
        const startPage = Math.max(1, this.currentPage - 2);
        const endPage = Math.min(totalPages, this.currentPage + 2);

        if (startPage > 1) {
            paginationHTML += `
                <li class="page-item">
                    <button class="page-link" onclick="dashboard.goToPage(1)" aria-label="Page 1">1</button>
                </li>
            `;
            if (startPage > 2) {
                paginationHTML += '<li class="page-item disabled"><span class="page-link">...</span></li>';
            }
        }

        for (let i = startPage; i <= endPage; i++) {
            paginationHTML += `
                <li class="page-item ${i === this.currentPage ? 'active' : ''}">
                    <button class="page-link border-0 bg-transparent"
                            onclick="dashboard.goToPage(${i})"
                            aria-label="Page ${i}"
                            ${i === this.currentPage ? 'aria-current="page"' : ''}>${i}</button>
                </li>
            `;
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                paginationHTML += '<li class="page-item disabled"><span class="page-link">...</span></li>';
            }
            paginationHTML += `
                <li class="page-item">
                    <button class="page-link" onclick="dashboard.goToPage(${totalPages})" aria-label="Page ${totalPages}">${totalPages}</button>
                </li>
            `;
        }

        // Next button
        paginationHTML += `
            <li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}">
                <button class="page-link border-0 bg-transparent"
                        onclick="dashboard.goToPage(${this.currentPage + 1})"
                        ${this.currentPage === totalPages ? 'disabled' : ''}
                        aria-label="Next page">
                    <i class="material-icons" style="font-size: 16px;" aria-hidden="true">chevron_right</i>
                </button>
            </li>
        `;

        pagination.innerHTML = paginationHTML;
    }

    /**
     * Navigate to a specific page
     */
    goToPage(page) {
        const totalPages = Math.ceil(this.filteredProjects.length / this.pageSize);
        if (page >= 1 && page <= totalPages) {
            this.currentPage = page;
            this.renderProjects();
            this.renderPagination();

            // Scroll to top for better UX
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }

    /**
     * Update results information
     */
    updateResultsInfo() {
        const resultsInfo = document.getElementById('resultsInfo');
        const start = (this.currentPage - 1) * this.pageSize + 1;
        const end = Math.min(this.currentPage * this.pageSize, this.filteredProjects.length);
        const total = this.filteredProjects.length;

        if (total === 0) {
            resultsInfo.textContent = 'No projects found';
        } else if (total === 1) {
            resultsInfo.textContent = 'Showing 1 project';
        } else if (total <= this.pageSize) {
            resultsInfo.textContent = `Showing ${total} projects`;
        } else {
            resultsInfo.textContent = `Showing ${start}-${end} of ${total} projects`;
        }
    }

    /**
     * Show project detail modal
     */
    showProjectModal(projectId) {
        const project = this.projects.find(p => p.id === projectId);
        if (!project) return;

        // Set modal title
        document.getElementById('projectModalLabel').textContent = project.name;

        // Populate overview tab
        this.renderProjectOverview(project);

        // Populate vulnerabilities tab
        this.renderProjectVulnerabilities(project);

        // Populate raw data tab
        this.renderRawData(project);

        // Update project link
        const projectLink = document.getElementById('projectLink');
        if (project.link) {
            projectLink.href = project.link;
            projectLink.classList.remove('d-none');
        } else {
            projectLink.classList.add('d-none');
        }

        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('projectModal'));
        modal.show();
    }

    /**
     * Render project overview in modal
     */
    renderProjectOverview(project) {
        const overview = document.getElementById('projectOverview');

        // Build vulnerability summary cards if available
        let vulnerabilitySummary = '';
        if (project.reachability?.summary) {
            const summary = project.reachability.summary;
            const total = summary.total_vulnerabilities || 0;
            const reachable = (summary.critical_reachable || 0) +
                            (summary.high_reachable || 0) +
                            (summary.medium_reachable || 0) +
                            (summary.low_reachable || 0);
            const unreachable = summary.not_reachable || 0;

            vulnerabilitySummary = `
                <div class="row g-3 mb-4">
                    <div class="col-12">
                        <div class="card border-0 bg-light">
                            <div class="card-header bg-transparent border-0 pb-0">
                                <h6 class="mb-0"><i class="material-icons align-middle me-2">security</i>Security Summary</h6>
                            </div>
                            <div class="card-body pt-3">
                                <div class="row g-3">
                                    <div class="col-md-4">
                                        <div class="d-flex align-items-center">
                                            <div class="me-3">
                                                <div class="rounded-circle bg-primary bg-opacity-10 p-2">
                                                    <i class="material-icons text-primary">assessment</i>
                                                </div>
                                            </div>
                                            <div>
                                                <div class="fs-4 fw-bold text-dark">${total}</div>
                                                <div class="small text-muted">Total Vulnerabilities</div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="d-flex align-items-center">
                                            <div class="me-3">
                                                <div class="rounded-circle bg-danger bg-opacity-10 p-2">
                                                    <i class="material-icons text-danger">warning</i>
                                                </div>
                                            </div>
                                            <div>
                                                <div class="fs-4 fw-bold text-danger">${reachable}</div>
                                                <div class="small text-muted">Reachable</div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="d-flex align-items-center">
                                            <div class="me-3">
                                                <div class="rounded-circle bg-success bg-opacity-10 p-2">
                                                    <i class="material-icons text-success">shield</i>
                                                </div>
                                            </div>
                                            <div>
                                                <div class="fs-4 fw-bold text-success">${unreachable}</div>
                                                <div class="small text-muted">Unreachable</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="row mt-3">
                                    <div class="col-12">
                                        <div class="small text-muted mb-2">Reachable by Severity</div>
                                        <div class="d-flex flex-wrap gap-2">
                                            <span class="badge status-critical px-2 py-1">Critical: ${summary.critical_reachable || 0}</span>
                                            <span class="badge status-high px-2 py-1">High: ${summary.high_reachable || 0}</span>
                                            <span class="badge status-medium px-2 py-1">Medium: ${summary.medium_reachable || 0}</span>
                                            <span class="badge status-low px-2 py-1">Low: ${summary.low_reachable || 0}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        overview.innerHTML = `
            ${vulnerabilitySummary}

            <div class="row g-3">
                <div class="col-md-8">
                    <div class="card border-0 shadow-sm">
                        <div class="card-header bg-white border-0 pb-0">
                            <h6 class="mb-0"><i class="material-icons align-middle me-2">info</i>Project Details</h6>
                        </div>
                        <div class="card-body pt-3">
                            <div class="row g-3">
                                <div class="col-sm-6">
                                    <div class="mb-3">
                                        <label class="small text-muted mb-1">Project Name</label>
                                        <div class="fw-medium">${this.escapeHtml(project.name)}</div>
                                    </div>
                                </div>
                                <div class="col-sm-6">
                                    <div class="mb-3">
                                        <label class="small text-muted mb-1">Language</label>
                                        <div class="fw-medium">
                                            <i class="material-icons align-middle me-1" style="font-size: 16px;">code</i>
                                            ${this.escapeHtml(project.language)}
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="mb-3">
                                        <label class="small text-muted mb-1">Description</label>
                                        <div class="text-dark">${this.escapeHtml(project.description)}</div>
                                    </div>
                                </div>
                                <div class="col-sm-6">
                                    <div class="mb-3">
                                        <label class="small text-muted mb-1">Status</label>
                                        <div><span class="badge status-${project.status} px-3 py-2">${project.status.toUpperCase()}</span></div>
                                    </div>
                                </div>
                                <div class="col-sm-6">
                                    <div class="mb-3">
                                        <label class="small text-muted mb-1">Risk Level</label>
                                        <div><span class="badge status-${project.severity} px-3 py-2">${project.severity.toUpperCase()}</span></div>
                                    </div>
                                </div>
                                <div class="col-sm-6">
                                    <div class="mb-3">
                                        <label class="small text-muted mb-1">Last Updated</label>
                                        <div class="fw-medium">
                                            <i class="material-icons align-middle me-1" style="font-size: 16px;">schedule</i>
                                            ${this.formatDate(project.updated)}
                                        </div>
                                    </div>
                                </div>
                                <div class="col-sm-6">
                                    <div class="mb-3">
                                        <label class="small text-muted mb-1">Tags</label>
                                        <div class="d-flex flex-wrap gap-1">
                                            ${project.tags.map(tag => `<span class="tag-pill">${this.escapeHtml(tag)}</span>`).join('')}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card border-0 shadow-sm">
                        <div class="card-header bg-white border-0 pb-0">
                            <h6 class="mb-0"><i class="material-icons align-middle me-2">assignment</i>Available Reports</h6>
                        </div>
                        <div class="card-body pt-3">
                            <div class="d-grid gap-2">
                                ${project.files?.reachability_report ? `
                                    <div class="d-flex align-items-center p-2 bg-success bg-opacity-10 rounded">
                                        <i class="material-icons text-success me-2">check_circle</i>
                                        <span class="text-success fw-medium">Reachability Analysis</span>
                                    </div>
                                ` : `
                                    <div class="d-flex align-items-center p-2 bg-light rounded">
                                        <i class="material-icons text-muted me-2">radio_button_unchecked</i>
                                        <span class="text-muted">Reachability Analysis</span>
                                    </div>
                                `}

                                ${project.files?.exploitability ? `
                                    <div class="d-flex align-items-center p-2 bg-success bg-opacity-10 rounded">
                                        <i class="material-icons text-success me-2">check_circle</i>
                                        <span class="text-success fw-medium">Exploitability Report</span>
                                    </div>
                                ` : `
                                    <div class="d-flex align-items-center p-2 bg-light rounded">
                                        <i class="material-icons text-muted me-2">radio_button_unchecked</i>
                                        <span class="text-muted">Exploitability Report</span>
                                    </div>
                                `}

                                ${project.files?.consolidated ? `
                                    <div class="d-flex align-items-center p-2 bg-success bg-opacity-10 rounded">
                                        <i class="material-icons text-success me-2">check_circle</i>
                                        <span class="text-success fw-medium">Consolidated Report</span>
                                    </div>
                                ` : `
                                    <div class="d-flex align-items-center p-2 bg-light rounded">
                                        <i class="material-icons text-muted me-2">radio_button_unchecked</i>
                                        <span class="text-muted">Consolidated Report</span>
                                    </div>
                                `}

                                ${project.files?.security_report ? `
                                    <div class="d-flex align-items-center p-2 bg-success bg-opacity-10 rounded">
                                        <i class="material-icons text-success me-2">check_circle</i>
                                        <span class="text-success fw-medium">Security Report</span>
                                    </div>
                                ` : `
                                    <div class="d-flex align-items-center p-2 bg-light rounded">
                                        <i class="material-icons text-muted me-2">radio_button_unchecked</i>
                                        <span class="text-muted">Security Report</span>
                                    </div>
                                `}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render project vulnerabilities in modal
     */
    renderProjectVulnerabilities(project) {
        const vulnerabilities = document.getElementById('projectVulnerabilities');

        console.log('renderProjectVulnerabilities called for:', project.name);
        console.log('Vulnerabilities count:', project.vulnerabilities ? project.vulnerabilities.length : 'undefined');
        console.log('Vulnerabilities data:', project.vulnerabilities);

        if (!project.vulnerabilities || project.vulnerabilities.length === 0) {
            vulnerabilities.innerHTML = `
                <div class="text-center py-5">
                    <i class="material-icons text-success" style="font-size: 3rem;">verified</i>
                    <h5 class="mt-3">No Vulnerabilities Found</h5>
                    <p class="text-muted">This project appears to be secure.</p>
                    <div class="mt-3">
                        <small class="text-muted">
                            Debug: Project has ${project.vulnerabilities ? project.vulnerabilities.length : 'undefined'} vulnerabilities
                        </small>
                    </div>
                </div>
            `;
            return;
        }

        let sortedVulns;
        try {
            const severityOrder = ['critical', 'high', 'medium', 'low', 'unknown'];
            sortedVulns = project.vulnerabilities.sort((a, b) => {
                const aSev = (a.criticality || a.severity || 'unknown').toLowerCase();
                const bSev = (b.criticality || b.severity || 'unknown').toLowerCase();
                return severityOrder.indexOf(aSev) - severityOrder.indexOf(bSev);
            });
        } catch (error) {
            console.error('Error sorting vulnerabilities:', error);
            sortedVulns = project.vulnerabilities;
        }

        try {
            vulnerabilities.innerHTML = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h6 class="mb-0">Vulnerability Details</h6>
                    <div class="badge bg-light text-dark px-3 py-2">
                        ${project.vulnerabilities.length} vulnerabilities found
                    </div>
                </div>
                <div class="vulnerabilities-list">
                    ${sortedVulns.map(vuln => {
                    const severity = (vuln.criticality || vuln.severity || 'unknown').toLowerCase();
                    const reachabilityStatus = vuln.reachability_status || (vuln.is_used ? 'REACHABLE' : 'NOT_REACHABLE');
                    const isReachable = vuln.is_used || reachabilityStatus.toUpperCase().includes('REACHABLE');

                    return `
                        <div class="card vuln-card ${severity} mb-3">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start mb-3">
                                    <div>
                                        <h6 class="card-title mb-1">${this.escapeHtml(vuln.package_name || 'Unknown Package')}</h6>
                                        <small class="text-muted">
                                            ${this.escapeHtml(vuln.installed_version || 'Unknown version')}
                                            ${vuln.recommended_version ? ` → ${this.escapeHtml(vuln.recommended_version)}` : ''}
                                        </small>
                                    </div>
                                    <div class="text-end">
                                        <span class="badge status-${severity} mb-1">
                                            ${(vuln.criticality || vuln.severity || 'UNKNOWN').toUpperCase()}
                                        </span>
                                        <br>
                                        <span class="badge ${isReachable ? 'bg-danger' : 'bg-success'} text-white">
                                            ${reachabilityStatus}
                                        </span>
                                    </div>
                                </div>

                                ${vuln.usage_details && vuln.usage_details.total_usages > 0 ? `
                                    <div class="row g-2 mb-3">
                                        <div class="col-sm-4">
                                            <div class="text-center p-2 bg-light rounded">
                                                <div class="fw-bold text-primary">${vuln.usage_details.total_usages}</div>
                                                <small class="text-muted">Total Usages</small>
                                            </div>
                                        </div>
                                        <div class="col-sm-4">
                                            <div class="text-center p-2 bg-light rounded">
                                                <div class="fw-bold text-primary">${vuln.usage_details.files_affected || 0}</div>
                                                <small class="text-muted">Files Affected</small>
                                            </div>
                                        </div>
                                        <div class="col-sm-4">
                                            <div class="text-center p-2 bg-light rounded">
                                                <div class="fw-bold ${isReachable ? 'text-danger' : 'text-success'}">
                                                    ${isReachable ? 'HIGH' : 'LOW'}
                                                </div>
                                                <small class="text-muted">Risk Level</small>
                                            </div>
                                        </div>
                                    </div>
                                ` : ''}

                                ${vuln.risk_reason ? `
                                    <div class="alert alert-info py-2 mb-0">
                                        <small><strong>Analysis:</strong> ${this.escapeHtml(vuln.risk_reason)}</small>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    `;
                    }).join('')}
                </div>
            `;
        } catch (error) {
            console.error('Error rendering vulnerabilities:', error);
            vulnerabilities.innerHTML = `
                <div class="alert alert-warning">
                    <h6>Error Loading Vulnerabilities</h6>
                    <p>There was an issue loading the vulnerability details. Please check the browser console for more information.</p>
                    <small>Error: ${error.message}</small>
                </div>
            `;
        }
    }

    /**
     * Render raw JSON data in modal
     */
    renderRawData(project) {
        const rawData = document.getElementById('rawJsonData');

        // Clean up the project data for display
        const cleanedProject = {
            id: project.id,
            name: project.name,
            language: project.language,
            description: project.description,
            status: project.status,
            severity: project.severity,
            tags: project.tags,
            created: project.created,
            updated: project.updated,
            files: project.files,
            vulnerabilities: project.vulnerabilities,
            reachability: project.reachability,
            exploitability: project.exploitability,
            consolidated: project.consolidated,
            security_report: project.security_report
        };

        rawData.textContent = JSON.stringify(cleanedProject, null, 2);
    }

    /**
     * Copy JSON data to clipboard
     */
    async copyJsonToClipboard() {
        try {
            const jsonData = document.getElementById('rawJsonData').textContent;
            await navigator.clipboard.writeText(jsonData);

            // Show success toast
            const toast = new bootstrap.Toast(document.getElementById('copyToast'));
            toast.show();
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
        }
    }

    /**
     * Show/hide loading overlay
     */
    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        overlay.style.display = show ? 'flex' : 'none';
    }

    /**
     * Show error message
     */
    showError(message) {
        // You could implement a more sophisticated error display here
        console.error(message);
        alert(message);
    }

    /**
     * Utility function to debounce function calls
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (typeof text !== 'string') return text;
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Truncate text to specified length
     */
    truncateText(text, maxLength) {
        if (typeof text !== 'string') return text;
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    /**
     * Highlight search terms in text
     */
    highlightSearch(text) {
        if (!this.searchTerm || typeof text !== 'string') return text;

        const regex = new RegExp(`(${this.escapeHtml(this.searchTerm)})`, 'gi');
        return text.replace(regex, '<span class="search-highlight">$1</span>');
    }

    /**
     * Format date for display
     */
    formatDate(dateString) {
        if (!dateString) return 'Unknown';

        try {
            const date = new Date(dateString);
            const now = new Date();
            const diffTime = now - date;
            const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

            if (diffDays === 0) {
                return 'Today';
            } else if (diffDays === 1) {
                return 'Yesterday';
            } else if (diffDays < 7) {
                return `${diffDays} days ago`;
            } else if (diffDays < 30) {
                return `${Math.floor(diffDays / 7)} weeks ago`;
            } else {
                return date.toLocaleDateString();
            }
        } catch (error) {
            return 'Invalid date';
        }
    }
}

// Initialize the dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SecurityDashboard();
});

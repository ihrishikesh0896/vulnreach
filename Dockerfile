# Multi-stage build for VulnReach
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install system dependencies needed for building and external tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Syft for SBOM generation
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy for vulnerability scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy external tools from builder stage
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy

# Copy the installed package from builder stage  
COPY --from=builder /app /app
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=builder /usr/local/bin/vulnreach /usr/local/bin/vulnreach
COPY --from=builder /usr/local/bin/vulnreach-scan /usr/local/bin/vulnreach-scan

# Create non-root user for security
RUN groupadd -r vulnreach && useradd -r -g vulnreach vulnreach
RUN chown -R vulnreach:vulnreach /app
USER vulnreach

# Create directory for scan results
RUN mkdir -p /app/security_findings

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/usr/local/bin:${PATH}"

# Expose volume for scanning external projects
VOLUME ["/scan"]

# Set default working directory for scans
WORKDIR /scan

# Default command
ENTRYPOINT ["vulnreach"]
CMD ["--help"]
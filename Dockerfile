FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Base OS deps and security scanners used by VulnReach
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install Syft + Trivy (required by SBOM/SCA phases)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Copy package metadata first for better layer caching
COPY requirements.txt pyproject.toml README.md MANIFEST.in ./
COPY src ./src
COPY run_vulnreach.py ./
COPY runtime_hooks ./runtime_hooks

# Install Python dependencies and package
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt \
    && python -m pip install .

# Run as non-root by default
RUN useradd --create-home --uid 10001 vulnreach \
    && chown -R vulnreach:vulnreach /app
USER vulnreach

ENTRYPOINT ["vulnreach"]
CMD ["--help"]

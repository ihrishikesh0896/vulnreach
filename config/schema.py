from pathlib import Path
from typing import List, Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator


class EbpfSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # "openat" traces file-open syscalls (portable, no USDT needed).
    # "usdt"   uses Python USDT probes (requires Python built with --with-dtrace).
    mode: str = "openat"
    # "bpftrace" or "bcc" — whichever is installed on the host.
    tracer: str = "bpftrace"
    # sidecar_mode: inject a privileged sidecar container instead of patching
    # the Dockerfile.  Non-invasive — requires docker-compose-based target.
    sidecar_mode: bool = False
    # kernel_check: log advisory warnings when kernel version < minimum for eBPF.
    # Never blocks execution — set false to suppress the warnings.
    kernel_check: bool = True
    # language: hint to the sidecar/tracer about the target runtime language.
    # "auto" lets the runtime detector choose; override with "python", "java", etc.
    language: str = "auto"


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    timeout: int = 60
    coverage_wait: int = 10
    container_port: int = 3000
    # Override the container WORKDIR for coverage path resolution.
    # Leave empty to auto-detect from the Dockerfile WORKDIR instruction.
    container_workdir: str = ""
    ebpf: EbpfSettings = EbpfSettings()


class OpenAPIGeneratorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # provider: "none" (default) disables LLM calls even when enabled=true.
    # Set to "anthropic", "openai", or "ollama" to activate.
    # VulnReach is fully functional without any LLM provider.
    provider: str = "none"
    model: str = "claude-sonnet-4-20250514"
    api_key_env: str = "ANTHROPIC_API_KEY"
    max_tokens: int = 4096


class IntelligentDastSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # provider: "none" (default) disables LLM calls even when enabled=true.
    # Set to "anthropic", "openai", or "ollama" to activate.
    # VulnReach is fully functional without any LLM provider.
    provider: str = "none"  # "none" | "anthropic" | "openai" | "ollama"
    model: str = "claude-sonnet-4-20250514"
    api_key_env: str = "ANTHROPIC_API_KEY"
    base_url: str = ""  # override target URL; empty = auto-detect from runtime
    ollama_base_url: str = "http://localhost:11434"
    max_iter: int = 5
    auth_credentials: str = ""  # optional "user:pass" for target app auth


class ScanSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    static_reachability: bool = True
    tools: List[str] = ["trivy", "tainter"]
    runtime: RuntimeSettings = RuntimeSettings()
    openapi_generator: OpenAPIGeneratorSettings = OpenAPIGeneratorSettings()
    intelligent_dast: IntelligentDastSettings = IntelligentDastSettings()



class NotificationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Per-connector toggle (opt-out). Defaults to on — every scan notifies the
    # connector if it is configured under the Connectors page. Set to false to
    # suppress. Credentials live server-side, never in this file. If the
    # connector has no webhook configured, the notifier silently no-ops.
    slack: bool = True
    jira: bool = False


class RiskSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exposure: Literal["public", "private", "internal"] = "private"
    data_sensitivity: Literal["low", "medium", "high"] = "low"


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    verdict: Literal["CONFIRMED", "LIKELY", "POSSIBLE", "NOT_OBSERVED"]


class PolicySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    block_if: List[PolicyRule] = []

    @field_validator("block_if", mode="before")
    def default_block_if(cls, value):  # type: ignore
        return value or []


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan: ScanSettings
    risk: RiskSettings = RiskSettings()
    policy: PolicySettings = PolicySettings()
    notifications: NotificationSettings = NotificationSettings()


def load_config(path: str) -> ScanConfig:
    """Load and validate YAML scan config."""

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    try:
        return ScanConfig.model_validate(raw)
    except ValidationError as exc:  # pragma: no cover - pydantic formats errors
        raise ValueError(f"Invalid config: {exc}")


def default_config() -> ScanConfig:
    """Return a sensible default config for URL-only scans with no config file."""
    return ScanConfig(
        scan=ScanSettings(tools=["git", "trivy", "tainter", "multi_language_reachability", "route_extractor"]),
        risk=RiskSettings(exposure="public"),
        policy=PolicySettings(block_if=[PolicyRule(severity="CRITICAL", verdict="CONFIRMED")]),
    )

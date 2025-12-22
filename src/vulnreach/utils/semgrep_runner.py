"""Semgrep runner for SAST signal collection (V1 scope: Python Flask/FastAPI).

Executes Semgrep with a curated/default ruleset, normalizes findings, and writes
results to JSON for downstream reachability scoring.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

DEFAULT_RULESET = "p/security-audit"
DEFAULT_EXCLUDES = [
    "env",
    "venv",
    ".venv",
    "tests",
    "security_findings",
    "vulnreach-dashboard",
    "build",
    "dist",
    ".git",
    "__pycache__",
]


class SemgrepNotFoundError(RuntimeError):
    """Raised when Semgrep executable is not available on PATH."""


@dataclass
class SemgrepFinding:
    rule_id: str
    file: str
    line: Optional[int]
    sink_function: Optional[str]
    taint_hint: Optional[str]
    message: str
    severity: Optional[str]
    metadata: Dict


class SemgrepRunner:
    def __init__(self, default_config: str = DEFAULT_RULESET, timeout_seconds: int = 120):
        self.semgrep_path = shutil.which("semgrep")
        if not self.semgrep_path:
            raise SemgrepNotFoundError("Semgrep not found on PATH. Install Semgrep or disable --run-sast.")
        self.default_config = default_config or DEFAULT_RULESET
        self.timeout_seconds = timeout_seconds

    def run_scan(
        self,
        target_dir: str,
        output_path: str,
        config: Optional[str] = None,
        excludes: Optional[List[str]] = None,
    ) -> List[SemgrepFinding]:
        """Execute Semgrep and persist raw + normalized results to output_path."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        cfg = config or self.default_config
        exclude_paths = excludes or DEFAULT_EXCLUDES

        cmd = [
            self.semgrep_path,
            "scan",
            "--json",
            "--quiet",
            "--timeout",
            str(self.timeout_seconds),
            "--config",
            cfg,
        ]

        for ex in exclude_paths:
            cmd.extend(["--exclude", ex])

        cmd.append(target_dir)

        env = os.environ.copy()
        env.setdefault("SEMGREP_SEND_METRICS", "off")

        result = subprocess.run(cmd, capture_output=True, text=True, env=env)

        # Semgrep returns exit code 1 when findings are present; treat 0/1 as success.
        if result.returncode not in (0, 1):
            raise RuntimeError(f"Semgrep scan failed (exit {result.returncode}): {result.stderr.strip()}")

        try:
            parsed = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Failed to parse Semgrep output: {exc}")

        normalized = self._normalize_results(parsed)

        output_payload = {
            "tool": "semgrep",
            "config": cfg,
            "exclude": exclude_paths,
            "results": parsed.get("results", []),
            "normalized_findings": [finding.__dict__ for finding in normalized],
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(output_payload, fh, indent=2)

        return normalized

    def _normalize_results(self, data: Dict) -> List[SemgrepFinding]:
        findings: List[SemgrepFinding] = []

        for result in data.get("results", []):
            extra = result.get("extra", {})
            metavars = extra.get("metavars", {}) or {}
            metadata = extra.get("metadata", {}) or {}

            sink_function = self._extract_sink_function(metavars, metadata)
            taint_hint = metadata.get("taint_source") or metadata.get("source")

            findings.append(
                SemgrepFinding(
                    rule_id=result.get("check_id", ""),
                    file=result.get("path", ""),
                    line=(result.get("start") or {}).get("line"),
                    sink_function=sink_function,
                    taint_hint=taint_hint,
                    message=extra.get("message", ""),
                    severity=extra.get("severity"),
                    metadata=metadata,
                )
            )

        return findings

    @staticmethod
    def _extract_sink_function(metavars: Dict, metadata: Dict) -> Optional[str]:
        # Prefer explicit metadata hint if present.
        if metadata.get("function"):
            return metadata.get("function")

        candidate_keys = ["$FUNC", "$FUNCTION", "$METHOD"]
        for key in candidate_keys:
            mv = metavars.get(key)
            if not mv:
                continue
            return mv.get("abstract_content") or mv.get("value")

        # Fallback: first metavariable value if it resembles a callable.
        for mv in metavars.values():
            if isinstance(mv, dict) and mv.get("abstract_content"):
                return mv.get("abstract_content")
        return None


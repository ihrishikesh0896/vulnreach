"""Outbound notifications for scan lifecycle events.

Connector credentials (Slack webhook URL, etc.) live server-side in the
``connectors`` table and are read here at send time. Nothing in this module
raises on failure — a broken webhook must never break a scan result.
"""

import asyncio
import logging
from typing import Any, Dict, Optional

import httpx

from storage.repository import StorageRepository

logger = logging.getLogger(__name__)

# Transient errors (DNS blips, connection resets) are common right after a
# runtime/dynamic scan churns Docker's embedded DNS. Retry a few times so a
# momentary blip never loses the notification.
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = 2.0

# Per-status header (emoji + title + short subtitle). Different shapes for
# different outcomes so on-call can triage from the notification alone.
_STATUS_HEADERS = {
    "completed": ("✅", "VulnReach scan complete", "No policy-blocking findings."),
    "blocked":   ("⛔", "VulnReach policy gate: BLOCK", "Reachable findings matched a block_if rule."),
    "partial":   ("⚠️", "VulnReach scan partial", "Some tools did not contribute — coverage degraded."),
    "failed":    ("❌", "VulnReach scan failed", "A required tool failed; results are unreliable."),
    "cancelled": ("🚫", "VulnReach scan cancelled", "Stopped before completion."),
    "timeout":   ("⏱️", "VulnReach scan timed out", "Scan exceeded its execution budget."),
    "error":     ("💥", "VulnReach scan error", "Unhandled exception during scan."),
}


class SlackNotifier:
    def __init__(self, storage: StorageRepository) -> None:
        self.storage = storage

    async def notify_scan_complete(
        self,
        scan_id: str,
        status: str,
        summary: Dict[str, Any],
        repo: str,
        pipeline_status: Optional[str] = None,
        failed_tools: Optional[list] = None,
        fatal_tools: Optional[list] = None,
        error: Optional[str] = None,
    ) -> bool:
        """Post a scan-outcome message to the configured Slack webhook.

        Message shape varies by ``status`` (completed / blocked / partial /
        failed / cancelled / timeout / error). Returns True if delivered,
        False otherwise. Never raises.
        """
        try:
            cfg = self.storage.get_connector("slack") or {}
            webhook_url = cfg.get("webhook_url")
            if not webhook_url:
                logger.info("slack notify skipped — connector not configured (scan_id=%s)", scan_id)
                return False

            text = self._format_message(
                scan_id, status, summary, repo, pipeline_status,
                failed_tools or [], fatal_tools or [], error,
            )
            payload: Dict[str, Any] = {"text": text}
            if cfg.get("channel"):
                payload["channel"] = cfg["channel"]

            last_err: Optional[str] = None
            for attempt in range(1, _MAX_ATTEMPTS + 1):
                try:
                    async with httpx.AsyncClient(timeout=10) as client:
                        resp = await client.post(webhook_url, json=payload)
                except httpx.RequestError as exc:
                    # Network-level failure (DNS, connect, timeout) — retry.
                    last_err = f"{type(exc).__name__}: {exc}"
                    logger.warning(
                        "slack notify transient error attempt %d/%d (scan_id=%s): %s",
                        attempt, _MAX_ATTEMPTS, scan_id, last_err,
                    )
                    if attempt < _MAX_ATTEMPTS:
                        await asyncio.sleep(_RETRY_BACKOFF_SECONDS * attempt)
                    continue

                if resp.status_code == 200:
                    logger.info("slack notify sent (scan_id=%s status=%s)", scan_id, status)
                    return True

                # HTTP-level failure from Slack — do not retry (bad payload/URL).
                logger.warning(
                    "slack notify failed — status=%s body=%s (scan_id=%s)",
                    resp.status_code, resp.text[:200], scan_id,
                )
                return False

            logger.warning(
                "slack notify gave up after %d attempts (scan_id=%s): %s",
                _MAX_ATTEMPTS, scan_id, last_err,
            )
            return False
        except Exception as exc:  # never let a notification failure break a scan
            logger.warning("slack notify error (scan_id=%s): %s", scan_id, exc)
            return False

    @staticmethod
    def _format_message(
        scan_id: str,
        status: str,
        summary: Dict[str, Any],
        repo: str,
        pipeline_status: Optional[str],
        failed_tools: list,
        fatal_tools: list,
        error: Optional[str],
    ) -> str:
        emoji, title, subtitle = _STATUS_HEADERS.get(
            status, ("•", f"VulnReach scan {status}", "")
        )
        dyn = summary.get("dynamically_reachable", 0) or 0
        stat = summary.get("statically_reachable", 0) or 0
        reachable = dyn + stat

        # Common header
        lines = [f"{emoji} *{title}*"]
        if subtitle:
            lines.append(f"_{subtitle}_")
        lines.append(f"• Repo: `{repo or 'unknown'}`")
        lines.append(f"• Scan ID: `{scan_id}`")

        # Per-status body
        if status in ("completed", "blocked", "partial"):
            lines.append(
                f"• Reachable findings: *{reachable}* "
                f"(dynamic: {dyn}, static: {stat})"
            )
            if pipeline_status:
                lines.append(f"• Policy gate: *{pipeline_status}*")
            if status == "partial" and failed_tools:
                lines.append(f"• Degraded tools: {', '.join(failed_tools)}")

        elif status == "failed":
            if fatal_tools:
                lines.append(f"• Fatal tool(s): *{', '.join(fatal_tools)}*")
            if failed_tools:
                lines.append(f"• Other failures: {', '.join(failed_tools)}")
            if error:
                lines.append(f"• Error: `{error[:200]}`")

        elif status in ("timeout", "error"):
            if error:
                lines.append(f"• Detail: `{error[:200]}`")
            if failed_tools or fatal_tools:
                lines.append(
                    f"• Tools impacted: {', '.join(fatal_tools + failed_tools)}"
                )

        elif status == "cancelled":
            if error:  # carries cancellation reason if provided
                lines.append(f"• Reason: {error[:200]}")

        return "\n".join(lines)
